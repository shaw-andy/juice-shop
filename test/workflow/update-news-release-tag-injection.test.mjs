/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * Spec for the release-news workflows. These tests fail while a release tag
 * or publish time is spliced into the shell script. They pass when those
 * values are passed only as environment variables and the script quotes them.
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const workflows = [
  '.github/workflows/update-news-www.yml',
  '.github/workflows/update-news-www-legacy.yml'
]
const placeholderToken = 'PLACEHOLDER_BOT_TOKEN'
const benignTag = 'v20.2.0'
const benignPublished = '2026-01-02T03:04:05Z'
const markerName = 'stolen-credential'

// A tag git accepts (no space, colon, star, or backslash) whose leading
// single quote ends the sed quotes. The colon in the checkout includeIf key
// is produced at runtime. The command copies the credential file checkout
// writes under RUNNER_TEMP.
const colon = '$(date${IFS}+%T|cut${IFS}-c3)'
const injectionTag = `v1'$(cat\${IFS}"$(git\${IFS}config\${IFS}--local\${IFS}--get\${IFS}includeIf.gitdir${colon}$(git\${IFS}rev-parse\${IFS}--absolute-git-dir).path)">${markerName})'`

function basicCredential () {
  return Buffer.from(`x-access-token:${placeholderToken}`, 'utf8').toString('base64')
}

function expandExpressions (raw, context) {
  const open = '${{'
  const close = '}}'
  if (!raw.includes(open)) return raw
  let i = 0
  let out = ''
  while (i < raw.length) {
    const start = raw.indexOf(open, i)
    if (start < 0) {
      out += raw.slice(i)
      break
    }
    out += raw.slice(i, start)
    let inString = false
    let end = -1
    for (let j = start + open.length; j < raw.length; j++) {
      if (raw[j] === '\'') inString = !inString
      else if (!inString && raw[j] === '}' && raw[j - 1] === '}') {
        end = j
        break
      }
    }
    if (end < 0) throw new Error('expression not closed')
    const expression = raw.slice(start + open.length, end - 1).trim()
    out += lookup(context, expression)
    i = end + 1
  }
  return out
}

function lookup (context, expression) {
  const parts = expression.split('.')
  let value = context
  for (const part of parts) {
    if (value == null || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, part)) {
      return ''
    }
    value = value[part]
  }
  if (value == null) return ''
  if (typeof value !== 'string') throw new Error(`expression did not resolve to a string: ${expression}`)
  return value
}

function readBlock (lines, headerIndex) {
  const header = lines[headerIndex]
  const indent = header.match(/^(\s*)/)[1].length
  const body = []
  let i = headerIndex + 1
  for (; i < lines.length; i++) {
    const line = lines[i]
    if (line.trim() === '') {
      body.push('')
      continue
    }
    const lineIndent = line.match(/^(\s*)/)[1].length
    if (lineIndent <= indent) break
    body.push(line)
  }
  const contentIndent = body.filter(line => line.trim() !== '').reduce((min, line) => {
    return Math.min(min, line.match(/^(\s*)/)[1].length)
  }, Infinity)
  const text = body.map(line => line.trim() === '' ? '' : line.slice(contentIndent)).join('\n')
  return { text: text.replace(/\n+$/, '') + '\n', next: i }
}

function loadUpdateStep (workflowPath) {
  const lines = fs.readFileSync(path.join(repoRoot, workflowPath), 'utf8').replace(/\r\n/g, '\n').split('\n')
  const header = lines.findIndex(line => line === '    - name: Update tab_news.md')
  if (header < 0) throw new Error(`missing news step in ${workflowPath}`)
  const step = { env: {}, run: '' }
  for (let i = header + 1; i < lines.length; i++) {
    const line = lines[i]
    if (line.trim() !== '' && !line.startsWith('      ') && !line.startsWith('\t')) break
    const env = line.match(/^      env:\s*$/)
    const runBlock = line.match(/^      run:\s*\|[+-]?\s*$/)
    const runInline = line.match(/^      run:\s*(\S.*)$/)
    if (env) {
      const block = readBlock(lines, i)
      for (const envLine of block.text.split('\n')) {
        const pair = envLine.match(/^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/)
        if (pair) step.env[pair[1]] = pair[2].replace(/^["']|["']$/g, '')
      }
      i = block.next - 1
    } else if (runBlock) {
      const block = readBlock(lines, i)
      step.run = block.text
      i = block.next - 1
    } else if (runInline) {
      step.run = runInline[1] + '\n'
    }
  }
  if (!step.run.trim()) throw new Error(`missing run script in ${workflowPath}`)
  return step
}

function gitEnv (home, runnerTemp) {
  return {
    ...process.env,
    HOME: home,
    RUNNER_TEMP: runnerTemp,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_AUTHOR_NAME: 'News Test',
    GIT_AUTHOR_EMAIL: 'news-test@example.com',
    GIT_COMMITTER_NAME: 'News Test',
    GIT_COMMITTER_EMAIL: 'news-test@example.com'
  }
}

function runGit (args, cwd, env) {
  const result = spawnSync('git', args, { cwd, env, encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  }
  return result.stdout
}

function plantCheckoutCredential (repo, runnerTemp, env) {
  const credentials = path.join(runnerTemp, 'git-credentials-news.config')
  const placeholder = 'AUTHORIZATION: basic ***'
  const value = `AUTHORIZATION: basic ${basicCredential()}`
  runGit(['config', '--file', credentials, 'http.https://github.com/.extraheader', placeholder], repo, env)
  const written = fs.readFileSync(credentials, 'utf8').replace(placeholder, value)
  fs.writeFileSync(credentials, written)
  const gitDir = runGit(['rev-parse', '--absolute-git-dir'], repo, env).trim()
  runGit(['config', '--local', `includeIf.gitdir:${gitDir}.path`, credentials], repo, env)
  return credentials
}

function prepareRepo () {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'news-injection-'))
  const repo = path.join(root, 'repo')
  const home = path.join(root, 'home')
  const runnerTemp = path.join(root, 'runner-temp')
  fs.mkdirSync(repo)
  fs.mkdirSync(home)
  fs.mkdirSync(runnerTemp)
  const env = gitEnv(home, runnerTemp)
  runGit(['init'], repo, env)
  fs.writeFileSync(path.join(repo, 'tab_news.md'), 'hello\n<!-- next:juice-shop -->\n')
  runGit(['add', 'tab_news.md'], repo, env)
  runGit(['commit', '-m', 'init'], repo, env)
  plantCheckoutCredential(repo, runnerTemp, env)
  return { root, repo, env }
}

function contextFor (tagName, publishedAt) {
  return {
    github: {
      event: {
        release: {
          tag_name: tagName,
          published_at: publishedAt
        }
      }
    }
  }
}

function runNewsStep (workflowPath, tagName, publishedAt) {
  const prepared = prepareRepo()
  const step = loadUpdateStep(workflowPath)
  const context = contextFor(tagName, publishedAt)
  const script = expandExpressions(step.run, context)
  const env = { ...prepared.env }
  for (const [key, value] of Object.entries(step.env)) {
    env[key] = expandExpressions(value, context)
  }
  const scriptPath = path.join(prepared.root, 'step.sh')
  fs.writeFileSync(scriptPath, script)
  const bash = spawnSync('bash', ['-e', scriptPath], {
    cwd: prepared.repo,
    env,
    encoding: 'utf8'
  })
  const marker = path.join(prepared.repo, markerName)
  const credential = basicCredential()
  let copied = false
  if (fs.existsSync(marker)) copied = true
  const news = fs.readFileSync(path.join(prepared.repo, 'tab_news.md'), 'utf8')
  if (news.includes(credential) || news.includes(placeholderToken)) copied = true
  fs.rmSync(prepared.root, { recursive: true, force: true })
  return { status: bash.status, copied, news }
}

describe('release tag git acceptance', () => {
  it('accepts the injected release tag as a git tag', () => {
    const prepared = prepareRepo()
    runGit(['tag', injectionTag], prepared.repo, prepared.env)
    const tags = runGit(['tag'], prepared.repo, prepared.env)
    assert.ok(tags.split('\n').includes(injectionTag))
    fs.rmSync(prepared.root, { recursive: true, force: true })
  })
})

for (const workflowPath of workflows) {
  describe(workflowPath, () => {
    it('inserts a normal release tag into tab_news.md', () => {
      const result = runNewsStep(workflowPath, benignTag, benignPublished)
      assert.equal(result.status, 0)
      assert.match(result.news, /<!-- next:juice-shop -->\n\* 2026-01-02T03:04:05Z: juice-shop \[`v20\.2\.0`\]\(https:\/\/github\.com\/juice-shop\/juice-shop\/releases\/tag\/v20\.2\.0\)/)
    })

    it('does not run a release tag that breaks out of the sed quotes', () => {
      const result = runNewsStep(workflowPath, injectionTag, benignPublished)
      assert.equal(result.copied, false)
    })

    it('does not run a publish time that breaks out of the sed quotes', () => {
      const result = runNewsStep(workflowPath, benignTag, injectionTag)
      assert.equal(result.copied, false)
    })
  })
}
