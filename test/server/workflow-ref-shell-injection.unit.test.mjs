/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * Spec for the workflow_dispatch ref shell injection in the site-publish jobs.
 * These tests fail while a chosen git ref is spliced into a `run` script.
 */

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

const WORKFLOWS = [
  '.github/workflows/update-challenges-www.yml',
  '.github/workflows/update-challenges-www-legacy.yml',
  '.github/workflows/update-challenges-ebook.yml',
  '.github/workflows/update-news-www.yml',
  '.github/workflows/update-news-www-legacy.yml'
]

const PLACEHOLDER_BOT_TOKEN = 'placeholder-bot-token'

function loadWorkflows () {
  const script = `
import json, sys, yaml
out = []
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as handle:
        doc = yaml.safe_load(handle)
    jobs = []
    for name, job in (doc.get('jobs') or {}).items():
        steps = []
        for step in job.get('steps') or []:
            steps.append({
                'name': step.get('name'),
                'uses': step.get('uses'),
                'run': step.get('run'),
                'env': step.get('env') if isinstance(step.get('env'), dict) else None,
                'with': step.get('with') if isinstance(step.get('with'), dict) else None,
            })
        jobs.append({'name': name, 'steps': steps})
    out.append({'path': path, 'jobs': jobs})
json.dump(out, sys.stdout)
`
  const absolute = WORKFLOWS.map(file => path.join(repoRoot, file))
  const result = spawnSync('python3', ['-c', script, ...absolute], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  return JSON.parse(result.stdout)
}

function runSteps (workflow) {
  return workflow.jobs.flatMap(job => job.steps.filter(step => typeof step.run === 'string').map(step => ({ job: job.name, ...step })))
}

// actions/runner v2.338.2 TemplateReader.ParseScalar splits on ${{ }} and builds
// format('literal {0}', expr). Format.Append inserts ConvertToString() with no
// shell escaping. StringEscape only protects the format template, then format()
// turns doubled braces back into the original literal text.
function expandExpressions (text, lookup) {
  let index = 0
  let expanded = ''
  while (index < text.length) {
    const start = text.indexOf('${{', index)
    if (start < 0) {
      expanded += text.slice(index)
      break
    }
    expanded += text.slice(index, start)
    let cursor = start + 3
    let inString = false
    let end = -1
    for (; cursor < text.length; cursor++) {
      const char = text[cursor]
      if (char === "'") {
        inString = !inString
      } else if (!inString && char === '}' && text[cursor - 1] === '}') {
        end = cursor
        break
      }
    }
    if (end < 0) {
      throw new Error('unclosed ${{ }} expression')
    }
    const expression = text.slice(start + 3, end - 1).trim()
    expanded += lookup(expression)
    index = end + 1
  }
  return expanded
}

function contextLookup (context) {
  return expression => {
    const parts = expression.split('.')
    let value = { github: context }
    for (const part of parts) {
      if (value == null || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, part)) {
        throw new Error(`unhandled expression ${expression}`)
      }
      value = value[part]
    }
    if (typeof value !== 'string') {
      throw new Error(`expression ${expression} did not resolve to a string`)
    }
    return value
  }
}

function githubEnvironment (context) {
  const env = {}
  for (const [key, value] of Object.entries(context)) {
    if (typeof value === 'string') {
      env[`GITHUB_${key.toUpperCase()}`] = value
    }
  }
  return env
}

function stepEnvironment (step, context) {
  const env = {}
  if (step.env == null) return env
  const lookup = contextLookup(context)
  for (const [key, value] of Object.entries(step.env)) {
    env[key] = expandExpressions(String(value), lookup)
  }
  return env
}

function assertGitRef (ref) {
  const check = spawnSync('git', ['check-ref-format', `refs/heads/${ref}`], { encoding: 'utf8' })
  assert.equal(check.status, 0, `payload is not a git ref: ${ref}\n${check.stderr}`)
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ref-accept-'))
  try {
    assert.equal(spawnSync('git', ['init', '-q', directory]).status, 0)
    const created = spawnSync('git', ['-C', directory, 'checkout', '-q', '--orphan', ref], { encoding: 'utf8' })
    assert.equal(created.status, 0, created.stderr)
    const head = spawnSync('git', ['-C', directory, 'symbolic-ref', 'HEAD'], { encoding: 'utf8' })
    assert.equal(head.stdout.trim(), `refs/heads/${ref}`)
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
}

function payloads (marker) {
  return [
    `b$(touch\${IFS}${marker})`,
    'b`touch${IFS}' + marker + '`',
    `v'$(touch\${IFS}${marker})'`
  ]
}

function bashExists () {
  const found = spawnSync('bash', ['-c', 'exit 0'])
  assert.equal(found.status, 0, 'bash is required; ScriptHandler prefers it on Linux')
}

// ScriptHandler default on Linux: command path is bash when present, arguments
// come from the "sh" format, which is `-e {0}`. FixUpScriptContents does not
// modify bash or sh scripts. The file is executed, not passed through another shell.
function runScript (script, cwd, env) {
  const file = path.join(cwd, `.step-${crypto.randomBytes(4).toString('hex')}.sh`)
  fs.writeFileSync(file, script)
  return spawnSync('bash', ['-e', file], {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8'
  })
}

function prepareWorkspace () {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-step-'))
  const source = path.join(cwd, 'juice-shop', 'data', 'static')
  fs.mkdirSync(source, { recursive: true })
  fs.writeFileSync(path.join(source, 'challenges.yml'), 'challenge-bytes\n')
  fs.mkdirSync(path.join(cwd, '_data'))
  const ebook = path.join(cwd, 'docs', 'modules', 'ROOT', 'assets', 'data')
  fs.mkdirSync(ebook, { recursive: true })
  fs.writeFileSync(path.join(ebook, 'challenges.yml'), 'old-ebook\n')
  fs.writeFileSync(path.join(cwd, 'tab_news.md'), '<!-- next:juice-shop -->\n')
  const bin = path.join(cwd, 'bin')
  fs.mkdirSync(bin)
  const wgetLog = path.join(cwd, 'wget.log')
  fs.writeFileSync(path.join(bin, 'wget'), '#!/bin/sh\nprintf "%s\\n" "$@" >> "$WGET_LOG"\n', { mode: 0o755 })
  return { cwd, wgetLog, bin }
}

function websiteCheckoutPersistsCredentials (workflow) {
  for (const job of workflow.jobs) {
    for (const step of job.steps) {
      if (typeof step.uses === 'string' && step.uses.startsWith('actions/checkout@') && step.with != null && step.with.token != null) {
        const raw = step.with['persist-credentials']
        if (raw == null) return true
        return String(raw).toLowerCase() === 'true'
      }
    }
  }
  return false
}

function plantCredentials (workspace, token) {
  assert.equal(spawnSync('git', ['init', '-q', workspace]).status, 0)
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'runner-temp-'))
  const cred = path.join(runnerTemp, `git-credentials-${crypto.randomUUID()}.config`)
  const basic = Buffer.from(`x-access-token:${token}`, 'utf8').toString('base64')
  const header = `AUTHORIZATION: basic ${basic}`
  const wrote = spawnSync('git', ['config', '--file', cred, 'http.https://github.com/.extraheader', header], { encoding: 'utf8' })
  assert.equal(wrote.status, 0, wrote.stderr)
  const gitDir = path.join(workspace, '.git').replace(/\\/g, '/')
  const include = spawnSync('git', ['-C', workspace, 'config', '--local', `includeIf.gitdir:${gitDir}.path`, cred], { encoding: 'utf8' })
  assert.equal(include.status, 0, include.stderr)
  const listed = spawnSync('git', ['-C', workspace, 'config', '--list', '--show-origin'], { encoding: 'utf8' })
  assert.equal(listed.status, 0, listed.stderr)
  assert.ok(listed.stdout.includes(cred), 'checkout includeIf did not attach the credential file')
  return { cred, runnerTemp }
}

function baseContext (refName) {
  return {
    ref_name: refName,
    ref: `refs/heads/${refName}`,
    repository: 'juice-shop/juice-shop',
    sha: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    event: {
      release: {
        tag_name: refName,
        published_at: '2020-01-01T00:00:00Z'
      }
    }
  }
}

const workflows = loadWorkflows()

describe('workflow ref shell injection', () => {
  it('passes a ref name through the environment without executing it', () => {
    bashExists()
    const marker = path.join(os.tmpdir(), `env-only-${crypto.randomBytes(6).toString('hex')}`)
    const ref = `b$(touch\${IFS}${marker})`
    assertGitRef(ref)
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'env-only-'))
    try {
      const result = runScript('if [ "$REF_NAME" = "master" ]; then\n  echo master\nelse\n  echo other\nfi\n', cwd, { REF_NAME: ref })
      assert.equal(result.status, 0, result.stderr)
      assert.equal(fs.existsSync(marker), false)
      assert.match(result.stdout, /other/)
    } finally {
      fs.rmSync(marker, { force: true })
      fs.rmSync(cwd, { recursive: true, force: true })
    }
  })

  for (const workflow of workflows) {
    const relative = path.relative(repoRoot, workflow.path)
    for (const step of runSteps(workflow)) {
      it(`${relative} / ${step.name} does not execute a chosen ref during the shell test`, () => {
        bashExists()
        const failures = []
        const marker = path.join(os.tmpdir(), `wf-${crypto.randomBytes(6).toString('hex')}`)
        const refs = payloads(marker)
        try {
          for (const ref of refs) {
            fs.rmSync(marker, { force: true })
            assertGitRef(ref)
            const { cwd, wgetLog, bin } = prepareWorkspace()
            try {
              const context = baseContext(ref)
              const script = expandExpressions(step.run, contextLookup(context))
              const result = runScript(script, cwd, {
                ...githubEnvironment(context),
                ...stepEnvironment(step, context),
                PATH: `${bin}${path.delimiter}${process.env.PATH}`,
                WGET_LOG: wgetLog
              })
              if (fs.existsSync(marker)) {
                failures.push({ ref, status: result.status, stdout: result.stdout, stderr: result.stderr })
              }
            } finally {
              fs.rmSync(cwd, { recursive: true, force: true })
            }
          }
          assert.deepEqual(failures, [], `${step.name} executed a git ref as shell before the branch comparison could reject it`)
        } finally {
          fs.rmSync(marker, { force: true })
        }
      })
    }
  }

  for (const relative of [
    '.github/workflows/update-challenges-www.yml',
    '.github/workflows/update-challenges-www-legacy.yml'
  ]) {
    const workflow = workflows.find(item => item.path.endsWith(relative.slice(relative.indexOf('.github'))))
    it(`${relative} still writes the master and develop challenge files`, () => {
      bashExists()
      const step = runSteps(workflow).find(item => item.name === 'Update challenges.yml')
      assert.ok(step)
      for (const ref of ['master', 'develop']) {
        const { cwd } = prepareWorkspace()
        try {
          const context = baseContext(ref)
          const script = expandExpressions(step.run, contextLookup(context))
          const result = runScript(script, cwd, {
            ...githubEnvironment(context),
            ...stepEnvironment(step, context)
          })
          assert.equal(result.status, 0, result.stderr)
          const dest = ref === 'master' ? '_data/challenges.yml' : '_data/challenges_dev.yml'
          const other = ref === 'master' ? '_data/challenges_dev.yml' : '_data/challenges.yml'
          assert.equal(fs.readFileSync(path.join(cwd, dest), 'utf8'), 'challenge-bytes\n')
          assert.equal(fs.existsSync(path.join(cwd, other)), false)
        } finally {
          fs.rmSync(cwd, { recursive: true, force: true })
        }
      }
    })

    it(`${relative} run step cannot copy the website checkout credential`, () => {
      bashExists()
      const step = runSteps(workflow).find(item => item.name === 'Update challenges.yml')
      const persists = websiteCheckoutPersistsCredentials(workflow)
      const marker = path.join(os.tmpdir(), `cred-${crypto.randomBytes(6).toString('hex')}`)
      const { cwd } = prepareWorkspace()
      const temps = []
      let planted = null
      try {
        if (persists) {
          planted = plantCredentials(cwd, PLACEHOLDER_BOT_TOKEN)
          temps.push(planted.runnerTemp)
          const nested = plantCredentials(path.join(cwd, 'juice-shop'), 'placeholder-github-token')
          temps.push(nested.runnerTemp)
        }
        const stolen = path.join(cwd, 'stolen-credential')
        const ref = persists
          ? `b$(cp\${IFS}${planted.cred}\${IFS}${stolen})`
          : `b$(touch\${IFS}${marker})`
        assertGitRef(ref)
        const context = baseContext(ref)
        const script = expandExpressions(step.run, contextLookup(context))
        runScript(script, cwd, {
          ...githubEnvironment(context),
          ...stepEnvironment(step, context)
        })
        assert.equal(fs.existsSync(stolen), false, 'the update step copied the credential file left by the website checkout')
        assert.equal(fs.existsSync(marker), false, 'the update step executed the ref')
      } finally {
        fs.rmSync(marker, { force: true })
        fs.rmSync(cwd, { recursive: true, force: true })
        for (const temp of temps) fs.rmSync(temp, { recursive: true, force: true })
      }
    })
  }
})
