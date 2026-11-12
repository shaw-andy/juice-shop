/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { safeLoad } from 'js-yaml'

const repoRoot = path.resolve(import.meta.dirname, '../..')
const upstream = 'juice-shop/juice-shop'
const botPlaceholder = 'placeholder-bot-token'
const githubTokenPlaceholder = 'placeholder-github-token'

interface WorkflowStep {
  name?: string
  uses?: string
  run?: string
  env?: Record<string, string>
  with?: Record<string, string>
}

interface WorkflowJob {
  if?: string
  steps?: WorkflowStep[]
}

interface WorkflowFile {
  jobs?: Record<string, WorkflowJob>
}

interface RunContext {
  repository: string
  refName: string
  tagName: string
  publishedAt: string
  sha: string
}

function loadWorkflow (relativePath: string): WorkflowFile {
  const raw = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8')
  return safeLoad(raw) as WorkflowFile
}

function contextValue (expression: string, context: RunContext): string {
  switch (expression) {
    case 'github.ref_name':
      return context.refName
    case 'github.repository':
      return context.repository
    case 'github.sha':
      return context.sha
    case 'github.event.release.tag_name':
      return context.tagName
    case 'github.event.release.published_at':
      return context.publishedAt
    default:
      throw new Error(`expression not mapped: ${expression}`)
  }
}

// actions/runner v2.338.2 TemplateReader builds format() for a string that
// mixes literals with ${{ }}, and Format appends ConvertToString() with no
// shell escaping. Insert the value once and do not scan it again.
function expandExpressions (input: string, context: RunContext): string {
  let result = ''
  let pos = 0
  while (pos < input.length) {
    const start = input.indexOf('${{', pos)
    if (start < 0) {
      result += input.slice(pos)
      break
    }
    result += input.slice(pos, start)
    const end = input.indexOf('}}', start + 3)
    if (end < 0) {
      result += input.slice(start)
      break
    }
    const expression = input.slice(start + 3, end).trim()
    result += contextValue(expression, context)
    pos = end + 2
  }
  return result
}

function jobRuns (condition: string | undefined, repository: string): boolean {
  if (condition == null || condition === '') return true
  const match = /^github\.repository == '([^']*)'$/.exec(condition)
  if (match == null) throw new Error(`unsupported job if: ${condition}`)
  return repository === match[1]
}

function checkoutPersistsCredentials (step: WorkflowStep): boolean {
  const raw = step.with?.['persist-credentials']
  if (raw == null || raw === '') return true
  return String(raw).toUpperCase() === 'TRUE'
}

function writePersistedCredential (repoDir: string, placeholder: string): string {
  fs.mkdirSync(repoDir, { recursive: true })
  const init = spawnSync('git', ['init', '-q'], { cwd: repoDir, encoding: 'utf8' })
  assert.equal(init.status, 0, init.stderr)
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'runner-temp-'))
  const credentials = path.join(runnerTemp, 'git-credentials-test.config')
  fs.writeFileSync(
    credentials,
    `[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic ${placeholder}\n`
  )
  const gitDir = path.join(repoDir, '.git').replace(/\\/g, '/')
  const configured = spawnSync(
    'git',
    ['config', `includeIf.gitdir:${gitDir}.path`, credentials],
    { cwd: repoDir, encoding: 'utf8' }
  )
  assert.equal(configured.status, 0, configured.stderr)
  return credentials
}

function prepareWorkspace (root: string): void {
  const shop = path.join(root, 'juice-shop', 'data', 'static')
  fs.mkdirSync(path.join(shop, 'codefixes'), { recursive: true })
  fs.writeFileSync(path.join(shop, 'challenges.yml'), 'name: fixture\n')
  fs.writeFileSync(path.join(shop, 'codefixes', 'alpha.info.yml'), 'fixes: []\n')
  const ebook = path.join(root, 'docs', 'modules', 'ROOT', 'assets', 'data')
  fs.mkdirSync(ebook, { recursive: true })
  fs.writeFileSync(path.join(ebook, 'challenges.yml'), 'old: true\n')
  fs.writeFileSync(path.join(root, 'tab_news.md'), '<!-- next:juice-shop -->\n')
  fs.mkdirSync(path.join(root, '_data'), { recursive: true })
}

function stubWget (root: string): { dir: string, log: string } {
  const dir = path.join(root, 'stub-bin')
  fs.mkdirSync(dir)
  const log = path.join(root, 'wget.log')
  fs.writeFileSync(path.join(dir, 'wget'), '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$WGET_LOG"\nexit 0\n', { mode: 0o755 })
  return { dir, log }
}

function stepEnvironment (step: WorkflowStep, context: RunContext, stubDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: `${stubDir}${path.delimiter}${process.env.PATH ?? ''}`,
    HOME: process.env.HOME ?? os.homedir(),
    TMPDIR: os.tmpdir(),
    LANG: 'C',
    WGET_LOG: path.join(path.dirname(stubDir), 'wget.log'),
    GITHUB_REF_NAME: context.refName,
    GITHUB_REPOSITORY: context.repository,
    GITHUB_SHA: context.sha
  }
  for (const [key, value] of Object.entries(step.env ?? {})) {
    env[key] = expandExpressions(String(value), context)
  }
  return env
}

function runStep (step: WorkflowStep, cwd: string, context: RunContext, stubDir: string): number {
  if (step.run == null) return 0
  const script = expandExpressions(step.run, context)
  const scriptPath = path.join(os.tmpdir(), `workflow-step-${process.pid}-${Math.random().toString(16).slice(2)}.sh`)
  fs.writeFileSync(scriptPath, script)
  try {
    const result = spawnSync('bash', ['-e', scriptPath], {
      cwd,
      env: stepEnvironment(step, context, stubDir),
      encoding: 'utf8'
    })
    return result.status ?? 1
  } finally {
    fs.rmSync(scriptPath, { force: true })
  }
}

function applyCheckouts (steps: WorkflowStep[], workspace: string): string | undefined {
  let botCredentials: string | undefined
  for (const step of steps) {
    if (step.uses == null || !step.uses.startsWith('actions/checkout')) continue
    const checkoutPath = step.with?.path == null || step.with.path === ''
      ? workspace
      : path.resolve(workspace, step.with.path)
    if (!checkoutPersistsCredentials(step)) continue
    const placeholder = step.with?.token == null ? githubTokenPlaceholder : botPlaceholder
    const credentials = writePersistedCredential(checkoutPath, placeholder)
    if (step.with?.token != null) botCredentials = credentials
  }
  return botCredentials
}

function withWorkspace (run: (workspace: string, stubDir: string) => void): void {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'workflow-shell-'))
  try {
    prepareWorkspace(workspace)
    const stub = stubWget(workspace)
    run(workspace, stub.dir)
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true })
  }
}

function runWorkflow (
  relativePath: string,
  context: RunContext,
  workspace: string,
  stubDir: string,
  expectSuccess = false
): void {
  const workflow = loadWorkflow(relativePath)
  const jobs = Object.values(workflow.jobs ?? {})
  assert.ok(jobs.length > 0, `${relativePath} has no jobs`)
  for (const job of jobs) {
    if (!jobRuns(job.if, context.repository)) continue
    const steps = job.steps ?? []
    applyCheckouts(steps, workspace)
    for (const step of steps) {
      if (step.run == null) continue
      const status = runStep(step, workspace, context, stubDir)
      if (expectSuccess) assert.equal(status, 0, step.name ?? 'run step')
    }
  }
}

function baseContext (overrides: Partial<RunContext> = {}): RunContext {
  return {
    repository: upstream,
    refName: 'develop',
    tagName: 'v1.2.3',
    publishedAt: '2020-01-01T00:00:00Z',
    sha: '0123456789abcdef0123456789abcdef01234567',
    ...overrides
  }
}

function markerPaths (workspace: string): { substitution: string, breakout: string } {
  return {
    substitution: path.join(workspace, 'marker-substitution'),
    breakout: path.join(workspace, 'marker-breakout')
  }
}

function assertPayloadsDoNotRun (
  relativePath: string,
  poison: 'refName' | 'tagName'
): void {
  withWorkspace((workspace, stubDir) => {
    const markers = markerPaths(workspace)
    const substitution = `x$(>${markers.substitution})`
    // Closes a single-quoted script and still expands inside double quotes.
    // A later command separated by ';' never runs under bash -e.
    const breakout = `x'$(>${markers.breakout})'`
    for (const value of [substitution, breakout]) {
      assert.equal(spawnSync('git', ['check-ref-format', '--branch', value]).status, 0)
    }
    runWorkflow(relativePath, baseContext({ [poison]: substitution }), workspace, stubDir)
    const substitutionCreated = fs.existsSync(markers.substitution)
    fs.rmSync(markers.substitution, { force: true })
    fs.rmSync(markers.breakout, { force: true })
    runWorkflow(relativePath, baseContext({ [poison]: breakout }), workspace, stubDir)
    assert.deepEqual(
      {
        substitution: substitutionCreated,
        breakout: fs.existsSync(markers.breakout)
      },
      { substitution: false, breakout: false }
    )
  })
}

const challengeWorkflows = [
  '.github/workflows/update-challenges-www-legacy.yml',
  '.github/workflows/update-challenges-www.yml'
]

const newsWorkflows = [
  '.github/workflows/update-news-www-legacy.yml',
  '.github/workflows/update-news-www.yml'
]

void describe('workflow shell steps', () => {
  for (const workflow of challengeWorkflows) {
    void it(`${workflow} does not execute a chosen ref name`, () => {
      assertPayloadsDoNotRun(workflow, 'refName')
    })
  }

  void it('update-challenges-ebook.yml does not execute a chosen ref name', () => {
    assertPayloadsDoNotRun('.github/workflows/update-challenges-ebook.yml', 'refName')
  })

  for (const workflow of newsWorkflows) {
    void it(`${workflow} does not execute a chosen release tag name`, () => {
      assertPayloadsDoNotRun(workflow, 'tagName')
    })
  }

  for (const workflow of [
    ...challengeWorkflows,
    '.github/workflows/update-challenges-ebook.yml',
    ...newsWorkflows
  ]) {
    void it(`${workflow} does not let the injected name read the bot checkout credential`, () => {
      withWorkspace((workspace, stubDir) => {
        const workflowFile = loadWorkflow(workflow)
        const job = Object.values(workflowFile.jobs ?? {})[0]
        assert.ok(job != null)
        assert.equal(jobRuns(job.if, upstream), true)
        const steps = job.steps ?? []
        const botCredentials = applyCheckouts(steps, workspace)
        assert.ok(botCredentials != null, 'bot checkout did not persist a credential')
        assert.equal(fs.existsSync(botCredentials), true)
        const stolen = path.join(workspace, 'stolen-credential')
        const copyCommand = `cp\${IFS}${botCredentials}\${IFS}${stolen}`
        // News steps wrap the value in single quotes, so the substitution has
        // to sit outside those quotes. The other steps expand $(...) directly.
        const refName = workflow.includes('update-news-')
          ? `x'$(${copyCommand})'`
          : `x$(${copyCommand})`
        assert.equal(spawnSync('git', ['check-ref-format', '--branch', refName]).status, 0)
        const poison = workflow.includes('update-news-')
          ? baseContext({ tagName: refName })
          : baseContext({ refName })
        for (const step of steps) {
          if (step.run == null) continue
          runStep(step, workspace, poison, stubDir)
        }
        const stolenText = fs.existsSync(stolen) ? fs.readFileSync(stolen, 'utf8') : ''
        assert.equal(stolenText.includes(botPlaceholder), false)
      })
    })
  }

  for (const workflow of challengeWorkflows) {
    void it(`${workflow} still selects the master and dev challenge files`, () => {
      withWorkspace((workspace, stubDir) => {
        runWorkflow(workflow, baseContext({ refName: 'master' }), workspace, stubDir, true)
        assert.equal(fs.readFileSync(path.join(workspace, '_data', 'challenges.yml'), 'utf8'), 'name: fixture\n')
        assert.equal(fs.existsSync(path.join(workspace, '_data', 'challenges_dev.yml')), false)
        assert.equal(fs.existsSync(path.join(workspace, '_data', 'snippets.json')), true)
        assert.match(fs.readFileSync(path.join(workspace, '_data', 'snippets.json'), 'utf8'), /alpha/)
      })
      withWorkspace((workspace, stubDir) => {
        runWorkflow(workflow, baseContext({ refName: 'feature/safe' }), workspace, stubDir, true)
        assert.equal(fs.readFileSync(path.join(workspace, '_data', 'challenges_dev.yml'), 'utf8'), 'name: fixture\n')
        assert.equal(fs.existsSync(path.join(workspace, '_data', 'challenges.yml')), false)
        assert.equal(fs.existsSync(path.join(workspace, '_data', 'snippets_dev.json')), true)
        assert.equal(fs.existsSync(path.join(workspace, '_data', 'snippets.json')), false)
      })
    })

    void it(`${workflow} does not run shell steps for another repository`, () => {
      withWorkspace((workspace, stubDir) => {
        const marker = path.join(workspace, 'marker-fork')
        runWorkflow(
          workflow,
          baseContext({ repository: 'example/fork', refName: `x$(>${marker})` }),
          workspace,
          stubDir
        )
        assert.equal(fs.existsSync(marker), false)
        assert.equal(fs.existsSync(path.join(workspace, '_data', 'challenges_dev.yml')), false)
      })
    })
  }

  void it('update-challenges-ebook.yml still requests the selected ref', () => {
    withWorkspace((workspace, stubDir) => {
      runWorkflow(
        '.github/workflows/update-challenges-ebook.yml',
        baseContext({ refName: 'develop' }),
        workspace,
        stubDir,
        true
      )
      const log = fs.readFileSync(path.join(workspace, 'wget.log'), 'utf8')
      assert.match(log, /juice-shop\/develop\/data\/static\/challenges\.yml/)
    })
  })
})
