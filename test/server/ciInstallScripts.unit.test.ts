/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../..')
const workflowsDir = join(repoRoot, '.github/workflows')

interface InstallCase {
  file: string
  job: string
  step: string
  script: string
  env: Record<string, string>
}

const npmBins = (process.env.NPM_BINS ?? 'npm').split(delimiter).filter(Boolean)

const markerNames = [
  'root-preinstall',
  'root-install',
  'root-postinstall',
  'root-prepare',
  'dep-preinstall',
  'dep-postinstall',
  'frontend-preinstall',
  'frontend-postinstall'
]

function asRecord (value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return null
}

function hasTrigger (on: unknown, name: string): boolean {
  if (typeof on === 'string') return on === name
  if (Array.isArray(on)) return on.includes(name)
  const record = asRecord(on)
  return record !== null && Object.prototype.hasOwnProperty.call(record, name)
}

function pushIsTagOnly (on: unknown): boolean {
  const record = asRecord(on)
  if (record === null) return false
  const push = asRecord(record.push)
  if (push === null) return false
  const tagOnly = Object.prototype.hasOwnProperty.call(push, 'tags') &&
    !Object.prototype.hasOwnProperty.call(push, 'branches') &&
    !Object.prototype.hasOwnProperty.call(push, 'branches-ignore')
  return tagOnly
}

function checksOutUntrustedCode (on: unknown): boolean {
  if (hasTrigger(on, 'pull_request')) return true
  return hasTrigger(on, 'push') && !pushIsTagOnly(on)
}

function tokenize (text: string): string[] {
  const tokens: string[] = []
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3])
  }
  return tokens
}

function isCd (segment: string): boolean {
  return /^cd(\s|$)/.test(segment.trim())
}

function isLocalNpmInstall (segment: string): boolean {
  const match = segment.trim().match(/^npm(?:\s+--\S+)*\s+(install|ci|i)\b([\s\S]*)$/)
  if (match === null) return false
  const tokens = tokenize(match[2])
  if (tokens.includes('-g') || tokens.includes('--global')) return false
  const positional = tokens.filter(token => !token.startsWith('-'))
  return positional.every(token => token === '.' || token.startsWith('./') || token.startsWith('file:'))
}

function installScript (run: string): string | null {
  const logical = run.replace(/\\\r?\n/g, ' ')
  const kept: string[] = []
  let sawInstall = false
  for (const line of logical.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) {
      kept.push(line)
      continue
    }
    const segments = trimmed.split(/\s*(?:&&|;)\s*/).filter(Boolean)
    if (!segments.some(isLocalNpmInstall)) continue
    sawInstall = true
    kept.push(segments.filter(segment => isCd(segment) || isLocalNpmInstall(segment)).join(' && '))
  }
  if (!sawInstall) return null
  return kept.join('\n').trim()
}

function stringEnv (value: unknown): Record<string, string> {
  const record = asRecord(value)
  if (record === null) return {}
  const env: Record<string, string> = {}
  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      env[key] = String(entry)
    }
  }
  return env
}

function collectInstallCases (): InstallCase[] {
  const cases: InstallCase[] = []
  for (const file of readdirSync(workflowsDir).sort()) {
    if (!file.endsWith('.yml') && !file.endsWith('.yaml')) continue
    const doc = asRecord(yaml.safeLoad(readFileSync(join(workflowsDir, file), 'utf8'), { schema: yaml.JSON_SCHEMA }))
    if (doc === null || !checksOutUntrustedCode(doc.on)) continue
    const workflowEnv = stringEnv(doc.env)
    const jobs = asRecord(doc.jobs) ?? {}
    for (const [jobName, jobValue] of Object.entries(jobs)) {
      const job = asRecord(jobValue)
      if (job === null || !Array.isArray(job.steps)) continue
      const jobEnv = { ...workflowEnv, ...stringEnv(job.env) }
      for (const stepValue of job.steps) {
        const step = asRecord(stepValue)
        if (step === null || typeof step.run !== 'string') continue
        const script = installScript(step.run)
        if (script === null) continue
        cases.push({
          file,
          job: jobName,
          step: typeof step.name === 'string' ? step.name : script,
          script,
          env: { ...jobEnv, ...stringEnv(step.env) }
        })
      }
    }
  }
  return cases
}

function markerScript (name: string): string {
  return `node -e "require('fs').writeFileSync(process.env.MARKER + '/${name}', '1')"`
}

function writeFixture (root: string): void {
  mkdirSync(join(root, 'vendor/evil'), { recursive: true })
  mkdirSync(join(root, 'frontend'), { recursive: true })
  writeFileSync(join(root, 'vendor/evil/package.json'), JSON.stringify({
    name: 'evil-dep',
    version: '1.0.0',
    scripts: {
      preinstall: markerScript('dep-preinstall'),
      postinstall: markerScript('dep-postinstall')
    }
  }))
  writeFileSync(join(root, 'package.json'), JSON.stringify({
    name: 'attacker-root',
    version: '1.0.0',
    scripts: {
      preinstall: markerScript('root-preinstall'),
      install: markerScript('root-install'),
      postinstall: markerScript('root-postinstall'),
      prepare: markerScript('root-prepare')
    },
    dependencies: {
      'evil-dep': 'file:vendor/evil'
    }
  }))
  writeFileSync(join(root, 'frontend/package.json'), JSON.stringify({
    name: 'attacker-frontend',
    version: '1.0.0',
    scripts: {
      preinstall: markerScript('frontend-preinstall'),
      postinstall: markerScript('frontend-postinstall')
    }
  }))
}

function childEnv (workflowEnv: Record<string, string>, marker: string, home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue
    if (/^npm_config_ignore_scripts$/i.test(key)) continue
    if (key === 'npm_config_userconfig' || key === 'npm_config_globalconfig') continue
    env[key] = value
  }
  env.HOME = home
  env.npm_config_userconfig = join(home, '.npmrc')
  env.npm_config_globalconfig = join(home, 'global.npmrc')
  for (const [key, value] of Object.entries(workflowEnv)) {
    env[key] = value
  }
  env.MARKER = marker
  return env
}

function runInstall (install: InstallCase, npmBin: string): string[] {
  const parent = mkdtempSync(join(tmpdir(), 'ci-install-'))
  const root = join(parent, 'workspace')
  const marker = join(parent, 'markers')
  const home = join(parent, 'home')
  const scriptPath = join(parent, 'install.sh')
  mkdirSync(marker)
  mkdirSync(home)
  writeFileSync(join(home, '.npmrc'), '')
  writeFileSync(join(home, 'global.npmrc'), '')
  writeFixture(root)
  const script = install.script
    .replace(/^npm(?=\s)/gm, npmBin.includes('/') ? `"${npmBin}"` : npmBin)
  writeFileSync(scriptPath, script + '\n')
  try {
    spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', scriptPath], {
      cwd: root,
      env: childEnv(install.env, marker, home),
      encoding: 'utf8'
    })
    return readdirSync(marker).sort()
  } finally {
    rmSync(parent, { recursive: true, force: true })
  }
}

const cases = collectInstallCases()

void describe('CI checkout install scripts', () => {
  void it('covers the frontend test install step', () => {
    assert.ok(
      cases.some(install => install.file === 'ci.yml' && install.job === 'frontend-test' && install.script.includes('npm install')),
      'frontend-test install step was not found in .github/workflows/ci.yml'
    )
  })

  for (const install of cases) {
    void it(`${install.file} job ${install.job} step "${install.step}" does not run lifecycle scripts from the checked-out tree`, () => {
      for (const npmBin of npmBins) {
        const created = runInstall(install, npmBin)
        assert.deepEqual(
          created.filter(name => markerNames.includes(name)),
          [],
          `${npmBin} ran lifecycle scripts for ${install.file} ${install.job} "${install.step}".\n` +
          `Command:\n${install.script}\nMarkers: ${created.join(', ')}`
        )
      }
    })
  }
})
