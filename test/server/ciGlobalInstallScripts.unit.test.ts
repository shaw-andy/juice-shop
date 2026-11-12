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

interface Step {
  name: string
  run: string
  env: Record<string, string>
  with: Record<string, string>
}

interface Job {
  name: string
  env: Record<string, string>
  steps: Step[]
}

interface ParsedWorkflow {
  env: Record<string, string>
  jobs: Job[]
}

interface Exposure {
  file: string
  job: string
  install: string
  sink: string
  script: string
  installSecrets: string[]
  sinkSecrets: string[]
}

const repoRoot = findRepoRoot()

function findRepoRoot (): string {
  let dir = process.cwd()
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, '.github', 'workflows', 'ci.yml'))) return dir
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  throw new Error('workflow directory not found from ' + process.cwd())
}

function stripComment (line: string): string {
  let quote: string | null = null
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (quote) {
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === '\'') {
      quote = ch
      continue
    }
    if (ch === '#' && (i === 0 || line[i - 1] === ' ')) return line.slice(0, i).trimEnd()
  }
  return line.trimEnd()
}

function unquote (value: string): string {
  const trimmed = value.trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith('\'') && trimmed.endsWith('\''))
  ) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

function indentOf (line: string): number {
  return line.match(/^ */)?.[0].length ?? 0
}

function emptyStep (): Step {
  return { name: '', run: '', env: {}, with: {} }
}

function parseWorkflow (text: string): ParsedWorkflow {
  const workflow: ParsedWorkflow = { env: {}, jobs: [] }
  let job: Job | null = null
  let step: Step | null = null
  let inJobs = false
  let inSteps = false
  let map: 'workflow-env' | 'job-env' | 'step-env' | 'step-with' | null = null
  let block: string[] | null = null

  const flushBlock = () => {
    if (!block || !step) {
      block = null
      return
    }
    const content = block.filter(line => line.trim() !== '')
    const min = content.reduce((n, line) => Math.min(n, indentOf(line)), 99)
    step.run = block.map(line => line.trim() === '' ? '' : line.slice(min)).join('\n').trim()
    block = null
  }

  for (const raw of text.split(/\r?\n/)) {
    if (block && raw.trim() === '') {
      block.push('')
      continue
    }
    const line = stripComment(raw)
    if (!line.trim()) continue
    const indent = indentOf(line)

    if (block) {
      if (indent > 8) {
        block.push(line)
        continue
      }
      flushBlock()
    }

    if (!inJobs) {
      if (line === 'env:') {
        map = 'workflow-env'
        continue
      }
      if (map === 'workflow-env' && indent === 2) {
        const entry = line.trim().match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
        if (entry) workflow.env[entry[1]] = unquote(entry[2])
        continue
      }
      map = null
      if (line === 'jobs:') inJobs = true
      continue
    }

    if (indent === 2 && /^[A-Za-z0-9_-]+:\s*$/.test(line.trim())) {
      job = { name: line.trim().slice(0, -1), env: {}, steps: [] }
      workflow.jobs.push(job)
      step = null
      inSteps = false
      map = null
      continue
    }
    if (!job) continue

    if (indent === 4 && line.trim() === 'steps:') {
      inSteps = true
      map = null
      continue
    }
    if (indent === 4 && line.trim() === 'env:') {
      inSteps = false
      map = 'job-env'
      continue
    }
    if (indent === 4) {
      map = null
      continue
    }
    if (map === 'job-env' && indent === 6) {
      const entry = line.trim().match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
      if (entry) job.env[entry[1]] = unquote(entry[2])
      continue
    }
    if (!inSteps) continue

    if (indent === 6 && line.trim().startsWith('- ')) {
      step = emptyStep()
      job.steps.push(step)
      map = null
      const rest = line.trim().slice(2)
      const named = rest.match(/^name:\s*(.*)$/)
      if (named) step.name = unquote(named[1])
      continue
    }
    if (!step || indent < 8) {
      map = null
      continue
    }
    if (map === 'step-env' && indent === 10) {
      const entry = line.trim().match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
      if (entry) step.env[entry[1]] = unquote(entry[2])
      continue
    }
    if (map === 'step-with' && indent === 10) {
      const entry = line.trim().match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
      if (entry) step.with[entry[1]] = unquote(entry[2])
      continue
    }
    if (indent !== 8) continue
    const key = line.trim().match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
    if (!key) continue
    map = null
    if (key[1] === 'name') step.name = unquote(key[2])
    if (key[1] === 'run') {
      if (key[2] === '|' || key[2] === '|-' || key[2] === '>' || key[2] === '>-') block = []
      else step.run = unquote(key[2])
    }
    if (key[1] === 'env' && key[2] === '') map = 'step-env'
    if (key[1] === 'with' && key[2] === '') map = 'step-with'
  }
  flushBlock()
  return workflow
}

function tokenize (line: string): string[] {
  const out: string[] = []
  let cur = ''
  let quote: string | null = null
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null
      else cur += ch
      continue
    }
    if (ch === '"' || ch === '\'') {
      quote = ch
      continue
    }
    if (/\s/.test(ch)) {
      if (cur) out.push(cur)
      cur = ''
      continue
    }
    cur += ch
  }
  if (cur) out.push(cur)
  return out
}

function globalInstallLines (run: string): string[] {
  return run.split('\n').map(line => line.trim()).filter(line => {
    const argv = tokenize(line)
    if (argv[0] !== 'npm') return false
    if (argv[1] !== 'install' && argv[1] !== 'i' && argv[1] !== 'add') return false
    return argv.includes('-g') || argv.includes('--global')
  })
}

function secretKeys (env: Record<string, string>): string[] {
  return Object.keys(env).filter(key => /\$\{\{\s*secrets\./.test(env[key]))
}

function workspaceScript (step: Step): string | null {
  const commands = [step.run, step.with.start, step.with.command, step.with['install-command']]
  for (const command of commands) {
    if (!command) continue
    for (const line of command.split('\n')) {
      const named = line.match(/(?:^|&&|\|\||;)\s*npm\s+run\s+([A-Za-z0-9:_-]+)/)
      if (named) return named[1]
      const lifecycle = line.match(/(?:^|&&|\|\||;)\s*npm\s+(start|test|stop|restart)\b/)
      if (lifecycle) return lifecycle[1]
    }
  }
  return null
}

function projectIgnoresScripts (): boolean {
  const npmrc = path.join(repoRoot, '.npmrc')
  if (!fs.existsSync(npmrc)) return false
  const text = fs.readFileSync(npmrc, 'utf8')
  return /^ignore-scripts\s*=\s*true\s*$/m.test(text) || /^strict-allow-scripts\s*=\s*true\s*$/m.test(text)
}

function exposuresIn (fileName: string, text = fs.readFileSync(path.join(repoRoot, '.github', 'workflows', fileName), 'utf8')): Exposure[] {
  const parsed = parseWorkflow(text)
  const found: Exposure[] = []
  for (const job of parsed.jobs) {
    const baseEnv = { ...parsed.env, ...job.env }
    job.steps.forEach((step, index) => {
      const installs = globalInstallLines(step.run).filter(line => !tokenize(line).includes('--ignore-scripts'))
      if (!installs.length) return
      const installSecrets = secretKeys({ ...baseEnv, ...step.env })
      const sinks = job.steps.slice(index + 1).flatMap(later => {
        const script = workspaceScript(later)
        const sinkSecrets = secretKeys({ ...baseEnv, ...later.env })
        if (!script || !sinkSecrets.length) return []
        return [{
          sink: later.name || script,
          script,
          sinkSecrets
        }]
      })
      for (const install of installs) {
        if (!sinks.length && installSecrets.length) {
          found.push({
            file: fileName,
            job: job.name,
            install,
            sink: step.name,
            script: '',
            installSecrets,
            sinkSecrets: []
          })
        }
        for (const sink of sinks) {
          found.push({
            file: fileName,
            job: job.name,
            install,
            sink: sink.sink,
            script: sink.script,
            installSecrets,
            sinkSecrets: sink.sinkSecrets
          })
        }
      }
    })
  }
  return found
}

function workflowFiles (): string[] {
  return fs.readdirSync(path.join(repoRoot, '.github', 'workflows')).filter(name => name.endsWith('.yml') || name.endsWith('.yaml'))
}

function placeholder (name: string): string {
  return `placeholder-value-for-${name}`
}

function npmCommandEnv (home: string, prefix: string, extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: home,
    npm_config_prefix: prefix,
    npm_config_cache: path.join(home, 'cache'),
    npm_config_userconfig: path.join(home, '.npmrc'),
    npm_config_globalconfig: path.join(home, 'global.npmrc')
  }
  if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot
  return { ...env, ...extra }
}

function installArgv (line: string, standIn: string): string[] {
  const argv = tokenize(line).slice(1)
  const flags: string[] = []
  const valued = new Set(['--prefix', '--script-shell', '--userconfig', '--globalconfig', '--cache'])
  let takeValue = false
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i]
    if (takeValue) {
      flags.push(arg)
      takeValue = false
      continue
    }
    if (arg === '--') break
    if (arg.startsWith('-')) {
      flags.push(arg)
      if (valued.has(arg.split('=')[0])) takeValue = !arg.includes('=')
      continue
    }
  }
  return [...argv.slice(0, 1), ...flags, standIn]
}

function readJson (file: string): Record<string, string | null> {
  return JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, string | null>
}

function namesSeen (capture: Record<string, string | null>, names: string[]): string[] {
  return names.filter(name => capture[name] === placeholder(name))
}

interface Replay {
  scriptRan: boolean
  leaked: string[]
  detail: string
}

function replay (exposure: Exposure, copyProjectNpmrc = true): Replay {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-global-install-'))
  const standIn = path.join(root, 'stand-in')
  const workspace = path.join(root, 'workspace')
  const prefix = path.join(root, 'prefix')
  const home = path.join(root, 'home')
  const capture = path.join(root, 'capture.json')
  try {
    fs.mkdirSync(standIn)
    fs.mkdirSync(workspace)
    fs.mkdirSync(prefix, { recursive: true })
    fs.mkdirSync(home, { recursive: true })
    fs.writeFileSync(path.join(home, '.npmrc'), '')
    fs.writeFileSync(path.join(home, 'global.npmrc'), '')
    const projectNpmrc = path.join(repoRoot, '.npmrc')
    if (copyProjectNpmrc && fs.existsSync(projectNpmrc)) fs.copyFileSync(projectNpmrc, path.join(workspace, '.npmrc'))
    const names = [...new Set([...exposure.installSecrets, ...exposure.sinkSecrets])]
    fs.writeFileSync(path.join(standIn, 'package.json'), JSON.stringify({
      name: 'untrusted-cli-stand-in',
      version: '0.0.0',
      scripts: { install: 'node rewrite.js' }
    }))
    fs.writeFileSync(path.join(standIn, 'rewrite.js'), [
      'const fs = require(\'fs\')',
      'const path = require(\'path\')',
      'const root = process.env.INIT_CWD',
      'if (!root) process.exit(2)',
      'const pkgPath = path.join(root, \'package.json\')',
      'const pkg = JSON.parse(fs.readFileSync(pkgPath, \'utf8\'))',
      'const scriptName = process.env.STANDIN_SCRIPT',
      'const names = (process.env.STANDIN_NAMES || \'\').split(\',\').filter(Boolean)',
      'const fields = names.map((name) => name + \':process.env.\' + name + \'??null\').join(\',\')',
      'pkg.scripts = pkg.scripts || {}',
      'if (scriptName) {',
      '  pkg.scripts[scriptName] = \'node -e "require(\\\'fs\\\').writeFileSync(process.env.CAPTURE_PATH, JSON.stringify({\' + fields + \'}))"\'',
      '}',
      'fs.writeFileSync(pkgPath, JSON.stringify(pkg))',
      'const direct = {}',
      'for (const name of names) direct[name] = process.env[name] ?? null',
      'fs.writeFileSync(path.join(root, \'direct-capture.json\'), JSON.stringify(direct))'
    ].join('\n'))
    const scripts: Record<string, string> = {}
    if (exposure.script) scripts[exposure.script] = 'node -e "process.exit(0)"'
    fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify({
      name: 'workspace',
      version: '0.0.0',
      scripts
    }))
    const installEnv = npmCommandEnv(home, prefix, {
      ...Object.fromEntries(exposure.installSecrets.map(name => [name, placeholder(name)])),
      STANDIN_SCRIPT: exposure.script,
      STANDIN_NAMES: names.join(',')
    })
    const installed = spawnSync('npm', installArgv(exposure.install, standIn), {
      cwd: workspace,
      env: installEnv,
      encoding: 'utf8'
    })
    if (installed.status !== 0) {
      throw new Error(`npm ${installArgv(exposure.install, standIn).join(' ')} exited ${installed.status}\n${installed.stdout}\n${installed.stderr}`)
    }
    const directFile = path.join(workspace, 'direct-capture.json')
    const scriptRan = fs.existsSync(directFile)
    const leaked = scriptRan ? namesSeen(readJson(directFile), exposure.installSecrets) : []
    if (exposure.script) {
      const started = spawnSync('npm', ['--silent', exposure.script === 'start' ? 'start' : 'run', ...(exposure.script === 'start' ? [] : [exposure.script])], {
        cwd: workspace,
        env: npmCommandEnv(home, prefix, {
          ...Object.fromEntries(exposure.sinkSecrets.map(name => [name, placeholder(name)])),
          CAPTURE_PATH: capture
        }),
        encoding: 'utf8'
      })
      if (fs.existsSync(capture)) leaked.push(...namesSeen(readJson(capture), exposure.sinkSecrets))
      else if (started.status !== 0 && scriptRan) {
        throw new Error(`npm ${exposure.script} exited ${started.status}\n${started.stdout}\n${started.stderr}`)
      }
    }
    return {
      scriptRan,
      leaked,
      detail: `${exposure.file} job ${exposure.job} install (${exposure.install}) then ${exposure.sink}`
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

void describe('global npm installs in CI', () => {
  void it('does not let a global install script read secrets from a later workspace script', () => {
    const found = workflowFiles().flatMap(file => exposuresIn(file))
    const failures: string[] = []
    for (const exposure of found) {
      const result = replay(exposure)
      const installAllowsScripts = !tokenize(exposure.install).includes('--ignore-scripts') && !projectIgnoresScripts()
      if (installAllowsScripts && !result.scriptRan) {
        failures.push(`${result.detail} did not run the package install script`)
      }
      if (result.leaked.length) {
        failures.push(`${result.detail} exposed ${result.leaked.join(', ')}`)
      }
    }
    assert.deepEqual(failures, [])
  })

  void it('accepts --ignore-scripts on the global install', () => {
    const found = exposuresIn('ci.yml', [
      'jobs:',
      '  e2e-test:',
      '    steps:',
      '      - name: Install CLI tools',
      '        run: npm install -g @angular/cli --ignore-scripts',
      '      - name: Execute end-to-end tests',
      '        uses: cypress-io/github-action@example',
      '        with:',
      '          start: npm start',
      '        env:',
      '          CYPRESS_RECORD_KEY: $' + '{{ secrets.CYPRESS_RECORD_KEY }}'
    ].join('\n'))
    assert.deepEqual(found, [])
  })

  void it('accepts dropping the global install', () => {
    const found = exposuresIn('ci.yml', [
      'jobs:',
      '  e2e-test:',
      '    steps:',
      '      - name: Install application',
      '        run: npm install',
      '      - name: Execute end-to-end tests',
      '        with:',
      '          start: npm start',
      '        env:',
      '          GITHUB_TOKEN: $' + '{{ secrets.GITHUB_TOKEN }}'
    ].join('\n'))
    assert.deepEqual(found, [])
  })

  void it('accepts keeping secrets out of the step that runs the workspace script', () => {
    const found = exposuresIn('ci.yml', [
      'jobs:',
      '  e2e-test:',
      '    steps:',
      '      - name: Install CLI tools',
      '        run: npm install -g @angular/cli',
      '      - name: Execute end-to-end tests',
      '        with:',
      '          start: npm start'
    ].join('\n'))
    assert.deepEqual(found, [])
  })

  void it('still runs install scripts when the global package spec is an exact version', () => {
    const found = exposuresIn('ci.yml', [
      'jobs:',
      '  e2e-test:',
      '    steps:',
      '      - name: Install CLI tools',
      '        run: npm install -g @angular/cli@22.0.1',
      '      - name: Execute end-to-end tests',
      '        with:',
      '          start: npm start',
      '        env:',
      '          ALCHEMY_API_KEY: $' + '{{ secrets.ALCHEMY_API_KEY }}'
    ].join('\n'))
    assert.equal(found.length, 1)
    const result = replay(found[0], false)
    assert.deepEqual(result.leaked, ['ALCHEMY_API_KEY'])
  })

  void it('does not flag the smoke-test or release jobs', () => {
    const smoke = exposuresIn('ci.yml').filter(exposure => exposure.job === 'smoke-test')
    const release = exposuresIn('release.yml')
    assert.deepEqual(smoke, [])
    assert.deepEqual(release, [])
  })
})
