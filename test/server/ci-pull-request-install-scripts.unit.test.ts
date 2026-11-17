/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const require = createRequire(__filename)
const yaml = require('js-yaml')

const repoRoot = path.resolve(__dirname, '../..')
const workflowPath = path.join(repoRoot, '.github/workflows/ci.yml')
const repository = 'shaw-andy/juice-shop'

interface InstallCommand {
  source: string
  job: string
  step: string
  raw: string
  args: string[]
  globalRegistry: boolean
  reached: boolean
}

interface EvalContext {
  github: {
    repository: string
    event_name: string
    ref: string
  }
  matrix: Record<string, string | number> | null
}

void describe('pull request install scripts', () => {
  void it('evaluates the repository matrix guard used by the CI jobs', () => {
    const expr = "github.repository == 'juice-shop/juice-shop' || (github.repository != 'juice-shop/juice-shop' && matrix.os == 'ubuntu-latest' && matrix.node-version == '24')"
    assert.equal(evalIf(expr, context(null)), false)
    assert.equal(evalIf(expr, context({ os: 'ubuntu-latest', 'node-version': 24 })), true)
    assert.equal(evalIf(expr, context({ os: 'windows-latest', 'node-version': 24 })), false)
    assert.equal(evalIf(expr, context({ os: 'ubuntu-latest', 'node-version': 22 })), false)
    const upstream = context({ os: 'windows-latest', 'node-version': 22 })
    upstream.github.repository = 'juice-shop/juice-shop'
    assert.equal(evalIf(expr, upstream), true)
  })

  void it('does not run lifecycle scripts for install commands a fork pull request reaches', { timeout: 180000 }, () => {
    const commands = collectInstallCommands()
    const npmBin = resolveCiNpm()
    const version = spawnSync(npmBin, ['-v'], { encoding: 'utf8' }).stdout.trim()
    assert.match(version, /^(?:10|11)\./, `npm ${version} is not a version whose install script loop was checked`)

    const reachedLocal = commands.filter(command => command.reached && !command.globalRegistry)
    assert.ok(reachedLocal.length > 0, 'expected at least one pull_request install of the checked out project')

    const failures: string[] = []
    for (const command of reachedLocal) {
      const result = runInstall(npmBin, command)
      if (result.proof.trim() !== '') {
        failures.push(`${command.source} ${command.job} / ${command.step} (${command.raw}) ran lifecycle scripts:\n${result.proof}`)
      } else if (result.status !== 0 && !ignoresScripts(command.args)) {
        failures.push(`${command.source} ${command.job} / ${command.step} (${command.raw}) exited ${result.status} before any lifecycle script:\n${result.stderr}`)
      }
    }
    assert.equal(failures.length, 0, failures.join('\n\n'))
  })

  void it('accounts for every npm install and npm ci in the pull request workflow and the images it builds', () => {
    const commands = collectInstallCommands()
    const workflowText = fs.readFileSync(workflowPath, 'utf8')
    const workflowHits = npmInstallLines(workflowText)
    const workflowCommands = commands.filter(command => command.source === '.github/workflows/ci.yml')
    assert.equal(workflowCommands.length, workflowHits.length, `parser found ${workflowCommands.length} workflow installs, file has ${workflowHits.length}`)

    const dockerHits = dockerfilesBuiltOnPullRequest().flatMap(file => {
      return npmInstallLines(fs.readFileSync(file, 'utf8')).map(raw => ({ file, raw }))
    })
    const dockerCommands = commands.filter(command => command.source !== '.github/workflows/ci.yml')
    assert.equal(dockerCommands.length, dockerHits.length)
  })

  void it('does not run the checked out package lifecycle scripts for a global install of another package', () => {
    const npmBin = resolveCiNpm()
    const proof = path.join(os.tmpdir(), `lifecycle-global-${process.pid}-${Date.now()}`)
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-cwd-'))
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-other-'))
    const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-prefix-'))
    try {
      writePackage(project)
      fs.writeFileSync(path.join(other, 'package.json'), JSON.stringify({ name: 'empty-global-pkg', version: '1.0.0' }))
      const result = spawnNpm(npmBin, ['install', '-g', other, '--prefix', prefix], project, proof)
      assert.equal(result.status, 0, result.stderr)
      assert.equal(readProof(proof), '')
    } finally {
      fs.rmSync(project, { recursive: true, force: true })
      fs.rmSync(other, { recursive: true, force: true })
      fs.rmSync(prefix, { recursive: true, force: true })
      fs.rmSync(proof, { force: true })
    }
  })
})

function collectInstallCommands (): InstallCommand[] {
  const workflow = loadYaml(workflowPath) as { on?: unknown, jobs?: Record<string, Job> }
  const jobs = workflow.jobs ?? {}
  const triggers = triggersOnPullRequest(workflow.on)
  const commands: InstallCommand[] = []

  for (const [jobName, job] of Object.entries(jobs)) {
    const rows = matrixRows(job)
    for (const step of job.steps ?? []) {
      if (typeof step.run !== 'string') continue
      const reached = triggers && rows.some(row => jobRuns(job, row) && stepRuns(step, row))
      for (const occurrence of npmOccurrences(step.run)) {
        commands.push({
          source: '.github/workflows/ci.yml',
          job: jobName,
          step: step.name ?? occurrence.raw,
          raw: occurrence.raw,
          args: occurrence.args,
          globalRegistry: isGlobalRegistry(occurrence.args),
          reached
        })
      }
      if (!reached) continue
      for (const dockerfile of dockerfilesFromStep(step.run)) {
        const text = fs.readFileSync(dockerfile, 'utf8')
        for (const occurrence of npmOccurrences(text)) {
          commands.push({
            source: path.relative(repoRoot, dockerfile),
            job: jobName,
            step: step.name ?? occurrence.raw,
            raw: occurrence.raw,
            args: occurrence.args,
            globalRegistry: isGlobalRegistry(occurrence.args),
            reached: true
          })
        }
      }
    }
  }
  return commands
}

function dockerfilesBuiltOnPullRequest (): string[] {
  const workflow = loadYaml(workflowPath) as { on?: unknown, jobs?: Record<string, Job> }
  if (!triggersOnPullRequest(workflow.on)) return []
  const files = new Set<string>()
  for (const job of Object.values(workflow.jobs ?? {})) {
    const rows = matrixRows(job)
    for (const step of job.steps ?? []) {
      if (typeof step.run !== 'string') continue
      if (!rows.some(row => jobRuns(job, row) && stepRuns(step, row))) continue
      for (const dockerfile of dockerfilesFromStep(step.run)) files.add(dockerfile)
    }
  }
  return [...files]
}

interface Job {
  if?: string
  strategy?: { matrix?: Record<string, unknown> }
  steps?: Step[]
}

interface Step {
  name?: string
  if?: unknown
  run?: unknown
}

function triggersOnPullRequest (on: unknown): boolean {
  if (on == null) return false
  if (typeof on === 'string') return on === 'pull_request'
  if (Array.isArray(on)) return on.includes('pull_request')
  if (typeof on === 'object') return Object.prototype.hasOwnProperty.call(on, 'pull_request')
  return false
}

function matrixRows (job: Job): Array<Record<string, string | number> | null> {
  const matrix = job.strategy?.matrix
  if (matrix == null) return [null]
  if (matrix.include != null || matrix.exclude != null) {
    throw new Error('matrix include/exclude is not evaluated by this test')
  }
  const keys = Object.keys(matrix).filter(key => Array.isArray(matrix[key]))
  let rows: Array<Record<string, string | number>> = [{}]
  for (const key of keys) {
    const values = matrix[key] as Array<string | number>
    const next: Array<Record<string, string | number>> = []
    for (const row of rows) {
      for (const value of values) next.push({ ...row, [key]: value })
    }
    rows = next
  }
  return rows
}

function jobRuns (job: Job, row: Record<string, string | number> | null): boolean {
  return truthy(evalIf(job.if, context(row)))
}

function stepRuns (step: Step, row: Record<string, string | number> | null): boolean {
  return truthy(evalIf(step.if, context(row)))
}

function context (matrix: Record<string, string | number> | null): EvalContext {
  return {
    github: {
      repository,
      event_name: 'pull_request',
      ref: 'refs/pull/1/merge'
    },
    matrix
  }
}

function dockerfilesFromStep (script: string): string[] {
  const files: string[] = []
  const pattern = /docker(?:-|\s+)compose\s+[^\n]*?-f\s+(\S+)/g
  for (const match of script.matchAll(pattern)) {
    const composePath = path.resolve(repoRoot, match[1])
    if (!fs.existsSync(composePath)) continue
    const compose = loadYaml(composePath) as { services?: Record<string, { build?: unknown }> }
    for (const service of Object.values(compose.services ?? {})) {
      const dockerfile = dockerfileFromBuild(composePath, service.build)
      if (dockerfile != null && fs.existsSync(dockerfile)) files.push(dockerfile)
    }
  }
  return files
}

function dockerfileFromBuild (composePath: string, build: unknown): string | null {
  if (typeof build === 'string') {
    return path.join(path.resolve(path.dirname(composePath), build), 'Dockerfile')
  }
  if (build != null && typeof build === 'object') {
    const spec = build as { context?: string, dockerfile?: string }
    const context = path.resolve(path.dirname(composePath), spec.context ?? '.')
    return path.resolve(context, spec.dockerfile ?? 'Dockerfile')
  }
  return null
}

interface NpmOccurrence {
  raw: string
  args: string[]
}

function npmOccurrences (text: string): NpmOccurrence[] {
  return npmInstallLines(text).map(raw => {
    const tokens = tokenizeShell(stripRunPrefix(raw))
    let index = 0
    while (index < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index])) index++
    return { raw, args: tokens.slice(index + 1) }
  })
}

function npmInstallLines (text: string): string[] {
  return text.split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => /^(?:(?:RUN|run:)\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*npm\s+(?:install|ci|i)\b/.test(line))
}

function stripRunPrefix (line: string): string {
  return line.replace(/^(?:RUN|run:)\s+/, '')
}

function tokenizeShell (line: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: string | null = null
  for (let i = 0; i < line.length; i++) {
    const char = line[i]
    if (quote != null) {
      if (char === quote) quote = null
      else current += char
      continue
    }
    if (char === '\'' || char === '"') {
      quote = char
      continue
    }
    if (char === ' ' || char === '\t') {
      if (current !== '') tokens.push(current)
      current = ''
      continue
    }
    current += char
  }
  if (current !== '') tokens.push(current)
  return tokens
}

function isGlobalRegistry (args: string[]): boolean {
  const global = args.includes('-g') || args.includes('--global')
  if (!global) return false
  const specs = args.filter(arg => arg !== 'install' && arg !== 'ci' && arg !== 'i' && !arg.startsWith('-'))
  if (specs.length === 0) return false
  return specs.every(spec => spec !== '.' && !spec.startsWith('./') && !spec.startsWith('/') && !spec.startsWith('file:'))
}

function ignoresScripts (args: string[]): boolean {
  return args.some(arg => arg === '--ignore-scripts' || arg === '--ignore-scripts=true')
}

function runInstall (npmBin: string, command: InstallCommand): { status: number, proof: string, stderr: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-pr-'))
  const proof = path.join(root, 'lifecycle-proof')
  try {
    writePackage(root)
    writePackage(path.join(root, 'frontend'))
    let cwd = root
    let status = 0
    let stderr = ''
    const script = command.raw.startsWith('RUN ') ? stripRunPrefix(command.raw) : readStepScript(command)
    for (const line of script.split(/\r?\n/)) {
      const trimmed = line.trim()
      if (trimmed === '' || trimmed.startsWith('#')) continue
      const cd = /^cd\s+(\S+)$/.exec(trimmed)
      if (cd != null) {
        cwd = path.resolve(cwd, cd[1])
        continue
      }
      const occurrence = npmOccurrences(trimmed)[0]
      if (occurrence == null || isGlobalRegistry(occurrence.args)) continue
      const result = spawnNpm(npmBin, occurrence.args, cwd, proof)
      status = result.status
      stderr += result.stderr
      if (status !== 0) break
    }
    return { status, proof: readProof(proof), stderr }
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

function readStepScript (command: InstallCommand): string {
  const workflow = loadYaml(workflowPath) as { jobs?: Record<string, Job> }
  const job = workflow.jobs?.[command.job]
  const step = job?.steps?.find(candidate => candidate.name === command.step && typeof candidate.run === 'string')
  return typeof step?.run === 'string' ? step.run : command.raw
}

function writePackage (dir: string): void {
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'record-lifecycle.js'), [
    'const fs = require(\'fs\')',
    'fs.appendFileSync(process.env.LIFECYCLE_PROOF, process.env.npm_lifecycle_event + \'\\n\')',
    ''
  ].join('\n'))
  const manifest = {
    name: 'pull-request-lifecycle-probe',
    version: '0.0.0',
    scripts: {
      preinstall: 'node ./record-lifecycle.js',
      install: 'node ./record-lifecycle.js',
      postinstall: 'node ./record-lifecycle.js',
      prepublish: 'node ./record-lifecycle.js',
      preprepare: 'node ./record-lifecycle.js',
      prepare: 'node ./record-lifecycle.js',
      postprepare: 'node ./record-lifecycle.js'
    }
  }
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest))
}

function spawnNpm (npmBin: string, args: string[], cwd: string, proof: string): { status: number, stderr: string } {
  const userconfig = path.join(cwd, '.empty-user-npmrc')
  const globalconfig = path.join(cwd, '.empty-global-npmrc')
  fs.writeFileSync(userconfig, '')
  fs.writeFileSync(globalconfig, '')
  const env = { ...process.env, LIFECYCLE_PROOF: proof }
  delete env.npm_config_ignore_scripts
  delete env.NPM_CONFIG_IGNORE_SCRIPTS
  env.npm_config_userconfig = userconfig
  env.npm_config_globalconfig = globalconfig
  const result = spawnSync(npmBin, args, { cwd, env, encoding: 'utf8' })
  return { status: result.status ?? 1, stderr: `${result.stderr ?? ''}${result.stdout ?? ''}` }
}

function readProof (proof: string): string {
  return fs.existsSync(proof) ? fs.readFileSync(proof, 'utf8') : ''
}

function resolveCiNpm (): string {
  const nvm = path.join(os.homedir(), '.nvm/versions/node')
  if (fs.existsSync(nvm)) {
    const versions = fs.readdirSync(nvm).filter(version => version.startsWith('v24.')).sort()
    const latest = versions[versions.length - 1]
    if (latest != null) {
      const bin = path.join(nvm, latest, 'bin', 'npm')
      if (fs.existsSync(bin)) return bin
    }
  }
  const sibling = path.join(path.dirname(process.execPath), 'npm')
  if (fs.existsSync(sibling)) return sibling
  return 'npm'
}

function loadYaml (file: string): unknown {
  const text = fs.readFileSync(file, 'utf8')
  if (typeof yaml.safeLoad === 'function') return yaml.safeLoad(text)
  return yaml.load(text)
}

type Token = string | { str: string } | { num: number } | { id: string }

function evalIf (expression: unknown, ctx: EvalContext): unknown {
  if (expression == null || expression === '') return true
  if (typeof expression === 'boolean') return expression
  let source = String(expression).trim()
  if (source.startsWith('${{') && source.endsWith('}}')) source = source.slice(3, -2).trim()
  const parser = new Parser(tokenizeExpr(source))
  return parser.parseOr(ctx)
}

function truthy (value: unknown): boolean {
  return !(value === false || value === 0 || value === '' || value === null || Object.is(value, -0))
}

function tokenizeExpr (input: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  while (i < input.length) {
    const char = input[i]
    if (char === ' ' || char === '\t' || char === '\n') {
      i++
      continue
    }
    const two = input.slice(i, i + 2)
    if (two === '&&' || two === '||' || two === '==' || two === '!=' || two === '<=' || two === '>=') {
      tokens.push(two)
      i += 2
      continue
    }
    if ('()!.<>'.includes(char)) {
      tokens.push(char)
      i++
      continue
    }
    if (char === '\'') {
      let text = ''
      i++
      while (i < input.length) {
        if (input[i] === '\'' && input[i + 1] === '\'') {
          text += '\''
          i += 2
          continue
        }
        if (input[i] === '\'') {
          i++
          break
        }
        text += input[i]
        i++
      }
      tokens.push({ str: text })
      continue
    }
    if (char >= '0' && char <= '9') {
      let text = ''
      while (i < input.length && input[i] >= '0' && input[i] <= '9') {
        text += input[i]
        i++
      }
      tokens.push({ num: Number(text) })
      continue
    }
    if (/[A-Za-z_]/.test(char)) {
      let text = ''
      while (i < input.length && /[A-Za-z0-9_-]/.test(input[i])) {
        text += input[i]
        i++
      }
      tokens.push({ id: text })
      continue
    }
    throw new Error(`Unsupported workflow expression near ${input.slice(i)}`)
  }
  return tokens
}

class Parser {
  private index = 0

  constructor (private readonly tokens: Token[]) {}

  parseOr (ctx: EvalContext): unknown {
    let value = this.parseAnd(ctx)
    while (this.peek() === '||') {
      this.index++
      const right = this.parseAnd(ctx)
      value = truthy(value) ? value : right
    }
    return value
  }

  private parseAnd (ctx: EvalContext): unknown {
    let value = this.parseCompare(ctx)
    while (this.peek() === '&&') {
      this.index++
      const right = this.parseCompare(ctx)
      value = truthy(value) ? right : value
    }
    return value
  }

  private parseCompare (ctx: EvalContext): unknown {
    let value = this.parseUnary(ctx)
    for (;;) {
      const op = this.peek()
      if (op !== '==' && op !== '!=' && op !== '<' && op !== '>' && op !== '<=' && op !== '>=') break
      this.index++
      const right = this.parseUnary(ctx)
      const equal = looseEqual(value, right)
      if (op === '==') value = equal
      else if (op === '!=') value = !equal
      else value = relational(op, value, right)
    }
    return value
  }

  private parseUnary (ctx: EvalContext): unknown {
    if (this.peek() === '!') {
      this.index++
      return !truthy(this.parseUnary(ctx))
    }
    return this.parsePrimary(ctx)
  }

  private parsePrimary (ctx: EvalContext): unknown {
    const token = this.tokens[this.index]
    this.index++
    if (token == null) throw new Error('workflow expression ended early')
    if (typeof token === 'object' && 'str' in token) return token.str
    if (typeof token === 'object' && 'num' in token) return token.num
    if (token === '(') {
      const value = this.parseOr(ctx)
      if (this.peek() !== ')') throw new Error('missing ) in workflow expression')
      this.index++
      return value
    }
    if (typeof token === 'object' && 'id' in token) {
      if (this.peek() === '(') {
        this.index++
        if (this.peek() !== ')') throw new Error(`arguments are not supported in ${token.id}()`)
        this.index++
        return callFn(token.id)
      }
      let value: unknown = lookup(token.id, ctx)
      while (this.peek() === '.') {
        this.index++
        const prop = this.tokens[this.index]
        this.index++
        if (typeof prop !== 'object' || !('id' in prop)) throw new Error('expected property name')
        value = readProp(value, prop.id)
      }
      return value
    }
    throw new Error(`unexpected token ${JSON.stringify(token)}`)
  }

  private peek (): Token | undefined {
    return this.tokens[this.index]
  }
}

function lookup (name: string, ctx: EvalContext): unknown {
  if (name === 'true') return true
  if (name === 'false') return false
  if (name === 'null') return null
  if (name === 'github') return ctx.github
  if (name === 'matrix') return ctx.matrix
  throw new Error(`unknown workflow context ${name}`)
}

function readProp (value: unknown, prop: string): unknown {
  if (value == null || typeof value !== 'object') return null
  if (!Object.prototype.hasOwnProperty.call(value, prop)) return null
  return (value as Record<string, unknown>)[prop]
}

function callFn (name: string): boolean {
  if (name === 'success' || name === 'always') return true
  if (name === 'failure' || name === 'cancelled') return false
  throw new Error(`unsupported workflow function ${name}`)
}

function looseEqual (left: unknown, right: unknown): boolean {
  if (typeof left === 'string' && typeof right === 'string') return left.toLowerCase() === right.toLowerCase()
  if (typeof left === typeof right) return left === right
  const leftNumber = coerceNumber(left)
  const rightNumber = coerceNumber(right)
  if (Number.isNaN(leftNumber) || Number.isNaN(rightNumber)) return false
  return leftNumber === rightNumber
}

function coerceNumber (value: unknown): number {
  if (value === null) return 0
  if (typeof value === 'boolean') return value ? 1 : 0
  if (typeof value === 'number') return value
  if (typeof value === 'string') {
    if (value === '') return 0
    if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(value)) return Number(value)
    return Number.NaN
  }
  return Number.NaN
}

function relational (op: string, left: unknown, right: unknown): boolean {
  const leftNumber = coerceNumber(left)
  const rightNumber = coerceNumber(right)
  if (Number.isNaN(leftNumber) || Number.isNaN(rightNumber)) return false
  if (op === '<') return leftNumber < rightNumber
  if (op === '>') return leftNumber > rightNumber
  if (op === '<=') return leftNumber <= rightNumber
  return leftNumber >= rightNumber
}
