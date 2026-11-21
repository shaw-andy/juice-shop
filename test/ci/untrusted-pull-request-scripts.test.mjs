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
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const workflowPath = path.join(repoRoot, '.github/workflows/ci.yml')
const FORK_HEAD = 'external-contributor/juice-shop'
const BASES = ['shaw-andy/juice-shop', 'juice-shop/juice-shop']
const BASE_SHA = 'cccccccccccccccccccccccccccccccccccccccc'
const HEAD_SHA = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
const MERGE_SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

function loadWorkflow () {
  const py = `
import json, yaml
from yaml.resolver import Resolver
for key in list(Resolver.yaml_implicit_resolvers):
    Resolver.yaml_implicit_resolvers[key] = [
        item for item in Resolver.yaml_implicit_resolvers[key]
        if item[0] != 'tag:yaml.org,2002:bool'
    ]
print(json.dumps(yaml.safe_load(open(${JSON.stringify(workflowPath)}))))
`
  const result = spawnSync('python3', ['-c', py], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  return JSON.parse(result.stdout)
}

function tokenize (src) {
  const tokens = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (c === ' ' || c === '\n' || c === '\t' || c === '\r') {
      i++
      continue
    }
    const two = src.slice(i, i + 2)
    if (two === '&&' || two === '||' || two === '==' || two === '!=' || two === '<=' || two === '>=') {
      tokens.push(two)
      i += 2
      continue
    }
    if (c === '(' || c === ')' || c === ',' || c === '!' || c === '.' || c === '[' || c === ']') {
      tokens.push(c)
      i++
      continue
    }
    if (c === '<' || c === '>') {
      tokens.push(c)
      i++
      continue
    }
    if (c === "'") {
      let j = i + 1
      let value = ''
      while (j < src.length) {
        if (src[j] === "'" && src[j + 1] === "'") {
          value += "'"
          j += 2
          continue
        }
        if (src[j] === "'") {
          j++
          break
        }
        value += src[j++]
      }
      tokens.push({ t: 'str', value })
      i = j
      continue
    }
    if ((c === '-' && /\d/.test(src[i + 1] || '')) || (c >= '0' && c <= '9')) {
      const match = src.slice(i).match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)
      if (match) {
        tokens.push({ t: 'num', value: Number(match[0]) })
        i += match[0].length
        continue
      }
    }
    const id = src.slice(i).match(/^[A-Za-z_][A-Za-z0-9_-]*/)
    if (id) {
      tokens.push({ t: 'id', value: id[0] })
      i += id[0].length
      continue
    }
    throw new Error('Cannot tokenize expression at "' + src.slice(i, i + 24) + '"')
  }
  return tokens
}

function parseExpression (src) {
  const tokens = tokenize(src)
  let i = 0
  const peek = () => tokens[i]
  const eat = () => tokens[i++]

  function parseOr () {
    let left = parseAnd()
    while (peek() === '||') {
      eat()
      const right = parseAnd()
      left = { op: '||', left, right }
    }
    return left
  }
  function parseAnd () {
    let left = parseCmp()
    while (peek() === '&&') {
      eat()
      const right = parseCmp()
      left = { op: '&&', left, right }
    }
    return left
  }
  function parseCmp () {
    let left = parseUnary()
    while (['==', '!=', '<', '>', '<=', '>='].includes(peek())) {
      const op = eat()
      left = { op, left, right: parseUnary() }
    }
    return left
  }
  function parseUnary () {
    if (peek() === '!') {
      eat()
      return { op: '!', expr: parseUnary() }
    }
    return parsePost()
  }
  function parsePost () {
    let expr = parsePrimary()
    while (peek() === '.' || peek() === '(' || peek() === '[') {
      if (peek() === '.') {
        eat()
        const name = eat()
        if (!name || name.t !== 'id') throw new Error('Expected property name')
        expr = { op: '.', expr, name: name.value }
      } else if (peek() === '[') {
        eat()
        const key = parseOr()
        if (eat() !== ']') throw new Error('Expected ]')
        expr = { op: '[]', expr, key }
      } else {
        eat()
        const args = []
        if (peek() !== ')') {
          args.push(parseOr())
          while (peek() === ',') {
            eat()
            args.push(parseOr())
          }
        }
        if (eat() !== ')') throw new Error('Expected )')
        expr = { op: 'call', expr, args }
      }
    }
    return expr
  }
  function parsePrimary () {
    if (peek() === '(') {
      eat()
      const expr = parseOr()
      if (eat() !== ')') throw new Error('Expected )')
      return expr
    }
    const token = eat()
    if (token && token.t === 'str') return { op: 'lit', value: token.value }
    if (token && token.t === 'num') return { op: 'lit', value: token.value }
    if (token && token.t === 'id') {
      if (token.value === 'true') return { op: 'lit', value: true }
      if (token.value === 'false') return { op: 'lit', value: false }
      if (token.value === 'null') return { op: 'lit', value: null }
      return { op: 'name', name: token.value }
    }
    throw new Error('Bad expression token ' + JSON.stringify(token))
  }

  const ast = parseOr()
  if (i !== tokens.length) throw new Error('Trailing expression tokens')
  return ast
}

function coerceNumber (value) {
  if (value === null || value === undefined) return 0
  if (typeof value === 'boolean') return value ? 1 : 0
  if (typeof value === 'number') return value
  if (typeof value === 'string') {
    if (value === '') return 0
    const parsed = Number(value)
    return Number.isNaN(parsed) ? NaN : parsed
  }
  return NaN
}

function looseEqual (left, right) {
  if (typeof left === 'string' && typeof right === 'string') {
    return left.toLowerCase() === right.toLowerCase()
  }
  if (typeof left === typeof right) return left === right
  const a = coerceNumber(left)
  const b = coerceNumber(right)
  if (Number.isNaN(a) || Number.isNaN(b)) return false
  return a === b
}

function truthy (value) {
  return !(value === false || value === 0 || value === '' || value === null || value === undefined)
}

function lookup (scope, name) {
  if (scope == null || typeof scope !== 'object') return null
  if (Object.prototype.hasOwnProperty.call(scope, name)) {
    const value = scope[name]
    return value === undefined ? null : value
  }
  return null
}

function evaluateAst (ast, scope) {
  switch (ast.op) {
    case 'lit':
      return ast.value
    case 'name':
      return lookup(scope, ast.name)
    case '.': {
      const parent = evaluateAst(ast.expr, scope)
      return lookup(parent, ast.name)
    }
    case '[]': {
      const parent = evaluateAst(ast.expr, scope)
      const key = evaluateAst(ast.key, scope)
      return lookup(parent, String(key))
    }
    case '!':
      return !truthy(evaluateAst(ast.expr, scope))
    case '&&':
      return truthy(evaluateAst(ast.left, scope)) ? evaluateAst(ast.right, scope) : evaluateAst(ast.left, scope)
    case '||':
      return truthy(evaluateAst(ast.left, scope)) ? evaluateAst(ast.left, scope) : evaluateAst(ast.right, scope)
    case '==':
      return looseEqual(evaluateAst(ast.left, scope), evaluateAst(ast.right, scope))
    case '!=':
      return !looseEqual(evaluateAst(ast.left, scope), evaluateAst(ast.right, scope))
    case '<':
    case '>':
    case '<=':
    case '>=': {
      const left = coerceNumber(evaluateAst(ast.left, scope))
      const right = coerceNumber(evaluateAst(ast.right, scope))
      if (Number.isNaN(left) || Number.isNaN(right)) return false
      if (ast.op === '<') return left < right
      if (ast.op === '>') return left > right
      if (ast.op === '<=') return left <= right
      return left >= right
    }
    case 'call': {
      const callee = ast.expr.op === 'name' ? ast.expr.name : null
      const args = ast.args.map(arg => evaluateAst(arg, scope))
      if (callee === 'success') return true
      if (callee === 'failure') return false
      if (callee === 'cancelled') return false
      if (callee === 'always') return true
      if (callee === 'startsWith') {
        return String(args[0] ?? '').toLowerCase().startsWith(String(args[1] ?? '').toLowerCase())
      }
      throw new Error('Unsupported expression function ' + callee)
    }
    default:
      throw new Error('Unsupported expression op ' + ast.op)
  }
}

function stripExpression (expr) {
  const text = String(expr).trim()
  const wrapped = text.match(/^\$\{\{\s*([\s\S]*?)\s*\}\}$/)
  return wrapped ? wrapped[1].trim() : text
}

function hasStatusFunction (expr) {
  return /\b(success|failure|always|cancelled)\s*\(/.test(expr)
}

function evaluate (expr, scope) {
  let text = stripExpression(expr)
  if (!hasStatusFunction(text)) text = 'success() && (' + text + ')'
  return evaluateAst(parseExpression(text), scope)
}

function substitute (script, scope) {
  return String(script).replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_match, expr) => {
    const value = evaluate(expr, scope)
    return value == null ? '' : String(value)
  })
}

function globToRegExp (pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
  return new RegExp('^' + escaped + '$')
}

function listFiles (dir, prefix = '') {
  const found = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'coverage' || entry.name === 'dist') continue
    const rel = prefix ? prefix + '/' + entry.name : entry.name
    if (entry.isDirectory()) found.push(...listFiles(path.join(dir, entry.name), rel))
    else found.push(rel)
  }
  return found
}

function pullRequestRuns (workflow) {
  const trigger = workflow.on && workflow.on.pull_request
  if (!trigger) return false
  const types = trigger.types
  if (Array.isArray(types) && !types.some(type => type === 'opened' || type === 'synchronize' || type === 'reopened')) {
    return false
  }
  const ignored = trigger['paths-ignore'] || []
  if (ignored.length === 0) return true
  const patterns = ignored.map(globToRegExp)
  return listFiles(repoRoot).some(file => !patterns.some(pattern => pattern.test(file)))
}

function matrixCells (job) {
  const matrix = job.strategy && job.strategy.matrix
  if (!matrix) return [null]
  const keys = Object.keys(matrix).filter(key => Array.isArray(matrix[key]))
  let cells = [{}]
  for (const key of keys) {
    const next = []
    for (const cell of cells) {
      for (const value of matrix[key]) next.push({ ...cell, [key]: value })
    }
    cells = next
  }
  return cells
}

function eventScope (repository, matrix) {
  return {
    github: {
      repository,
      event_name: 'pull_request',
      ref: 'refs/pull/1/merge',
      sha: MERGE_SHA,
      base_ref: 'master',
      head_ref: 'attacker-branch',
      event: {
        pull_request: {
          head: { sha: HEAD_SHA, repo: { full_name: FORK_HEAD } },
          base: { ref: 'master', sha: BASE_SHA }
        }
      }
    },
    matrix,
    env: {}
  }
}

function mergedEnv (workflow, job) {
  return { ...(workflow.env || {}), ...(job.env || {}) }
}

function stepEnabled (step, scope) {
  if (step.if == null) return true
  return truthy(evaluate(step.if, scope))
}

function jobEnabled (job, scope) {
  if (job.if == null) return true
  return truthy(evaluate(job.if, scope))
}

function resolvedCheckoutRef (step, scope) {
  if (!step.with || step.with.ref == null || step.with.ref === '') return scope.github.ref
  return substitute(String(step.with.ref), scope)
}

function checkoutIsUntrusted (ref) {
  if (ref == null || ref === '') return true
  if (ref === BASE_SHA || ref === 'master' || ref === 'refs/heads/master') return false
  return true
}

function attackerCommands (workflow, repository) {
  if (!pullRequestRuns(workflow)) return []
  const commands = []
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    for (const matrix of matrixCells(job)) {
      const scope = eventScope(repository, matrix)
      scope.env = mergedEnv(workflow, job)
      if (!jobEnabled(job, scope)) continue
      const checkout = (job.steps || []).find(step => typeof step.uses === 'string' && step.uses.startsWith('actions/checkout'))
      const untrusted = !checkout || (stepEnabled(checkout, scope) && checkoutIsUntrusted(resolvedCheckoutRef(checkout, scope)))
      if (!untrusted) continue
      for (const step of job.steps || []) {
        if (!stepEnabled(step, scope)) continue
        if (typeof step.run === 'string') {
          commands.push({
            job: jobName,
            script: substitute(step.run, scope),
            shell: step.shell || null,
            kind: 'run'
          })
        } else if (typeof step.uses === 'string' && step.uses.startsWith('nick-invision/retry') && step.with && step.with.command) {
          commands.push({
            job: jobName,
            script: substitute(String(step.with.command), scope),
            shell: 'retry',
            kind: 'retry'
          })
        } else if (typeof step.uses === 'string' && step.uses.startsWith('cypress-io/github-action') && step.with && step.with.start) {
          commands.push({
            job: jobName,
            script: substitute(String(step.with.start), scope),
            shell: 'exec',
            kind: 'start'
          })
        }
      }
    }
  }
  const seen = new Set()
  return commands.filter(command => {
    const key = command.kind + '\0' + command.script
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function cleanEnv (extra) {
  const env = { ...process.env, ...extra }
  delete env.npm_config_ignore_scripts
  env.npm_config_update_notifier = 'false'
  env.npm_config_fund = 'false'
  env.HOME = extra.HOME
  return env
}

function runShell (script, cwd, env, shell) {
  if (shell === 'retry' || shell === 'exec') {
    return spawnSync('bash', ['-c', script], { cwd, env, encoding: 'utf8', timeout: 120000 })
  }
  const file = path.join(cwd, '.step.sh')
  fs.writeFileSync(file, script)
  const args = shell === 'bash' ? ['--noprofile', '--norc', '-eo', 'pipefail', file] : ['-e', file]
  return spawnSync('bash', args, { cwd, env, encoding: 'utf8', timeout: 120000 })
}

function hookScript () {
  return 'node -e "require(\'fs\').writeFileSync(process.env.CANARY, \'1\')"'
}

function writeAttackerTree (dir) {
  const hook = hookScript()
  const scripts = {
    postinstall: hook,
    preinstall: hook,
    install: hook,
    prepare: hook,
    lint: hook,
    rsn: hook,
    'test:frontend:coverage': hook,
    'test:server:coverage': hook,
    'test:api:coverage': hook,
    'test:server': hook,
    'package:ci': hook,
    sbom: hook,
    start: hook,
    prestart: hook
  }
  fs.mkdirSync(path.join(dir, 'frontend'), { recursive: true })
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true })
  fs.mkdirSync(path.join(dir, 'test/smoke'), { recursive: true })
  fs.mkdirSync(path.join(dir, 'dist/juice-shop_20.2.0'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'juice-shop',
    version: '20.2.0',
    scripts,
    allowScripts: { 'sqlite3@5.1.7': true }
  }, null, 2))
  fs.writeFileSync(path.join(dir, 'frontend/package.json'), JSON.stringify({
    name: 'frontend',
    version: '20.2.0',
    scripts: { postinstall: hook, install: hook }
  }))
  fs.writeFileSync(path.join(dir, '.npmrc'), 'package-lock=false\n')
  fs.writeFileSync(path.join(dir, 'scripts/package.mjs'), "import fs from 'node:fs'\nfs.writeFileSync(process.env.CANARY, '1')\n")
  fs.writeFileSync(path.join(dir, 'test/smoke/smoke-test.sh'), '#!/bin/sh\necho 1 > "$CANARY"\n')
  fs.chmodSync(path.join(dir, 'test/smoke/smoke-test.sh'), 0o755)
  const packed = spawnSync('tar', ['-czf', 'juice-shop-20.2.0.tgz', '-C', 'dist', 'juice-shop_20.2.0'], { cwd: dir })
  assert.equal(packed.status, 0, packed.stderr && packed.stderr.toString())
  fs.renameSync(path.join(dir, 'juice-shop-20.2.0.tgz'), path.join(dir, 'dist/juice-shop-20.2.0.tgz'))
}

function executesProjectCode (script) {
  if (/^\s*npm install -g\b/.test(script) && !/\bnpm (install|run|start|test)\b/.test(script.replace(/npm install -g[^\n]*/g, ''))) {
    return false
  }
  return /\bnpm (install|run|start|test)\b/.test(script) ||
    /smoke-test\.sh/.test(script) ||
    /scripts\/package\.mjs/.test(script) ||
    /docker-compose\.test\.yml/.test(script)
}

function isDockerCommand (script) {
  return /\bdocker(\s|$)/.test(script)
}

describe('pull request packaging scripts', () => {
  it('compares matrix node versions the way GitHub compares them', () => {
    const scope = { matrix: { os: 'ubuntu-latest', 'node-version': 24 }, github: { repository: 'shaw-andy/juice-shop' } }
    assert.equal(truthy(evaluate("matrix.node-version == '24'", scope)), true)
    assert.equal(truthy(evaluate("matrix.os == 'ubuntu-latest'", { matrix: null, github: {} })), false)
    assert.equal(truthy(evaluate("github.repository == 'juice-shop/juice-shop'", scope)), false)
    assert.equal(truthy(evaluate("github.repository != 'juice-shop/juice-shop'", scope)), true)
  })

  it('does not run fork pull-request scripts from the CI workflow', { timeout: 180000 }, () => {
    const workflow = loadWorkflow()
    const failures = []
    for (const repository of BASES) {
      for (const command of attackerCommands(workflow, repository)) {
        if (isDockerCommand(command.script)) continue
        if (!executesProjectCode(command.script)) continue
        if (/curl\s+https:\/\/cli-assets\.heroku\.com/.test(command.script)) {
          failures.push(repository + ' ' + command.job + ' planned a Heroku installer on a fork pull request')
          continue
        }
        const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-home-'))
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-tree-'))
        const canary = path.join(dir, 'canary')
        writeAttackerTree(dir)
        const env = cleanEnv({ HOME: home, CANARY: canary, npm_config_cache: path.join(home, 'npm-cache') })
        runShell(command.script, dir, env, command.shell)
        if (fs.existsSync(canary)) {
          failures.push(repository + ' job ' + command.job + ' executed:\n' + command.script.trim())
        }
      }
    }
    assert.deepEqual(failures, [], 'Fork pull request code ran in CI:\n' + failures.join('\n---\n'))
  })

  it('does not reach scripts/package.mjs from package:ci on a fork pull request', { timeout: 180000 }, () => {
    const workflow = loadWorkflow()
    const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'))
    const planned = []
    for (const repository of BASES) {
      for (const command of attackerCommands(workflow, repository)) {
        if (command.job === 'smoke-test' && /\bnpm run package:ci\b/.test(command.script)) {
          planned.push({ repository, command })
        }
      }
    }
    if (planned.length === 0) return
    if (!String(pkg.scripts['package:ci']).includes('node scripts/package.mjs')) return

    const repository = planned[0].repository
    const scope = eventScope(repository, null)
    const job = workflow.jobs['smoke-test']
    scope.env = mergedEnv(workflow, job)
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-home-'))
    const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-prefix-'))
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-tree-'))
    const canary = path.join(dir, 'canary')
    fs.mkdirSync(path.join(dir, 'frontend'), { recursive: true })
    fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true })
    fs.writeFileSync(path.join(dir, '.npmrc'), 'package-lock=false\n')
    fs.writeFileSync(path.join(dir, 'frontend/package.json'), JSON.stringify({ name: 'frontend', version: '20.2.0' }))
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'juice-shop',
      version: '20.2.0',
      dependencies: { ms: '2.1.3' },
      scripts: {
        postinstall: 'node -e "process.exit(0)"',
        'package:ci': pkg.scripts['package:ci'],
        sbom: pkg.scripts.sbom
      }
    }, null, 2))
    fs.writeFileSync(path.join(dir, 'scripts/package.mjs'), "import fs from 'node:fs'\nfs.writeFileSync(process.env.CANARY, '1')\n")

    const installStep = (job.steps || []).find(step => typeof step.run === 'string' && step.run.includes('cyclonedx-npm'))
    assert.ok(installStep, 'smoke-test no longer installs cyclonedx-npm, so this chain cannot be reproduced')
    const cyclonedxLine = substitute(installStep.run, scope).split('\n').map(line => line.trim()).find(line => line.includes('cyclonedx-npm'))
    const env = cleanEnv({
      HOME: home,
      CANARY: canary,
      npm_config_cache: path.join(home, 'npm-cache'),
      npm_config_prefix: prefix,
      PATH: path.join(prefix, 'bin') + path.delimiter + process.env.PATH,
      CYCLONEDX_NPM_VERSION: scope.env.CYCLONEDX_NPM_VERSION
    })
    const installed = runShell(cyclonedxLine, dir, env, null)
    assert.equal(installed.status, 0, installed.stdout + '\n' + installed.stderr)
    const packaged = runShell(planned[0].command.script, dir, env, planned[0].command.shell)
    if (fs.existsSync(canary)) {
      assert.fail('scripts/package.mjs ran from npm run package:ci on a fork pull request checkout')
    }
    assert.equal(packaged.status, 0, 'package:ci exited before scripts/package.mjs could be judged:\n' + packaged.stdout + '\n' + packaged.stderr)
  })
})
