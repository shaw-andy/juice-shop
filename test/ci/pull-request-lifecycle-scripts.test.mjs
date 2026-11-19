import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const workflowPath = path.join(repoRoot, '.github/workflows/ci.yml')
const nodeBin = path.dirname(process.execPath)

// custom-config-test on this workflow installs Node 24, and a run of that job
// recorded node v24.21.0 / npm 11.19.0. The assertions below execute that npm.
const REQUIRED_NODE = 'v24.21.0'
const REQUIRED_NPM = '11.19.0'

const PULL_REQUEST_REPOSITORY = 'shaw-andy/juice-shop'

function loadYaml (file) {
  const json = execFileSync('python3', ['-c', `
import json, sys, yaml
data = yaml.safe_load(open(sys.argv[1]))
# YAML 1.1 treats the key "on" as boolean true.
if True in data:
    data['on'] = data.pop(True)
print(json.dumps(data))
`, file], { encoding: 'utf8' })
  return JSON.parse(json)
}

function kind (value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value === 'number') return 'number'
  if (typeof value === 'string') return 'string'
  return 'object'
}

function toNumber (value) {
  const valueKind = kind(value)
  if (valueKind === 'null') return 0
  if (valueKind === 'boolean') return value ? 1 : 0
  if (valueKind === 'number') return value
  if (valueKind === 'string') {
    const trimmed = value.trim()
    if (trimmed === '') return 0
    if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(trimmed)) return Number(trimmed)
    return NaN
  }
  return NaN
}

// GitHub.DistributedTask.Expressions2 EvaluationResult.AbstractEqual / CoerceTypes
// at actions/runner v2.338.0. String equality is ordinal-ignore-case. Null becomes
// 0 and a non-numeric string becomes NaN, so null == 'ubuntu-latest' is false.
function abstractEqual (left, right) {
  function go (a, b) {
    let lk = kind(a)
    let rk = kind(b)
    if (lk === rk) {
      if (lk === 'number') return a === b
      if (lk === 'string') return a.toLowerCase() === b.toLowerCase()
      if (lk === 'null') return true
      if (lk === 'boolean') return a === b
      return a === b
    }
    if (lk === 'number' && rk === 'string') return go(a, toNumber(b))
    if (lk === 'string' && rk === 'number') return go(toNumber(a), b)
    if (lk === 'boolean' || lk === 'null') return go(toNumber(a), b)
    if (rk === 'boolean' || rk === 'null') return go(a, toNumber(b))
    return false
  }
  return go(left, right)
}

function isFalsy (value) {
  const valueKind = kind(value)
  if (valueKind === 'null') return true
  if (valueKind === 'boolean') return !value
  if (valueKind === 'number') return value === 0 || Number.isNaN(value)
  if (valueKind === 'string') return value === ''
  return false
}

function tokenize (expression) {
  const source = String(expression).trim().replace(/^\$\{\{\s*/, '').replace(/\s*\}\}$/, '')
  const tokens = []
  let i = 0
  while (i < source.length) {
    const c = source[i]
    if (/\s/.test(c)) {
      i++
      continue
    }
    if (c === '(' || c === ')') {
      tokens.push(c)
      i++
      continue
    }
    if (source.startsWith('==', i) || source.startsWith('!=', i) || source.startsWith('&&', i) || source.startsWith('||', i)) {
      tokens.push(source.slice(i, i + 2))
      i += 2
      continue
    }
    if (c === '!') {
      tokens.push('!')
      i++
      continue
    }
    if (c === "'") {
      let j = i + 1
      let value = ''
      while (j < source.length) {
        if (source[j] === "'" && source[j + 1] === "'") {
          value += "'"
          j += 2
          continue
        }
        if (source[j] === "'") break
        value += source[j]
        j++
      }
      tokens.push({ str: value })
      i = j + 1
      continue
    }
    if (/[0-9]/.test(c)) {
      let j = i
      while (j < source.length && /[0-9.]/.test(source[j])) j++
      tokens.push({ num: Number(source.slice(i, j)) })
      i = j
      continue
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1
      while (j < source.length && /[A-Za-z0-9_-]/.test(source[j])) j++
      const parts = [source.slice(i, j)]
      while (source[j] === '.') {
        j++
        const start = j
        while (j < source.length && /[A-Za-z0-9_-]/.test(source[j])) j++
        parts.push(source.slice(start, j))
      }
      tokens.push({ path: parts })
      i = j
      continue
    }
    throw new Error(`Cannot tokenize expression at ${JSON.stringify(source.slice(i))}`)
  }
  return tokens
}

function lookup (context, parts) {
  if (!Object.prototype.hasOwnProperty.call(context, parts[0])) {
    throw new Error(`Unrecognized named-value: ${parts[0]}`)
  }
  let current = context[parts[0]]
  for (const part of parts.slice(1)) {
    if (current === null || current === undefined || typeof current !== 'object' || !Object.prototype.hasOwnProperty.call(current, part)) {
      return null
    }
    current = current[part]
  }
  return current
}

function evaluateExpression (expression, context) {
  const tokens = tokenize(expression)
  let index = 0
  function peek () { return tokens[index] }
  function eat (expected) {
    const token = tokens[index]
    if (expected !== undefined && token !== expected) {
      throw new Error(`Expected ${expected} in ${expression}`)
    }
    index++
    return token
  }
  function parseOr () {
    let value = parseAnd()
    while (peek() === '||') {
      eat('||')
      const next = parseAnd()
      if (isFalsy(value)) value = next
    }
    return value
  }
  function parseAnd () {
    let value = parseCmp()
    while (peek() === '&&') {
      eat('&&')
      const next = parseCmp()
      if (!isFalsy(value)) value = next
    }
    return value
  }
  function parseCmp () {
    const left = parseUnary()
    if (peek() === '==') {
      eat('==')
      return abstractEqual(left, parseUnary())
    }
    if (peek() === '!=') {
      eat('!=')
      return !abstractEqual(left, parseUnary())
    }
    return left
  }
  function parseUnary () {
    if (peek() === '!') {
      eat('!')
      return isFalsy(parseUnary())
    }
    return parsePrimary()
  }
  function parsePrimary () {
    const token = peek()
    if (token === '(') {
      eat('(')
      const value = parseOr()
      eat(')')
      return value
    }
    if (token && Object.prototype.hasOwnProperty.call(token, 'str')) {
      eat()
      return token.str
    }
    if (token && Object.prototype.hasOwnProperty.call(token, 'num')) {
      eat()
      return token.num
    }
    if (token && token.path) {
      eat()
      if (peek() === '(') {
        eat('(')
        eat(')')
        const name = token.path.join('.')
        // Job conditions in this file only reach these after an earlier clause
        // has already failed for a pull request to this repository.
        if (name === 'success') return true
        if (name === 'failure') return false
        throw new Error(`Unsupported expression function ${name}`)
      }
      return lookup(context, token.path)
    }
    throw new Error(`Cannot parse ${expression}`)
  }
  const value = parseOr()
  if (index !== tokens.length) throw new Error(`Trailing tokens in ${expression}`)
  return value
}

function conditionPasses (expression, context) {
  if (expression === undefined || expression === null || expression === '') return true
  return !isFalsy(evaluateExpression(expression, context))
}

function expandMatrix (matrix) {
  if (!matrix) return [{}]
  if (matrix.include || matrix.exclude) {
    throw new Error('This workflow uses matrix include/exclude, which this test does not expand')
  }
  let combos = [{}]
  for (const [key, values] of Object.entries(matrix)) {
    if (!Array.isArray(values)) throw new Error(`Matrix ${key} is not a list`)
    combos = combos.flatMap(combo => values.map(value => ({ ...combo, [key]: value })))
  }
  return combos
}

function pullRequestContext (matrix) {
  return {
    github: {
      repository: PULL_REQUEST_REPOSITORY,
      event_name: 'pull_request',
      ref: 'refs/pull/1/merge'
    },
    // A job with no strategy still received a matrix context: the custom-config
    // install step was skipped rather than failed on the unrecognized name.
    matrix
  }
}

function shellCommands (step) {
  const commands = []
  if (typeof step.run === 'string' && step.run.trim() !== '') commands.push(step.run)
  const uses = typeof step.uses === 'string' ? step.uses : ''
  // nick-invision/retry@7152eba spawns `with.command` through bash -c.
  if (uses.startsWith('nick-invision/retry@') && step.with && typeof step.with.command === 'string') {
    commands.push(step.with.command)
  }
  return commands
}

function isGlobalInstall (line) {
  return /(?:^|&&|\|\||;|\n)\s*npm\s+(?:install|i|ci)\b[^\n]*\s(?:-g|--global)\b/.test(line) ||
    /(?:^|&&|\|\||;|\n)\s*npm\s+(?:install|i)\s+-g\b/.test(line)
}

function runnableLines (command) {
  return command.split('\n').map(line => line.trim()).filter(line => line !== '' && !isGlobalInstall(line))
}

function dockerfileInstalls () {
  const dockerfile = fs.readFileSync(path.join(repoRoot, 'Dockerfile'), 'utf8')
  const lines = []
  for (const line of dockerfile.split('\n')) {
    const match = /^RUN\s+(.+)$/.exec(line.trim())
    if (!match) continue
    const run = match[1]
    if (/npm\s+install\s+-g\b/.test(run) || /npm\s+install\s+[^\s]*@/.test(run) && /-g\b/.test(run)) continue
    if (/\bnpm\s+(install|i|run|start)\b/.test(run) && !/\s-g\b/.test(run) && !/\s--global\b/.test(run)) {
      lines.push(run)
    }
  }
  return lines
}

function commandsForPullRequest (workflow) {
  const commands = []
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    for (const matrix of expandMatrix(job.strategy && job.strategy.matrix)) {
      const context = pullRequestContext(matrix)
      if (!conditionPasses(job.if, context)) continue
      const label = Object.keys(matrix).length
        ? `${jobName} [${Object.entries(matrix).map(([k, v]) => `${k}=${v}`).join(', ')}]`
        : jobName
      for (const step of job.steps || []) {
        if (!conditionPasses(step.if, context)) continue
        for (const command of shellCommands(step)) {
          const lines = runnableLines(command)
          if (lines.length === 0) continue
          commands.push({
            label: `${label} / ${step.name || 'unnamed step'}`,
            command: lines.join('\n')
          })
          if (jobName === 'docker-test' && /docker\s+compose\b/.test(command) && /docker-compose\.test\.yml/.test(command)) {
            for (const run of dockerfileInstalls()) {
              commands.push({
                label: `${label} / Dockerfile RUN ${run}`,
                command: run
              })
            }
          }
        }
      }
    }
  }
  return commands
}

function markerPackage () {
  const mark = (name) => `node -e 'require("fs").writeFileSync(${JSON.stringify(name + '.ran')},"1")'`
  const scripts = {}
  for (const name of ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare', 'prestart', 'start', 'pretest', 'test']) {
    scripts[name] = mark(name)
  }
  const workflow = fs.readFileSync(workflowPath, 'utf8')
  const dockerfile = fs.readFileSync(path.join(repoRoot, 'Dockerfile'), 'utf8')
  for (const match of `${workflow}\n${dockerfile}`.matchAll(/\bnpm\s+run(?:-script)?\s+([A-Za-z0-9:_-]+)/g)) {
    const name = match[1]
    scripts[name] = mark(name)
    scripts[`pre${name}`] = mark(`pre${name}`)
    scripts[`post${name}`] = mark(`post${name}`)
  }
  return {
    name: 'pull-request-payload',
    version: '0.0.0',
    scripts
  }
}

function runCommand (command) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-scripts-'))
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(markerPackage()))
  fs.writeFileSync(path.join(dir, '.npmrc'), 'package-lock=false\n')
  const env = {
    ...process.env,
    PATH: `${nodeBin}${path.delimiter}${process.env.PATH}`,
    npm_config_cache: path.join(dir, 'npm-cache'),
    npm_config_fund: 'false',
    npm_config_audit: 'false'
  }
  let status = 0
  try {
    execFileSync('bash', ['-c', command], { cwd: dir, env, stdio: 'pipe' })
  } catch (error) {
    status = error.status ?? 1
  }
  const markers = fs.readdirSync(dir).filter(name => name.endsWith('.ran')).sort()
  fs.rmSync(dir, { recursive: true, force: true })
  return { status, markers }
}

test('npm matches the Node.js 24 toolchain the custom-config job installs', () => {
  assert.equal(process.version, REQUIRED_NODE)
  const npmVersion = execFileSync(path.join(nodeBin, 'npm'), ['-v'], { encoding: 'utf8' }).trim()
  assert.equal(npmVersion, REQUIRED_NPM)
  const ignoreScripts = execFileSync(path.join(nodeBin, 'npm'), ['config', 'get', 'ignore-scripts'], { encoding: 'utf8' }).trim()
  assert.equal(ignoreScripts, 'false')
})

test('pull request code cannot run package.json scripts from CI commands', () => {
  const workflow = loadYaml(workflowPath)
  assert.ok(workflow.on.pull_request, 'ci.yml is triggered by pull_request')
  const commands = commandsForPullRequest(workflow)
  assert.ok(commands.some(entry => entry.label.startsWith('custom-config-test') && /npm\s+run\s+test:server\b/.test(entry.command)))
  const executed = []
  for (const entry of commands) {
    const result = runCommand(entry.command)
    executed.push({ ...entry, ...result })
  }
  const ranScripts = executed.filter(entry => entry.markers.length > 0)
  for (const entry of executed) {
    const runsPackageScript = /\bnpm\s+(?:run|start)\b/.test(entry.command) ||
      (/\bnpm\s+(?:install|i)\b/.test(entry.command) && !/--ignore-scripts\b/.test(entry.command))
    if (runsPackageScript && entry.markers.length === 0) {
      throw new Error(`${entry.label} invokes a package.json script but none ran (exit ${entry.status}). The command was: ${entry.command}`)
    }
  }
  assert.deepEqual(ranScripts.map(entry => ({
    step: entry.label,
    scripts: entry.markers
  })), [])
})
