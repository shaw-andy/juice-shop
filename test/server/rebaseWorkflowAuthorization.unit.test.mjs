/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const workflowPath = path.join(root, '.github/workflows/rebase.yml')
const entrypointPath = path.join(
  root,
  'test/server/fixtures/cirrus-actions-rebase-b87d48154a87a85666003575337e27b8cd65f691/entrypoint.sh'
)
const entrypointSha256 = '2aca86f11baccb4e5ce6ec31c702026d9d57cfed218f86b9bf1ef7ad040a90a3'
const rebasePin = 'b87d48154a87a85666003575337e27b8cd65f691'
const repo = 'example-org/example-repo'
const workflowToken = 'WORKFLOW_TOKEN_PLACEHOLDER'
const allowedAssociations = ['OWNER', 'MEMBER', 'COLLABORATOR']
const deniedAssociations = ['NONE', 'CONTRIBUTOR', 'FIRST_TIMER', 'FIRST_TIME_CONTRIBUTOR', 'MANNEQUIN']

const entrypointBytes = readFileSync(entrypointPath)
const entrypointHash = createHash('sha256').update(entrypointBytes).digest('hex')
if (entrypointHash !== entrypointSha256) {
  throw new Error('vendored rebase entrypoint does not match the pinned action script')
}

function redact (text) {
  return String(text ?? '').split(workflowToken).join('[workflow-token]')
}

function loadWorkflow () {
  const script = `
import json, sys, yaml
def norm(o):
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if k is True:
                k = "on"
            elif k is False:
                k = "off"
            elif not isinstance(k, str):
                k = str(k)
            out[k] = norm(v)
        return out
    if isinstance(o, list):
        return [norm(x) for x in o]
    return o
json.dump(norm(yaml.safe_load(sys.stdin.read())), sys.stdout)
`
  const parsed = spawnSync('python3', ['-c', script], {
    input: readFileSync(workflowPath),
    encoding: 'utf8'
  })
  if (parsed.status !== 0) {
    throw new Error(redact(parsed.stderr || parsed.stdout))
  }
  return JSON.parse(parsed.stdout)
}

function kind (value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value === 'number') return 'number'
  if (typeof value === 'string') return 'string'
  if (Array.isArray(value)) return 'array'
  return 'object'
}

function isPrimitive (value) {
  const valueKind = kind(value)
  return valueKind === 'null' || valueKind === 'boolean' || valueKind === 'number' || valueKind === 'string'
}

function parseNumber (value) {
  const text = String(value ?? '').trim()
  if (text === '') return 0
  if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(text)) return Number(text)
  if (text === 'Infinity') return Infinity
  if (text === '-Infinity') return -Infinity
  return NaN
}

function convertToNumber (value) {
  switch (kind(value)) {
    case 'null': return 0
    case 'boolean': return value ? 1 : 0
    case 'number': return value
    case 'string': return parseNumber(value)
    default: return NaN
  }
}

function convertToString (value) {
  switch (kind(value)) {
    case 'null': return ''
    case 'boolean': return value ? 'true' : 'false'
    case 'number': return Number.isNaN(value) ? 'NaN' : String(value)
    case 'string': return value
    case 'array': return 'Array'
    default: return 'Object'
  }
}

function isFalsy (value) {
  switch (kind(value)) {
    case 'null': return true
    case 'boolean': return !value
    case 'number': return value === 0 || Number.isNaN(value)
    case 'string': return value === ''
    default: return false
  }
}

function isTruthy (value) {
  return !isFalsy(value)
}

function sameText (left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase()
}

function coerce (left, right) {
  let leftKind = kind(left)
  let rightKind = kind(right)
  if (leftKind === rightKind) return [left, right]
  if (leftKind === 'number' && rightKind === 'string') return coerce(left, parseNumber(right))
  if (leftKind === 'string' && rightKind === 'number') return coerce(parseNumber(left), right)
  if (leftKind === 'boolean' || leftKind === 'null') return coerce(convertToNumber(left), right)
  if (rightKind === 'boolean' || rightKind === 'null') return coerce(left, convertToNumber(right))
  return [left, right]
}

function abstractEqual (left, right) {
  const [coercedLeft, coercedRight] = coerce(left, right)
  if (kind(coercedLeft) !== kind(coercedRight)) return false
  switch (kind(coercedLeft)) {
    case 'null': return true
    case 'number':
      if (Number.isNaN(coercedLeft) || Number.isNaN(coercedRight)) return false
      return coercedLeft === coercedRight
    case 'string': return sameText(coercedLeft, coercedRight)
    case 'boolean': return coercedLeft === coercedRight
    default: return coercedLeft === coercedRight
  }
}

function abstractCompare (left, right) {
  const [coercedLeft, coercedRight] = coerce(left, right)
  if (kind(coercedLeft) !== kind(coercedRight)) return null
  switch (kind(coercedLeft)) {
    case 'number':
      if (Number.isNaN(coercedLeft) || Number.isNaN(coercedRight)) return null
      if (coercedLeft > coercedRight) return 1
      if (coercedLeft < coercedRight) return -1
      return 0
    case 'string': {
      const foldedLeft = coercedLeft.toLowerCase()
      const foldedRight = coercedRight.toLowerCase()
      if (foldedLeft > foldedRight) return 1
      if (foldedLeft < foldedRight) return -1
      return 0
    }
    case 'boolean':
      if (coercedLeft === coercedRight) return 0
      return coercedLeft ? 1 : -1
    default: return null
  }
}

function lookupKey (container, key) {
  if (container == null || typeof container !== 'object') return null
  if (Array.isArray(container)) {
    const index = typeof key === 'number' ? key : parseNumber(convertToString(key))
    if (!Number.isInteger(index) || index < 0 || index >= container.length) return null
    return container[index]
  }
  const name = convertToString(key)
  const found = Object.keys(container).find(candidate => sameText(candidate, name))
  if (found === undefined) return null
  return container[found]
}

function tokenize (input) {
  const tokens = []
  let index = 0
  while (index < input.length) {
    const character = input[index]
    if (character === ' ' || character === '\n' || character === '\t' || character === '\r') {
      index++
      continue
    }
    if (character === "'") {
      let value = ''
      index++
      while (index < input.length) {
        if (input[index] === "'" && input[index + 1] === "'") {
          value += "'"
          index += 2
          continue
        }
        if (input[index] === "'") {
          index++
          break
        }
        value += input[index]
        index++
      }
      tokens.push({ type: 'string', value })
      continue
    }
    const pair = input.slice(index, index + 2)
    if (pair === '!=' || pair === '==' || pair === '&&' || pair === '||' || pair === '>=' || pair === '<=') {
      tokens.push({ type: 'op', value: pair })
      index += 2
      continue
    }
    if ('!><().,[]'.includes(character)) {
      tokens.push({ type: 'op', value: character })
      index++
      continue
    }
    if (/[0-9]/.test(character)) {
      let end = index + 1
      while (end < input.length && /[0-9.eE+-]/.test(input[end])) end++
      tokens.push({ type: 'number', value: Number(input.slice(index, end)) })
      index = end
      continue
    }
    if (/[A-Za-z_]/.test(character)) {
      let end = index + 1
      while (end < input.length && /[A-Za-z0-9_-]/.test(input[end])) end++
      const word = input.slice(index, end)
      if (word === 'true' || word === 'false' || word === 'null') tokens.push({ type: word })
      else tokens.push({ type: 'ident', value: word })
      index = end
      continue
    }
    throw new Error('unsupported expression character at ' + index)
  }
  return tokens
}

function parseExpression (input) {
  const tokens = tokenize(input)
  let position = 0
  const peek = () => tokens[position]
  const eat = () => tokens[position++]

  function parsePrimary () {
    const token = eat()
    if (!token) throw new Error('expression ended early')
    if (token.type === 'string' || token.type === 'number') return { type: 'lit', value: token.value }
    if (token.type === 'true') return { type: 'lit', value: true }
    if (token.type === 'false') return { type: 'lit', value: false }
    if (token.type === 'null') return { type: 'lit', value: null }
    if (token.type === 'op' && token.value === '(') {
      const inner = parseBinary(0)
      const close = eat()
      if (!close || close.value !== ')') throw new Error('expected )')
      return inner
    }
    if (token.type === 'ident') {
      if (peek() && peek().type === 'op' && peek().value === '(') {
        eat()
        const args = []
        if (!(peek() && peek().type === 'op' && peek().value === ')')) {
          args.push(parseBinary(0))
          while (peek() && peek().type === 'op' && peek().value === ',') {
            eat()
            args.push(parseBinary(0))
          }
        }
        const close = eat()
        if (!close || close.value !== ')') throw new Error('expected )')
        return { type: 'call', name: token.value, args }
      }
      return { type: 'name', name: token.value }
    }
    throw new Error('unexpected token ' + JSON.stringify(token))
  }

  function parseUnary () {
    if (peek() && peek().type === 'op' && peek().value === '!') {
      eat()
      return { type: 'not', arg: parseUnary() }
    }
    return parsePostfix(parsePrimary())
  }

  function parsePostfix (expression) {
    let current = expression
    while (peek() && peek().type === 'op' && (peek().value === '.' || peek().value === '[')) {
      if (peek().value === '.') {
        eat()
        const property = eat()
        if (!property || property.type !== 'ident') throw new Error('expected property name')
        current = { type: 'index', object: current, index: { type: 'lit', value: property.value } }
      } else {
        eat()
        const index = parseBinary(0)
        const close = eat()
        if (!close || close.value !== ']') throw new Error('expected ]')
        current = { type: 'index', object: current, index }
      }
    }
    return current
  }

  function precedence (operator) {
    switch (operator) {
      case '||': return 5
      case '&&': return 6
      case '==':
      case '!=': return 10
      case '<':
      case '<=':
      case '>':
      case '>=': return 11
      default: return -1
    }
  }

  function parseBinary (minimum) {
    let left = parseUnary()
    while (peek() && peek().type === 'op' && precedence(peek().value) >= minimum) {
      const operator = eat().value
      const right = parseBinary(precedence(operator) + 1)
      left = { type: 'bin', op: operator, left, right }
    }
    return left
  }

  const ast = parseBinary(0)
  if (position !== tokens.length) throw new Error('trailing expression tokens')
  return ast
}

function referencesStatus (node) {
  if (!node || typeof node !== 'object') return false
  if (node.type === 'call') {
    const name = node.name.toLowerCase()
    if (name === 'success' || name === 'failure' || name === 'always' || name === 'cancelled') return true
    return node.args.some(referencesStatus)
  }
  if (node.type === 'not') return referencesStatus(node.arg)
  if (node.type === 'index') return referencesStatus(node.object) || referencesStatus(node.index)
  if (node.type === 'bin') return referencesStatus(node.left) || referencesStatus(node.right)
  return false
}

function evaluateNode (node, ctx) {
  switch (node.type) {
    case 'lit': return node.value
    case 'name': return lookupKey(ctx.scope, node.name)
    case 'index': return lookupKey(evaluateNode(node.object, ctx), evaluateNode(node.index, ctx))
    case 'not': return isFalsy(evaluateNode(node.arg, ctx))
    case 'bin': {
      if (node.op === '&&') {
        const left = evaluateNode(node.left, ctx)
        if (isFalsy(left)) return left
        return evaluateNode(node.right, ctx)
      }
      if (node.op === '||') {
        const left = evaluateNode(node.left, ctx)
        if (isTruthy(left)) return left
        return evaluateNode(node.right, ctx)
      }
      const left = evaluateNode(node.left, ctx)
      const right = evaluateNode(node.right, ctx)
      if (node.op === '==') return abstractEqual(left, right)
      if (node.op === '!=') return !abstractEqual(left, right)
      const compared = abstractCompare(left, right)
      if (compared == null) return false
      if (node.op === '>') return compared > 0
      if (node.op === '>=') return compared >= 0
      if (node.op === '<') return compared < 0
      if (node.op === '<=') return compared <= 0
      throw new Error('unsupported operator ' + node.op)
    }
    case 'call': return evaluateCall(node, ctx)
    default: throw new Error('unsupported expression node ' + node.type)
  }
}

function evaluateCall (node, ctx) {
  const name = node.name.toLowerCase()
  const args = () => node.args.map(arg => evaluateNode(arg, ctx))
  if (name === 'success') return ctx.jobStatus === 'success'
  if (name === 'failure') return ctx.jobStatus === 'failure'
  if (name === 'cancelled') return ctx.jobStatus === 'cancelled'
  if (name === 'always') return true
  if (name === 'contains') {
    const [left, right] = args()
    if (isPrimitive(left)) {
      if (!isPrimitive(right)) return false
      return convertToString(left).toLowerCase().includes(convertToString(right).toLowerCase())
    }
    if (Array.isArray(left) && left.length > 0) return left.some(item => abstractEqual(right, item))
    return false
  }
  if (name === 'startswith') {
    const [left, right] = args()
    if (!isPrimitive(left) || !isPrimitive(right)) return false
    return convertToString(left).toLowerCase().startsWith(convertToString(right).toLowerCase())
  }
  if (name === 'endswith') {
    const [left, right] = args()
    if (!isPrimitive(left) || !isPrimitive(right)) return false
    return convertToString(left).toLowerCase().endsWith(convertToString(right).toLowerCase())
  }
  if (name === 'fromjson') return JSON.parse(convertToString(args()[0]))
  throw new Error('unsupported expression function ' + node.name)
}

function stripOuterExpression (text) {
  const trimmed = text.trim()
  if (trimmed.startsWith('${{') && trimmed.endsWith('}}')) return trimmed.slice(3, -2).trim()
  return trimmed
}

function conditionIsTrue (expression, ctx) {
  if (typeof expression === 'boolean') return expression
  const source = expression == null ? '' : stripOuterExpression(String(expression))
  if (source === '') return ctx.jobStatus === 'success'
  const ast = parseExpression(source)
  const wrapped = referencesStatus(ast) ? source : 'success() && (' + source + ')'
  return isTruthy(evaluateNode(parseExpression(wrapped), ctx))
}

function expressionReferencesAlways (expression) {
  if (expression == null || typeof expression === 'boolean') return false
  const source = stripOuterExpression(String(expression))
  if (source === '') return false
  return referencesStatus(parseExpression(source)) && source.toLowerCase().includes('always(')
}

function expandExpressions (text, ctx) {
  let output = ''
  let index = 0
  while (index < text.length) {
    const start = text.indexOf('${{', index)
    if (start < 0) {
      output += text.slice(index)
      break
    }
    output += text.slice(index, start)
    const end = text.indexOf('}}', start)
    if (end < 0) throw new Error('unclosed expression')
    const value = evaluateNode(parseExpression(text.slice(start + 3, end)), ctx)
    output += convertToString(value)
    index = end + 2
  }
  return output
}

function contextFor (event, jobStatus, needs) {
  return {
    jobStatus,
    scope: {
      github: {
        event,
        repository: repo,
        token: workflowToken,
        actor: event?.comment?.user?.login ?? null
      },
      secrets: {
        GITHUB_TOKEN: workflowToken
      },
      needs: needs ?? {}
    }
  }
}

function commentEvent ({
  action = 'created',
  association,
  body,
  pullRequest = true,
  issueNumber = 7,
  commentLogin = 'outside-user'
}) {
  const issue = {
    number: issueNumber,
    author_association: 'OWNER',
    user: { login: 'pr-author' }
  }
  if (pullRequest) {
    issue.pull_request = {
      url: 'https://api.github.com/repos/' + repo + '/pulls/' + issueNumber,
      html_url: 'https://github.com/' + repo + '/pull/' + issueNumber,
      diff_url: 'https://github.com/' + repo + '/pull/' + issueNumber + '.diff',
      patch_url: 'https://github.com/' + repo + '/pull/' + issueNumber + '.patch',
      merged_at: null
    }
  }
  return {
    action,
    issue,
    comment: {
      body,
      author_association: association,
      user: { login: commentLogin }
    }
  }
}

function needsOf (job) {
  if (job.needs == null) return []
  return Array.isArray(job.needs) ? job.needs : [job.needs]
}

function orderedJobs (jobs) {
  const visiting = new Set()
  const visited = new Set()
  const order = []
  const visit = (id) => {
    if (visited.has(id)) return
    if (visiting.has(id)) throw new Error('job needs cycle at ' + id)
    if (jobs[id] == null) throw new Error('missing needed job ' + id)
    visiting.add(id)
    for (const needed of needsOf(jobs[id])) visit(needed)
    visiting.delete(id)
    visited.add(id)
    order.push(id)
  }
  for (const id of Object.keys(jobs)) visit(id)
  return order
}

function activityAllowed (workflow, event) {
  const trigger = workflow.on && workflow.on.issue_comment
  if (trigger == null) return false
  if (trigger.types == null) return true
  const types = Array.isArray(trigger.types) ? trigger.types : [trigger.types]
  return types.includes(event.action)
}

function gitEnvFor (home) {
  return {
    PATH: process.env.PATH,
    HOME: home,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com'
  }
}

function runGit (cwd, env, args) {
  const result = spawnSync('git', args, { cwd, env, encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(redact((result.stderr || result.stdout || 'git failed').trim()))
  }
  return (result.stdout || '').trim()
}

function initFixture () {
  const dir = mkdtempSync(path.join(tmpdir(), 'rebase-authz-'))
  const home = path.join(dir, 'setup-home')
  const origin = path.join(dir, 'origin')
  mkdirSync(home)
  const env = gitEnvFor(home)
  env.GIT_CONFIG_GLOBAL = '/dev/null'
  const git = (args, cwd = origin) => runGit(cwd, env, args)
  git(['init', '-q', '-b', 'develop', origin], dir)
  writeFileSync(path.join(origin, 'file'), 'a\n')
  git(['add', 'file'])
  git(['commit', '-qm', 'A'])
  const commitA = git(['rev-parse', 'HEAD'])
  writeFileSync(path.join(origin, 'file'), 'a\nb\n')
  git(['add', 'file'])
  git(['commit', '-qm', 'B'])
  git(['checkout', '-q', '-b', 'feature-7', commitA])
  writeFileSync(path.join(origin, 'feature7'), 'f7\n')
  git(['add', 'feature7'])
  git(['commit', '-qm', 'F7'])
  git(['checkout', '-q', '-b', 'feature-999', commitA])
  writeFileSync(path.join(origin, 'feature999'), 'f999\n')
  git(['add', 'feature999'])
  git(['commit', '-qm', 'F999'])
  git(['checkout', '-q', 'develop'])
  const pulls = path.join(dir, 'pulls')
  mkdirSync(pulls)
  for (const [number, head] of [[7, 'feature-7'], [999, 'feature-999']]) {
    writeFileSync(path.join(pulls, number + '.json'), JSON.stringify({
      rebaseable: true,
      base: { ref: 'develop', repo: { full_name: repo } },
      head: { ref: head, repo: { full_name: repo } }
    }))
  }
  return {
    dir,
    origin,
    pulls,
    before: {
      'feature-7': git(['rev-parse', 'feature-7']),
      'feature-999': git(['rev-parse', 'feature-999'])
    }
  }
}

function tip (fixture, branch) {
  const env = gitEnvFor(path.join(fixture.dir, 'setup-home'))
  env.GIT_CONFIG_GLOBAL = '/dev/null'
  return runGit(fixture.origin, env, ['rev-parse', branch])
}

function writeCurlStub (binDir, pullsDir) {
  mkdirSync(binDir)
  const stub = `#!/bin/bash
url=""
for arg in "$@"; do
  case "$arg" in
    https://*) url="$arg" ;;
  esac
done
case "$url" in
  https://api.github.com/repos/${repo}/pulls/*)
    number="\${url##*/}"
    number="\${number%%\\?*}"
    cat "${pullsDir}/$number.json"
    ;;
  https://api.github.com/users/*)
    printf '%s\\n' '{"name":null,"email":null}'
    ;;
  *)
    echo "blocked non-local request" >&2
    exit 1
    ;;
esac
`
  const stubPath = path.join(binDir, 'curl')
  writeFileSync(stubPath, stub)
  spawnSync('chmod', ['755', stubPath])
}

function runWorkflow (fixture, event) {
  const workflow = loadWorkflow()
  const outcome = {
    rebaseInvoked: false,
    checkoutInvoked: false,
    rebaseExit: null
  }
  if (!activityAllowed(workflow, event)) return outcome
  const jobs = workflow.jobs || {}
  const results = {}
  let jobStatus = 'success'
  for (const jobId of orderedJobs(jobs)) {
    const job = jobs[jobId]
    const needs = {}
    for (const needed of needsOf(job)) {
      needs[needed] = { result: results[needed] || 'skipped', outputs: {} }
    }
    const unmetNeeds = needsOf(job).some(needed => results[needed] !== 'success')
    if (unmetNeeds && !expressionReferencesAlways(job.if)) {
      results[jobId] = 'skipped'
      continue
    }
    jobStatus = 'success'
    const jobCtx = contextFor(event, jobStatus, needs)
    if (!conditionIsTrue(job.if, jobCtx)) {
      results[jobId] = 'skipped'
      continue
    }
    const workspace = path.join(fixture.dir, 'workspace-' + jobId)
    for (const step of job.steps || []) {
      const stepCtx = contextFor(event, jobStatus, needs)
      if (!conditionIsTrue(step.if, stepCtx)) continue
      const uses = typeof step.uses === 'string' ? step.uses : ''
      if (uses.startsWith('actions/checkout@') || uses === 'actions/checkout') {
        outcome.checkoutInvoked = true
        const cloneEnv = gitEnvFor(path.join(fixture.dir, 'setup-home'))
        cloneEnv.GIT_CONFIG_GLOBAL = '/dev/null'
        if (!existsSync(workspace)) {
          runGit(fixture.dir, cloneEnv, ['clone', '-q', fixture.origin, workspace])
        }
        continue
      }
      if (uses.startsWith('cirrus-actions/rebase@')) {
        const pin = uses.slice('cirrus-actions/rebase@'.length).trim()
        if (pin !== rebasePin) throw new Error('rebase action pin changed to ' + pin)
        outcome.rebaseInvoked = true
        const actionHome = path.join(fixture.dir, 'action-home')
        mkdirSync(actionHome)
        const binDir = path.join(fixture.dir, 'bin')
        if (!existsSync(path.join(binDir, 'curl'))) writeCurlStub(binDir, fixture.pulls)
        const remote = 'https://x-access-token:' + workflowToken + '@github.com/' + repo + '.git'
        runGit(actionHome, gitEnvFor(actionHome), ['config', '--global', 'url.' + fixture.origin + '/.insteadOf', remote])
        const stepEnv = {
          PATH: binDir + ':' + process.env.PATH,
          HOME: actionHome,
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_EDITOR: 'true',
          GITHUB_EVENT_PATH: path.join(fixture.dir, 'event.json'),
          GITHUB_REPOSITORY: repo,
          GITHUB_TOKEN: workflowToken,
          INPUT_AUTOSQUASH: 'false',
          MAX_RETRIES: '1',
          RETRY_INTERVAL: '0'
        }
        writeFileSync(stepEnv.GITHUB_EVENT_PATH, JSON.stringify(event))
        const expandedEnv = {}
        for (const [key, value] of Object.entries(step.env || {})) {
          expandedEnv[key] = expandExpressions(String(value), stepCtx)
        }
        if (expandedEnv.GITHUB_TOKEN != null) stepEnv.GITHUB_TOKEN = expandedEnv.GITHUB_TOKEN
        for (const [key, value] of Object.entries(expandedEnv)) stepEnv[key] = value
        if (step.with && step.with.autosquash != null) {
          const raw = String(step.with.autosquash)
          stepEnv.INPUT_AUTOSQUASH = raw.includes('${{') ? expandExpressions(raw, stepCtx) : raw
        }
        const cwd = existsSync(path.join(workspace, '.git')) ? workspace : fixture.dir
        const executed = spawnSync('bash', [entrypointPath], {
          cwd,
          env: stepEnv,
          encoding: 'utf8'
        })
        outcome.rebaseExit = executed.status
        if (executed.status !== 0) jobStatus = 'failure'
        continue
      }
      if (typeof step.run === 'string') {
        const scriptPath = path.join(fixture.dir, 'step-' + jobId + '.sh')
        writeFileSync(scriptPath, expandExpressions(step.run, stepCtx))
        const stepEnv = {
          PATH: process.env.PATH,
          HOME: path.join(fixture.dir, 'setup-home'),
          GITHUB_EVENT_PATH: path.join(fixture.dir, 'event.json'),
          GITHUB_REPOSITORY: repo,
          GITHUB_TOKEN: workflowToken
        }
        writeFileSync(stepEnv.GITHUB_EVENT_PATH, JSON.stringify(event))
        for (const [key, value] of Object.entries(step.env || {})) {
          stepEnv[key] = expandExpressions(String(value), stepCtx)
        }
        const executed = spawnSync('bash', ['--noprofile', '--norc', '-e', scriptPath], {
          cwd: existsSync(workspace) ? workspace : fixture.dir,
          env: stepEnv,
          encoding: 'utf8'
        })
        if (executed.status !== 0) jobStatus = 'failure'
      }
    }
    results[jobId] = jobStatus === 'failure' ? 'failure' : 'success'
  }
  return outcome
}

function withFixture (fn) {
  const fixture = initFixture()
  try {
    return fn(fixture)
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true })
  }
}

function observed (fixture, outcome) {
  return {
    rebaseInvoked: outcome.rebaseInvoked,
    checkoutInvoked: outcome.checkoutInvoked,
    feature7: tip(fixture, 'feature-7'),
    feature999: tip(fixture, 'feature-999')
  }
}

function assertUntouched (fixture, outcome) {
  assert.deepEqual(observed(fixture, outcome), {
    rebaseInvoked: false,
    checkoutInvoked: false,
    feature7: fixture.before['feature-7'],
    feature999: fixture.before['feature-999']
  })
}

function assertRewroteCommentedBranch (fixture, outcome) {
  assert.equal(outcome.rebaseInvoked, true)
  assert.equal(outcome.rebaseExit, 0)
  assert.notEqual(tip(fixture, 'feature-7'), fixture.before['feature-7'])
  assert.equal(tip(fixture, 'feature-999'), fixture.before['feature-999'])
  const env = gitEnvFor(path.join(fixture.dir, 'setup-home'))
  env.GIT_CONFIG_GLOBAL = '/dev/null'
  const ancestor = spawnSync('git', ['merge-base', '--is-ancestor', fixture.before['feature-7'], 'feature-7'], {
    cwd: fixture.origin,
    env,
    encoding: 'utf8'
  })
  assert.notEqual(ancestor.status, 0)
  const log = runGit(fixture.origin, env, ['log', '--format=%s', 'feature-7'])
  assert.match(log, /^F7\nB\nA$/)
}

describe('rebase workflow authorization', () => {
  it('evaluates runner comparisons used by the workflow condition', () => {
    const pullRequest = contextFor(commentEvent({ association: 'NONE', body: 'Please /ReBase now' }), 'success', {})
    const issue = contextFor(commentEvent({ association: 'NONE', body: '/rebase', pullRequest: false }), 'success', {})
    assert.equal(conditionIsTrue("github.event.issue.pull_request != ''", issue), false)
    assert.equal(conditionIsTrue("github.event.issue.pull_request != ''", pullRequest), true)
    assert.equal(conditionIsTrue("contains(github.event.comment.body, '/rebase')", pullRequest), true)
    assert.equal(conditionIsTrue("false && true || true", pullRequest), true)
    assert.equal(conditionIsTrue("contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), 'member')", pullRequest), true)
    assert.equal(conditionIsTrue("github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'MEMBER' && contains(github.event.comment.body, '/rebase')", pullRequest), false)
  })

  for (const association of deniedAssociations) {
    it('does not rewrite history for a ' + association + ' commenter', () => {
      withFixture(fixture => {
        const outcome = runWorkflow(fixture, commentEvent({
          association,
          body: '/rebase',
          commentLogin: 'outside-user'
        }))
        assertUntouched(fixture, outcome)
      })
    })
  }

  it('does not rewrite history when an outside comment merely contains /rebase', () => {
    withFixture(fixture => {
      const outcome = runWorkflow(fixture, commentEvent({
        association: 'NONE',
        body: 'Please /ReBase now',
        commentLogin: 'outside-user'
      }))
      assertUntouched(fixture, outcome)
    })
  })

  it('does not rewrite history for an outside comment on an issue', () => {
    withFixture(fixture => {
      const outcome = runWorkflow(fixture, commentEvent({
        association: 'NONE',
        body: '/rebase',
        pullRequest: false
      }))
      assertUntouched(fixture, outcome)
    })
  })

  it('does not run the rebase for an edited comment', () => {
    withFixture(fixture => {
      const outcome = runWorkflow(fixture, commentEvent({
        action: 'edited',
        association: 'OWNER',
        body: '/rebase',
        commentLogin: 'owner-user'
      }))
      assertUntouched(fixture, outcome)
    })
  })

  for (const association of allowedAssociations) {
    it('rewrites only the commented pull request for a ' + association, () => {
      withFixture(fixture => {
        const outcome = runWorkflow(fixture, commentEvent({
          association,
          body: '/rebase',
          commentLogin: association.toLowerCase() + '-user'
        }))
        assertRewroteCommentedBranch(fixture, outcome)
      })
    })
  }

  it('does not rebase when a maintainer comment lacks /rebase', () => {
    withFixture(fixture => {
      const outcome = runWorkflow(fixture, commentEvent({
        association: 'MEMBER',
        body: 'ship it',
        commentLogin: 'member-user'
      }))
      assertUntouched(fixture, outcome)
    })
  })

  it('rebases the pull request that was commented on when the body names another pull request', () => {
    withFixture(fixture => {
      const outcome = runWorkflow(fixture, commentEvent({
        association: 'OWNER',
        body: '/rebase 999',
        issueNumber: 7,
        commentLogin: 'owner-user'
      }))
      assertRewroteCommentedBranch(fixture, outcome)
    })
  })
})
