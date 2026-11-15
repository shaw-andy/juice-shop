/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const workflowPath = path.join(repoRoot, '.github/workflows/pr-compliance.yml')
const templatePath = path.join(repoRoot, '.github/PULL_REQUEST_TEMPLATE.md')
const depRoot = path.join(tmpdir(), 'juice-shop-pr-compliance-deps')

const ACTIONS_TOKEN = 'ghs_actions_token_placeholder'
const ORG_ADMIN_TOKEN = 'org-admin-token-placeholder'

const VERSIONS = {
  '@actions/github': '6.0.0',
  '@actions/core': '1.10.1',
  '@octokit/core': '5.0.1',
  '@octokit/request': '8.1.1',
  '@octokit/request-error': '5.0.0',
  '@octokit/plugin-rest-endpoint-methods': '10.0.1',
  '@octokit/plugin-retry': '6.0.1',
  'js-yaml': '3.14.1'
}

function ensureDeps () {
  const marker = path.join(depRoot, 'node_modules', '@actions', 'github', 'package.json')
  if (!existsSync(marker)) {
    mkdirSync(depRoot, { recursive: true })
    writeFileSync(path.join(depRoot, 'package.json'), JSON.stringify({
      name: 'pr-compliance-deps',
      private: true,
      dependencies: {
        '@actions/github': VERSIONS['@actions/github'],
        '@actions/core': VERSIONS['@actions/core'],
        '@octokit/plugin-retry': VERSIONS['@octokit/plugin-retry'],
        'js-yaml': VERSIONS['js-yaml']
      },
      overrides: {
        '@octokit/core': VERSIONS['@octokit/core'],
        '@octokit/request': VERSIONS['@octokit/request'],
        '@octokit/request-error': VERSIONS['@octokit/request-error'],
        '@octokit/plugin-rest-endpoint-methods': VERSIONS['@octokit/plugin-rest-endpoint-methods']
      }
    }))
    execFileSync('npm', ['install', '--silent', '--prefix', depRoot], { stdio: 'inherit' })
  }
  for (const [name, version] of Object.entries(VERSIONS)) {
    const installed = JSON.parse(readFileSync(path.join(depRoot, 'node_modules', name, 'package.json'), 'utf8')).version
    if (installed !== version) {
      throw new Error(`${name} resolved to ${installed}, expected ${version}`)
    }
  }
}

ensureDeps()

const { createRequire } = await import('node:module')
const require = createRequire(path.join(depRoot, 'package.json'))
const yaml = require('js-yaml')
const core = require('@actions/core')
const { getOctokit } = require('@actions/github')
const { Context } = require('@actions/github/lib/context')
const { retry } = require('@octokit/plugin-retry')

const workflow = yaml.safeLoad(readFileSync(workflowPath, 'utf8'))
const steps = workflow.jobs['check-compliance'].steps
const templateBody = readFileSync(templatePath, 'utf8')

function diffEntry (file) {
  return {
    sha: '0123456789abcdef0123456789abcdef01234567',
    filename: file.filename,
    status: file.status,
    additions: file.additions,
    deletions: file.deletions,
    changes: file.additions + file.deletions,
    blob_url: `https://github.com/shaw-andy/juice-shop/blob/develop/${file.filename}`,
    raw_url: `https://github.com/shaw-andy/juice-shop/raw/develop/${file.filename}`,
    contents_url: `https://api.github.com/repos/shaw-andy/juice-shop/contents/${file.filename}`
  }
}

function commitEntry (message) {
  return {
    url: 'https://api.github.com/repos/shaw-andy/juice-shop/commits/0123456789abcdef0123456789abcdef01234567',
    sha: '0123456789abcdef0123456789abcdef01234567',
    node_id: 'MDY6Q29tbWl0MA==',
    html_url: 'https://github.com/shaw-andy/juice-shop/commit/0123456789abcdef0123456789abcdef01234567',
    comments_url: 'https://api.github.com/repos/shaw-andy/juice-shop/commits/0123456789abcdef0123456789abcdef01234567/comments',
    commit: {
      message,
      comment_count: 0
    },
    author: null,
    committer: null,
    parents: []
  }
}

function orgMembership (username, state) {
  return {
    url: `https://api.github.com/orgs/juice-shop/memberships/${username}`,
    state,
    role: 'member',
    direct_membership: true,
    enterprise_teams_providing_indirect_membership: [],
    organization_url: 'https://api.github.com/orgs/juice-shop',
    organization: { login: 'juice-shop' },
    user: { login: username },
    permissions: { can_create_repository: false }
  }
}

function parseNumber (str) {
  str = (str ?? '').trim()
  if (str.length === 0) return 0
  if (/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(str)) return Number(str)
  if (str[0] === '0' && str.length > 2 && str[1] === 'x' && /^[0-9a-fA-F]+$/.test(str.slice(2))) {
    const integer = Number.parseInt(str.slice(2), 16)
    if (integer <= 0x7fffffff) return integer
  }
  if (str[0] === '0' && str.length > 2 && str[1] === 'o' && /^[0-7]+$/.test(str.slice(2))) {
    const integer = Number.parseInt(str.slice(2), 8)
    if (integer <= 0x7fffffff) return integer
  }
  if (str === 'Infinity') return Number.POSITIVE_INFINITY
  if (str === '-Infinity') return Number.NEGATIVE_INFINITY
  return Number.NaN
}

function kindOf (value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value === 'number') return 'number'
  if (typeof value === 'string') return 'string'
  return 'object'
}

function convertToNumber (value) {
  switch (kindOf(value)) {
    case 'null': return 0
    case 'boolean': return value ? 1 : 0
    case 'number': return value
    case 'string': return parseNumber(value)
    default: return Number.NaN
  }
}

function coerceTypes (left, right) {
  let leftKind = kindOf(left)
  let rightKind = kindOf(right)
  if (leftKind === rightKind) return { left, right, leftKind, rightKind }
  if (leftKind === 'number' && rightKind === 'string') {
    return { left, right: convertToNumber(right), leftKind, rightKind: 'number' }
  }
  if (leftKind === 'string' && rightKind === 'number') {
    return { left: convertToNumber(left), right, leftKind: 'number', rightKind }
  }
  if (leftKind === 'boolean' || leftKind === 'null') {
    return coerceTypes(convertToNumber(left), right)
  }
  if (rightKind === 'boolean' || rightKind === 'null') {
    return coerceTypes(left, convertToNumber(right))
  }
  return { left, right, leftKind, rightKind }
}

function abstractEqual (left, right) {
  const coerced = coerceTypes(left, right)
  if (coerced.leftKind !== coerced.rightKind) return false
  if (coerced.leftKind === 'null') return true
  if (coerced.leftKind === 'number') {
    if (Number.isNaN(coerced.left) || Number.isNaN(coerced.right)) return false
    return coerced.left === coerced.right
  }
  if (coerced.leftKind === 'string') return coerced.left.toLowerCase() === coerced.right.toLowerCase()
  if (coerced.leftKind === 'boolean') return coerced.left === coerced.right
  return false
}

function abstractGreaterThan (left, right) {
  const coerced = coerceTypes(left, right)
  if (coerced.leftKind !== coerced.rightKind) return false
  if (coerced.leftKind === 'number') {
    if (Number.isNaN(coerced.left) || Number.isNaN(coerced.right)) return false
    return coerced.left > coerced.right
  }
  if (coerced.leftKind === 'string') return coerced.left.toLowerCase() > coerced.right.toLowerCase()
  if (coerced.leftKind === 'boolean') return coerced.left && !coerced.right
  return false
}

function abstractGreaterThanOrEqual (left, right) {
  return abstractEqual(left, right) || abstractGreaterThan(left, right)
}

function isFalsy (value) {
  const kind = kindOf(value)
  if (kind === 'null') return true
  if (kind === 'boolean') return !value
  if (kind === 'number') return value === 0 || Number.isNaN(value)
  if (kind === 'string') return value === ''
  return false
}

function tokenize (input) {
  const tokens = []
  let i = 0
  while (i < input.length) {
    if (/\s/.test(input[i])) {
      i++
      continue
    }
    if (input.startsWith('&&', i) || input.startsWith('==', i) || input.startsWith('>=', i)) {
      tokens.push(input.slice(i, i + 2))
      i += 2
      continue
    }
    if ('().'.includes(input[i])) {
      tokens.push(input[i])
      i++
      continue
    }
    if (input[i] === "'" || input[i] === '"') {
      const quote = input[i]
      i++
      let value = ''
      while (i < input.length && input[i] !== quote) {
        value += input[i]
        i++
      }
      i++
      tokens.push({ string: value })
      continue
    }
    if (/[0-9]/.test(input[i])) {
      let value = ''
      while (i < input.length && /[0-9.]/.test(input[i])) {
        value += input[i]
        i++
      }
      tokens.push({ number: Number(value) })
      continue
    }
    if (/[A-Za-z_]/.test(input[i])) {
      let value = ''
      while (i < input.length && /[A-Za-z0-9_-]/.test(input[i])) {
        value += input[i]
        i++
      }
      tokens.push({ ident: value })
      continue
    }
    throw new Error(`Cannot tokenize expression at ${input.slice(i)}`)
  }
  return tokens
}

function evaluateExpression (expression, env) {
  const tokens = tokenize(expression)
  let index = 0
  const peek = () => tokens[index]
  const take = () => tokens[index++]

  function evalAnd () {
    let value = evalComparison()
    while (peek() === '&&') {
      take()
      const next = evalComparison()
      if (!isFalsy(value)) value = next
    }
    return value
  }

  function evalComparison () {
    const left = evalUnary()
    if (peek() === '==') {
      take()
      return abstractEqual(left, evalUnary())
    }
    if (peek() === '>=') {
      take()
      return abstractGreaterThanOrEqual(left, evalUnary())
    }
    return left
  }

  function evalUnary () {
    const token = take()
    if (token && token.ident) {
      if (peek() === '(') {
        take()
        if (take() !== ')') throw new Error(`Expected ) after ${token.ident}`)
        if (token.ident === 'always') return true
        if (token.ident === 'success') return env.jobStatus === 'success'
        throw new Error(`Unknown function ${token.ident}`)
      }
      const path = [token.ident]
      while (peek() === '.') {
        take()
        const part = take()
        path.push(part.ident)
      }
      return lookup(env, path)
    }
    if (token && Object.hasOwn(token, 'string')) return token.string
    if (token && Object.hasOwn(token, 'number')) return token.number
    if (token === '(') {
      const value = evalAnd()
      if (take() !== ')') throw new Error('Expected )')
      return value
    }
    throw new Error(`Unexpected token ${JSON.stringify(token)}`)
  }

  const value = evalAnd()
  if (index !== tokens.length) throw new Error(`Unused expression tokens in ${expression}`)
  return value
}

function lookup (env, pathParts) {
  let current = env
  for (const part of pathParts) {
    if (current == null || typeof current !== 'object') return null
    if (!Object.hasOwn(current, part)) return null
    current = current[part]
  }
  return current
}

function shouldRun (step, env) {
  if (!step.if) return !isFalsy(evaluateExpression('success()', env))
  const expression = /\b(always|failure|cancelled)\s*\(/.test(step.if)
    ? step.if
    : `success() && (${step.if})`
  return !isFalsy(evaluateExpression(expression, env))
}

function interpolate (value, env) {
  return String(value).replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_match, expression) => {
    const result = evaluateExpression(expression, env)
    if (result === null || result === undefined) return ''
    return String(result)
  })
}

function readStepOutputs (filePath) {
  const text = readFileSync(filePath, 'utf8')
  const outputs = {}
  const pattern = /^([^\n<]+)<<([^\n]+)\n([\s\S]*?)\n\2\n/gm
  for (const match of text.matchAll(pattern)) {
    outputs[match[1]] = match[3]
  }
  return outputs
}

function headerMap (headers) {
  const out = {}
  if (!headers) return out
  if (typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      out[String(key).toLowerCase()] = value
    })
    return out
  }
  for (const [key, value] of Object.entries(headers)) out[key.toLowerCase()] = value
  return out
}

function jsonResponse (status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

function emptyResponse (status) {
  return new Response(null, { status })
}

function basicError (message) {
  return { message, documentation_url: 'https://docs.github.com/rest' }
}

class Api {
  constructor (scenario) {
    this.scenario = scenario
    this.requests = []
    this.sequences = structuredClone(scenario.sequences ?? {})
  }

  user (username) {
    const user = this.scenario.users[username]
    if (!user) throw new Error(`No membership fixture for ${username}`)
    return user
  }

  next (kind, username) {
    const queued = this.sequences[kind]?.[username]
    if (queued && queued.length > 0) return queued.shift()
    return null
  }

  async handle (url, options) {
    const parsed = new URL(url)
    const method = (options.method ?? 'GET').toUpperCase()
    const headers = headerMap(options.headers)
    const pathname = decodeURI(parsed.pathname)
    const parts = pathname.split('/').filter(Boolean)
    let bodyText = ''
    if (options.body) bodyText = String(options.body)
    let body = null
    if (bodyText) {
      try { body = JSON.parse(bodyText) } catch { body = bodyText }
    }

    const record = { method, pathname, status: 0, headers, body }
    this.requests.push(record)

    if (parsed.hostname !== 'api.github.com') {
      record.status = 0
      throw new Error(`Refusing request to ${parsed.hostname}`)
    }

    try {
      const response = await this.route(method, parts, body, record)
      record.status = response.status
      return response
    } catch (error) {
      record.status = 0
      record.error = error.message
      throw error
    }
  }

  route (method, parts, body, record) {
    if (method === 'GET' && parts[0] === 'repos' && parts[3] === 'pulls' && parts[5] === 'files') {
      record.kind = 'list-files'
      return jsonResponse(200, this.scenario.files.map(diffEntry))
    }
    if (method === 'GET' && parts[0] === 'repos' && parts[3] === 'pulls' && parts[5] === 'commits') {
      record.kind = 'list-commits'
      return jsonResponse(200, this.scenario.commits.map(commit => commitEntry(commit.message)))
    }
    if (method === 'GET' && parts[0] === 'orgs' && parts[1] === 'juice-shop' && parts[2] === 'public_members') {
      return this.publicMembership(parts[3], record)
    }
    if (method === 'GET' && parts[0] === 'orgs' && parts[1] === 'juice-shop' && parts[2] === 'memberships') {
      return this.orgMembership(parts[3], record)
    }
    if (method === 'GET' && parts[0] === 'orgs' && parts[1] === 'juice-shop' && parts[2] === 'members') {
      return this.memberCheck(parts[3], record)
    }
    if (method === 'PUT' && parts[0] === 'orgs' && parts[1] === 'juice-shop' && parts[2] === 'blocks') {
      record.kind = 'block'
      record.username = parts[3]
      return emptyResponse(204)
    }
    if (method === 'POST' && parts[0] === 'repos' && parts[3] === 'issues' && parts[5] === 'labels') {
      record.kind = 'labels'
      record.issue = Number(parts[4])
      return jsonResponse(200, body?.labels ?? [])
    }
    if (method === 'POST' && parts[0] === 'repos' && parts[3] === 'issues' && parts[5] === 'comments') {
      record.kind = 'comment'
      record.issue = Number(parts[4])
      return jsonResponse(201, { id: 1, body: body?.body ?? '' })
    }
    if (method === 'PATCH' && parts[0] === 'repos' && parts[3] === 'pulls') {
      record.kind = 'close'
      record.pull = Number(parts[4])
      record.state = body?.state
      return jsonResponse(200, { number: record.pull, state: body?.state })
    }
    record.kind = 'unknown'
    return jsonResponse(404, basicError('Not Found'))
  }

  publicMembership (username, record) {
    record.kind = 'public'
    record.username = username
    const queued = this.next('public', username)
    if (queued === 'network') throw new TypeError('network error')
    if (queued === '500') return jsonResponse(500, basicError('Internal Server Error'))
    const user = this.user(username)
    if (user.publicMember) return emptyResponse(204)
    return jsonResponse(404, basicError('Not Found if user is not a public member'))
  }

  orgMembership (username, record) {
    record.kind = 'memberships'
    record.username = username
    const queued = this.next('memberships', username)
    if (queued === 'network') throw new TypeError('network error')
    if (queued === '500') return jsonResponse(500, basicError('Internal Server Error'))
    if (queued === '404') return jsonResponse(404, basicError('Not Found'))
    if (queued === '200') {
      record.membershipState = 'active'
      return jsonResponse(200, orgMembership(username, 'active'))
    }
    const user = this.user(username)
    if (!user.member) return jsonResponse(404, basicError('Not Found'))
    record.membershipState = 'active'
    return jsonResponse(200, orgMembership(username, 'active'))
  }

  memberCheck (username, record) {
    record.kind = 'members'
    record.username = username
    const queued = this.next('members', username)
    if (queued === 'network') throw new TypeError('network error')
    if (queued === '500') return jsonResponse(500, basicError('Internal Server Error'))
    const user = this.user(username)
    if (!user.member) return jsonResponse(404, basicError('Not Found'))
    return emptyResponse(204)
  }
}

function callAsyncFunction (args, source) {
  const AsyncFunction = Object.getPrototypeOf(async () => null).constructor
  const fn = new AsyncFunction(...Object.keys(args), source)
  return fn(...Object.values(args))
}

async function runWorkflow (scenario) {
  const api = new Api(scenario)
  const mockedFetch = (url, options = {}) => api.handle(url, options)
  const previousFetch = globalThis.fetch
  globalThis.fetch = mockedFetch
  const eventDir = mkdtempSync(path.join(tmpdir(), 'pr-event-'))
  const eventPath = path.join(eventDir, 'event.json')
  const author = scenario.author
  const pullNumber = scenario.pullNumber
  writeFileSync(eventPath, JSON.stringify({
    pull_request: {
      number: pullNumber,
      body: scenario.body,
      title: scenario.title,
      base: { ref: scenario.baseRef },
      user: { login: author }
    },
    repository: {
      name: 'juice-shop',
      owner: { login: 'shaw-andy' }
    }
  }))
  const previousEnv = {
    GITHUB_EVENT_PATH: process.env.GITHUB_EVENT_PATH,
    GITHUB_EVENT_NAME: process.env.GITHUB_EVENT_NAME,
    GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY
  }
  process.env.GITHUB_EVENT_PATH = eventPath
  process.env.GITHUB_EVENT_NAME = 'pull_request_target'
  process.env.GITHUB_REPOSITORY = 'shaw-andy/juice-shop'
  const outputs = { steps: {}, secrets: scenario.secrets }
  const env = {
    steps: outputs.steps,
    secrets: outputs.secrets,
    jobStatus: 'success'
  }
  try {
    const context = new Context()
    const github = getOctokit(ACTIONS_TOKEN, {
      request: { fetch: mockedFetch },
      retry: { enabled: false }
    }, retry)
    for (const step of steps) {
      if (!shouldRun(step, env)) continue
      if (!String(step.uses ?? '').startsWith('actions/github-script@')) continue
      const stepEnvNames = []
      for (const [name, value] of Object.entries(step.env ?? {})) {
        stepEnvNames.push(name)
        process.env[name] = interpolate(value, env)
      }
      const outputFile = path.join(eventDir, `${step.id}.output`)
      writeFileSync(outputFile, '')
      process.env.GITHUB_OUTPUT = outputFile
      let stepError = null
      try {
        await callAsyncFunction({ github, context, core }, step.with.script)
      } catch (error) {
        env.jobStatus = 'failure'
        stepError = error
      } finally {
        for (const name of stepEnvNames) delete process.env[name]
      }
      outputs.steps[step.id] = { outputs: readStepOutputs(outputFile), error: stepError }
    }
    return { requests: api.requests, outputs: outputs.steps }
  } finally {
    globalThis.fetch = previousFetch
    delete process.env.GITHUB_OUTPUT
    for (const [name, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  }
}

function enforcement (requests) {
  return requests.filter(request => ['labels', 'comment', 'close', 'block', 'unknown'].includes(request.kind))
}

function confirmedAbsentBefore (requests, username, action) {
  const actionIndex = requests.indexOf(action)
  const prior = requests.slice(0, actionIndex).filter(request => request.username === username)
  const sawMember = prior.some(request =>
    (request.kind === 'memberships' && request.status === 200 && request.membershipState === 'active') ||
    (request.kind === 'members' && request.status === 204) ||
    (request.kind === 'public' && request.status === 204)
  )
  if (sawMember) return false
  const confirming = prior.filter(request =>
    (request.kind === 'memberships' || request.kind === 'members') && request.status === 404
  )
  if (confirming.length === 0) return false
  const lastLookup = [...prior].reverse().find(request =>
    request.kind === 'memberships' || request.kind === 'members' || request.kind === 'public'
  )
  return lastLookup?.status === 404 && (lastLookup.kind === 'memberships' || lastLookup.kind === 'members')
}

function lookupHappened (requests, username) {
  return requests.some(request =>
    request.username === username &&
    (request.kind === 'public' || request.kind === 'memberships' || request.kind === 'members')
  )
}

const ordinaryFile = [{ filename: 'routes/search.ts', status: 'modified', additions: 12, deletions: 1 }]
const maintainerFile = [{ filename: 'CONTRIBUTING.md', status: 'modified', additions: 8, deletions: 1 }]
const unsignedCommit = [{ message: 'Adjust product search validation\n\nExplain the search change for review.' }]

const maintainerBody = [
  '### Description',
  '',
  'This change updates the contributing guide wording so the rules are easier to follow.',
  '',
  '### AI Tool Disclosure',
  '',
  '- [ ] My contribution does not include any AI-generated content',
  '- [ ] My contribution includes AI-generated content',
  '',
  '### Affirmation',
  '',
  '- [ ] My code follows the CONTRIBUTING.md guidelines',
  ''
].join('\n')

function scenario (overrides) {
  return {
    pullNumber: 4177,
    title: 'Adjust product search validation',
    body: templateBody,
    baseRef: 'develop',
    files: ordinaryFile,
    commits: unsignedCommit,
    secrets: { ORG_ADMIN_TOKEN },
    ...overrides
  }
}

describe('PR compliance membership', () => {
  it('compares a string spam-rating output with the runner numeric rules', () => {
    const env = {
      steps: { spam: { outputs: { spamRating: '85' } }, membership: { outputs: { is_member: 'false' } } },
      jobStatus: 'success'
    }
    assert.equal(abstractGreaterThanOrEqual('85', 75), true)
    assert.equal(abstractGreaterThanOrEqual('', 75), false)
    assert.equal(abstractEqual('false', 'false'), true)
    assert.equal(isFalsy(evaluateExpression("steps.spam.outputs.spamRating >= 75", env)), false)
    assert.equal(isFalsy(evaluateExpression("steps.membership.outputs.is_member == 'false'", env)), false)
    const blockIf = steps.find(step => step.name === 'Block Spammer').if
    assert.equal(isFalsy(evaluateExpression(blockIf, env)), false)
    env.steps.membership.outputs.is_member = 'true'
    assert.equal(isFalsy(evaluateExpression(blockIf, env)), true)
  })

  it('does not close or block a private member who leaves the template placeholder', async () => {
    const author = 'private-member'
    const result = await runWorkflow(scenario({
      author,
      users: { [author]: { publicMember: false, member: true } }
    }))
    assert.equal(lookupHappened(result.requests, author), true)
    assert.deepEqual(enforcement(result.requests), [])
  })

  it('does not close or block a private member who edits a maintainer file', async () => {
    const author = 'private-member'
    const result = await runWorkflow(scenario({
      author,
      body: maintainerBody,
      files: maintainerFile,
      users: { [author]: { publicMember: false, member: true } }
    }))
    assert.equal(lookupHappened(result.requests, author), true)
    assert.deepEqual(enforcement(result.requests), [])
  })

  it('does not enforce when the public membership lookup throws for a public member', async () => {
    const author = 'public-member'
    const result = await runWorkflow(scenario({
      author,
      users: { [author]: { publicMember: true, member: true } },
      sequences: { public: { [author]: ['network'] } }
    }))
    assert.equal(lookupHappened(result.requests, author), true)
    assert.deepEqual(enforcement(result.requests), [])
  })

  it('does not enforce when every membership lookup returns an error', async () => {
    const author = 'public-member'
    const result = await runWorkflow(scenario({
      author,
      users: { [author]: { publicMember: true, member: true } },
      sequences: {
        public: { [author]: ['500', '500', '500'] },
        memberships: { [author]: ['500', '500', '500'] },
        members: { [author]: ['500', '500', '500'] }
      }
    }))
    assert.equal(lookupHappened(result.requests, author), true)
    assert.deepEqual(enforcement(result.requests), [])
  })

  it('does not enforce when a later membership lookup for the same private member errors', async () => {
    const author = 'private-member'
    const result = await runWorkflow(scenario({
      author,
      users: { [author]: { publicMember: false, member: true } },
      sequences: { memberships: { [author]: ['200', '500', '500'] } }
    }))
    assert.equal(lookupHappened(result.requests, author), true)
    assert.deepEqual(enforcement(result.requests), [])
  })

  it('closes and blocks a confirmed non-member once the spam rating reaches the threshold', async () => {
    const author = 'outsider'
    const result = await runWorkflow(scenario({
      author,
      users: { [author]: { publicMember: false, member: false } }
    }))
    const actions = enforcement(result.requests)
    assert.ok(actions.length > 0, 'expected enforcement against a confirmed non-member')
    for (const action of actions) {
      assert.equal(
        confirmedAbsentBefore(result.requests, author, action),
        true,
        `enforcement ${action.kind} was not preceded by an authenticated absence result for ${author}: ${JSON.stringify(result.requests.map(request => [request.kind, request.username, request.status]))}`
      )
      if (action.kind === 'block') assert.equal(action.username, author)
      if (action.kind === 'close') {
        assert.equal(action.pull, 4177)
        assert.equal(action.state, 'closed')
      }
      if (action.kind === 'labels') assert.equal(action.issue, 4177)
    }
    assert.ok(actions.some(action => action.kind === 'close'))
    assert.ok(actions.some(action => action.kind === 'block' && action.headers.authorization === `Bearer ${ORG_ADMIN_TOKEN}`))
    assert.ok(actions.some(action => action.kind === 'labels' && action.body.labels.includes('invalid')))
    assert.equal(isFalsy(abstractGreaterThanOrEqual(result.outputs.spam.outputs.spamRating, 75)), false)
  })

  it('closes a confirmed non-member without blocking when the org admin token is absent', async () => {
    const author = 'outsider'
    const result = await runWorkflow(scenario({
      author,
      secrets: { ORG_ADMIN_TOKEN: '' },
      users: { [author]: { publicMember: false, member: false } }
    }))
    const actions = enforcement(result.requests)
    assert.ok(actions.some(action => action.kind === 'close' && action.state === 'closed'))
    assert.equal(actions.some(action => action.kind === 'block'), false)
    for (const action of actions) {
      assert.equal(confirmedAbsentBefore(result.requests, author, action), true)
    }
  })

  it('does not enforce against a public member', async () => {
    const author = 'public-member'
    const result = await runWorkflow(scenario({
      author,
      users: { [author]: { publicMember: true, member: true } }
    }))
    assert.equal(lookupHappened(result.requests, author), true)
    assert.equal(result.requests.some(request => request.kind === 'public' && request.status === 204), true)
    assert.deepEqual(enforcement(result.requests), [])
  })
})
