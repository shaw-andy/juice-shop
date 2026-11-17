/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { load as loadYaml } from 'js-yaml'

const root = join(dirname(fileURLToPath(import.meta.url)), '../..')
const workflowPath = join(root, '.github/workflows/pr-compliance.yml')
const templatePath = join(root, '.github/PULL_REQUEST_TEMPLATE.md')

// Stand-in for a configured actions secret. Not a credential.
const PLACEHOLDER_ORG_ADMIN_TOKEN = 'placeholder-org-admin-token'

const SCANNER_NAMES = ['semgrep', 'snyk', 'sonar', 'fortify', 'checkmarx', 'veracode', 'trivy', 'grype', 'zap', 'burp']

interface PullFile {
  filename: string
  status: string
  additions: number
  deletions: number
}

interface Scenario {
  author: string
  title: string
  body: string | null
  baseRef: string
  files: PullFile[]
  commitMessages: string[]
  publicMember: boolean
  orgAdminToken: string
}

interface BlockRequest {
  method: string
  url: string
  username: string
  hasAuthorization: boolean
}

interface RunResult {
  blockRequests: BlockRequest[]
  spamRating: string | null
  isMember: string | null
  closed: boolean
}

interface StepOutputs {
  [name: string]: string
}

interface StepState {
  skipped: boolean
  outputs: StepOutputs
}

interface WorkflowStep {
  id?: string
  name?: string
  if?: string
  uses?: string
  env?: Record<string, string>
  with?: { script?: string }
}

interface WorkflowFile {
  jobs?: {
    'check-compliance'?: {
      steps?: WorkflowStep[]
    }
  }
}

void describe('pull request compliance organization block', () => {
  const template = readFileSync(templatePath, 'utf8')
  const ordinaryFile: PullFile = { filename: 'routes/search.ts', status: 'modified', additions: 12, deletions: 1 }

  void it('does not organization-block a non-member whose title is fix, body is empty, and AI, affirmation, and DCO checks are missing', async () => {
    const result = await runCompliance({
      author: 'external-contributor',
      title: 'fix',
      body: '',
      baseRef: 'develop',
      files: [ordinaryFile],
      commitMessages: ['fix the thing'],
      publicMember: false,
      orgAdminToken: PLACEHOLDER_ORG_ADMIN_TOKEN
    })
    assertNoOrgBlock(result)
  })

  void it('does not organization-block a non-member who leaves the pull request template checks unset', async () => {
    const result = await runCompliance({
      author: 'external-contributor',
      title: 'Correct the product price label',
      body: template,
      baseRef: 'develop',
      files: [ordinaryFile],
      commitMessages: ['Correct the product price label'],
      publicMember: false,
      orgAdminToken: PLACEHOLDER_ORG_ADMIN_TOKEN
    })
    assertNoOrgBlock(result)
  })

  for (const scanner of SCANNER_NAMES) {
    void it(`does not organization-block a non-member when ${scanner} appears in the title, body, and commit message`, async () => {
      const result = await runCompliance({
        author: 'external-contributor',
        title: `${scanner} findings`,
        body: checkedBody(`Reviewed a ${scanner} result in the login form.`),
        baseRef: 'develop',
        files: [ordinaryFile],
        commitMessages: [`Note ${scanner} output\n\nSigned-off-by: Contributor <contributor@example.com>`],
        publicMember: false,
        orgAdminToken: PLACEHOLDER_ORG_ADMIN_TOKEN
      })
      assertNoOrgBlock(result)
    })
  }

  void it('does not organization-block when the same short pull request is opened by a public organization member', async () => {
    const result = await runCompliance({
      author: 'public-maintainer',
      title: 'fix',
      body: '',
      baseRef: 'develop',
      files: [ordinaryFile],
      commitMessages: ['fix the thing'],
      publicMember: true,
      orgAdminToken: PLACEHOLDER_ORG_ADMIN_TOKEN
    })
    assert.equal(result.isMember, 'true')
    assertNoOrgBlock(result)
  })

  void it('does not organization-block a short pull request whose score stays under 75', async () => {
    const result = await runCompliance({
      author: 'external-contributor',
      title: 'fix',
      body: '',
      baseRef: 'develop',
      files: [ordinaryFile],
      commitMessages: ['fix the thing\n\nSigned-off-by: Contributor <contributor@example.com>'],
      publicMember: false,
      orgAdminToken: PLACEHOLDER_ORG_ADMIN_TOKEN
    })
    assertNoOrgBlock(result)
  })

  void it('does not organization-block when the organization admin token is absent', async () => {
    const result = await runCompliance({
      author: 'external-contributor',
      title: 'fix',
      body: '',
      baseRef: 'develop',
      files: [ordinaryFile],
      commitMessages: ['fix the thing'],
      publicMember: false,
      orgAdminToken: ''
    })
    assertNoOrgBlock(result)
  })

  void it('treats a step output of 75 as reaching the workflow threshold and 74 as below it', () => {
    const atThreshold = evaluateExpression('steps.spam.outputs.spamRating >= 75', {
      steps: { spam: { skipped: false, outputs: { spamRating: '75' } } },
      secrets: {},
      jobSuccess: true
    })
    const belowThreshold = evaluateExpression('steps.spam.outputs.spamRating >= 75', {
      steps: { spam: { skipped: false, outputs: { spamRating: '74' } } },
      secrets: {},
      jobSuccess: true
    })
    assert.equal(isTruthy(atThreshold), true)
    assert.equal(isTruthy(belowThreshold), false)
  })
})

function checkedBody (description: string): string {
  return [
    '### Description',
    '',
    description,
    '',
    '### AI Tool Disclosure',
    '',
    '- [x] My contribution does not include any AI-generated content',
    '',
    '### Affirmation',
    '',
    '- [x] My code follows the CONTRIBUTING.md guidelines'
  ].join('\n')
}

function assertNoOrgBlock (result: RunResult): void {
  assert.deepEqual(result.blockRequests, [], `spam rating ${result.spamRating ?? 'unset'} issued an organization block`)
}

async function runCompliance (scenario: Scenario): Promise<RunResult> {
  const workflow = loadYaml(readFileSync(workflowPath, 'utf8')) as WorkflowFile
  const steps = workflow.jobs?.['check-compliance']?.steps
  if (steps == null) throw new Error('check-compliance job is missing from the workflow')

  const stepState: Record<string, StepState> = {}
  const blockRequests: BlockRequest[] = []
  let closed = false
  let jobSuccess = true
  const previousFetch = globalThis.fetch
  globalThis.fetch = (async (input: unknown, init?: { method?: string, headers?: Record<string, string> }) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const username = blockUsername(url)
    if (username != null) {
      const authorization = init?.headers?.Authorization ?? init?.headers?.authorization ?? ''
      blockRequests.push({
        method,
        url,
        username,
        hasAuthorization: authorization.startsWith('Bearer ') && authorization.length > 'Bearer '.length
      })
    }
    // OpenAPI orgs/block-user: a successful block responds with 204.
    const status = method === 'PUT' && username != null ? 204 : 404
    return new Response(null, { status })
  }) as typeof fetch

  try {
    for (const step of steps) {
      const script = step.with?.script
      const usesGithubScript = typeof step.uses === 'string' && step.uses.startsWith('actions/github-script@')
      const condition = step.if ?? 'success()'
      const shouldRun = isTruthy(evaluateExpression(condition, { steps: stepState, secrets: { ORG_ADMIN_TOKEN: scenario.orgAdminToken }, jobSuccess }))
      if (!usesGithubScript || typeof script !== 'string' || !shouldRun) {
        if (step.id != null) stepState[step.id] = { skipped: true, outputs: {} }
        continue
      }
      const env = interpolateEnv(step.env ?? {}, stepState, scenario.orgAdminToken)
      const outputs: StepOutputs = {}
      const core = {
        setOutput (name: string, value: unknown) {
          outputs[name] = toCommandValue(value)
        }
      }
      const github = githubFor(scenario, () => { closed = true })
      const context = {
        payload: {
          pull_request: {
            number: 417,
            body: scenario.body,
            title: scenario.title,
            base: { ref: scenario.baseRef },
            user: { login: scenario.author }
          }
        },
        repo: { owner: 'juice-shop', repo: 'juice-shop' }
      }
      const originalLog = console.log
      console.log = () => undefined
      try {
        await withEnv(env, async () => {
          await callGithubScript(script, { github, context, core })
        })
        if (step.id != null) stepState[step.id] = { skipped: false, outputs }
      } catch (error) {
        jobSuccess = false
        if (step.id != null) stepState[step.id] = { skipped: false, outputs }
        throw error
      } finally {
        console.log = originalLog
      }
    }
  } finally {
    globalThis.fetch = previousFetch
  }

  return {
    blockRequests,
    spamRating: stepState.spam?.outputs.spamRating ?? null,
    isMember: stepState.membership?.outputs.is_member ?? null,
    closed
  }
}

function githubFor (scenario: Scenario, onClose: () => void) {
  return {
    rest: {
      pulls: {
        async listFiles () {
          return { data: scenario.files }
        },
        async listCommits () {
          return { data: scenario.commitMessages.map(message => ({ commit: { message } })) }
        },
        async update (params: { state?: string }) {
          if (params.state === 'closed') onClose()
          return { data: {} }
        }
      },
      issues: {
        async addLabels () {
          return { data: [] }
        },
        async createComment () {
          return { data: {} }
        }
      },
      orgs: {
        async checkPublicMembershipForUser (params: { org?: string, username?: string }) {
          if (params.org !== 'juice-shop' || params.username !== scenario.author) {
            const error = new Error('Not Found') as Error & { status: number }
            error.status = 404
            throw error
          }
          if (!scenario.publicMember) {
            // @octokit/request 8.1.1 throws RequestError when status >= 400.
            // Check public membership returns 404 when the user is not a public member.
            const error = new Error('Not Found') as Error & { status: number }
            error.status = 404
            throw error
          }
          return { status: 204, data: undefined }
        }
      }
    }
  }
}

function blockUsername (url: string): string | null {
  const match = /^https:\/\/api\.github\.com\/orgs\/juice-shop\/blocks\/([^/?#]+)$/.exec(url)
  if (match == null) return null
  return decodeURIComponent(match[1])
}

async function callGithubScript (source: string, bindings: { github: unknown, context: unknown, core: unknown }): Promise<void> {
  const AsyncFunction = Object.getPrototypeOf(async function () { await Promise.resolve() }).constructor as new (...args: string[]) => (...values: unknown[]) => Promise<unknown>
  const names = ['require', '__original_require__', 'github', 'octokit', 'context', 'core', 'exec', 'glob', 'io']
  const fn = new AsyncFunction(...names, source)
  await fn(undefined, undefined, bindings.github, bindings.github, bindings.context, bindings.core, undefined, undefined, undefined)
}

function toCommandValue (input: unknown): string {
  if (input === null || input === undefined) return ''
  if (typeof input === 'string') return input
  return JSON.stringify(input)
}

async function withEnv (env: Record<string, string>, fn: () => Promise<void>): Promise<void> {
  const previous = new Map<string, string | undefined>()
  for (const [key, value] of Object.entries(env)) {
    previous.set(key, process.env[key])
    process.env[key] = value
  }
  try {
    await fn()
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

function interpolateEnv (env: Record<string, string>, steps: Record<string, StepState>, orgAdminToken: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(env)) {
    result[key] = value.replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_match, expression: string) => {
      return expressionToString(evaluateExpression(expression, { steps, secrets: { ORG_ADMIN_TOKEN: orgAdminToken }, jobSuccess: true }))
    })
  }
  return result
}

interface EvalState {
  steps: Record<string, StepState>
  secrets: Record<string, string>
  jobSuccess: boolean
}

type ExprValue = null | boolean | number | string

function evaluateExpression (expression: string, state: EvalState): ExprValue {
  const parser = new Parser(tokenize(expression), state)
  const value = parser.parseOr()
  parser.end()
  return value
}

function expressionToString (value: ExprValue): string {
  if (value === null) return ''
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return String(value)
  return value
}

function isTruthy (value: ExprValue): boolean {
  return !isFalsy(value)
}

function isFalsy (value: ExprValue): boolean {
  if (value === null) return true
  if (typeof value === 'boolean') return !value
  if (typeof value === 'number') return value === 0 || Number.isNaN(value)
  return value === ''
}

function abstractEqual (left: ExprValue, right: ExprValue): boolean {
  const coerced = coerce(left, right)
  if (coerced.leftKind !== coerced.rightKind) return false
  if (coerced.leftKind === 'null') return true
  if (coerced.leftKind === 'number') {
    if (typeof coerced.left !== 'number' || typeof coerced.right !== 'number') return false
    if (Number.isNaN(coerced.left) || Number.isNaN(coerced.right)) return false
    return coerced.left === coerced.right
  }
  if (coerced.leftKind === 'string') {
    return String(coerced.left).toLowerCase() === String(coerced.right).toLowerCase()
  }
  if (coerced.leftKind === 'boolean') return coerced.left === coerced.right
  return false
}

function abstractGreaterThan (left: ExprValue, right: ExprValue): boolean {
  const coerced = coerce(left, right)
  if (coerced.leftKind !== coerced.rightKind) return false
  if (coerced.leftKind === 'number') {
    if (typeof coerced.left !== 'number' || typeof coerced.right !== 'number') return false
    if (Number.isNaN(coerced.left) || Number.isNaN(coerced.right)) return false
    return coerced.left > coerced.right
  }
  if (coerced.leftKind === 'string') {
    return String(coerced.left).toLowerCase() > String(coerced.right).toLowerCase()
  }
  if (coerced.leftKind === 'boolean') return coerced.left === true && coerced.right === false
  return false
}

function coerce (left: ExprValue, right: ExprValue): { left: ExprValue, right: ExprValue, leftKind: string, rightKind: string } {
  const leftKind = kindOf(left)
  const rightKind = kindOf(right)
  if (leftKind === rightKind) return { left, right, leftKind, rightKind }
  if (leftKind === 'number' && rightKind === 'string') {
    return { left, right: convertToNumber(right), leftKind, rightKind: 'number' }
  }
  if (leftKind === 'string' && rightKind === 'number') {
    return { left: convertToNumber(left), right, leftKind: 'number', rightKind }
  }
  if (leftKind === 'boolean' || leftKind === 'null') {
    return coerce(convertToNumber(left), right)
  }
  if (rightKind === 'boolean' || rightKind === 'null') {
    return coerce(left, convertToNumber(right))
  }
  return { left, right, leftKind, rightKind }
}

function convertToNumber (value: ExprValue): number {
  if (value === null) return 0
  if (typeof value === 'boolean') return value ? 1 : 0
  if (typeof value === 'number') return value
  return parseActionNumber(value)
}

function parseActionNumber (value: string): number {
  const trimmed = value.trim()
  if (trimmed === '') return 0
  if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(trimmed)) return Number(trimmed)
  return Number.NaN
}

function kindOf (value: ExprValue): string {
  if (value === null) return 'null'
  return typeof value
}

interface Token {
  type: string
  value?: string
  number?: number
}

class Parser {
  private index = 0

  constructor (private readonly tokens: Token[], private readonly state: EvalState) {}

  parseOr (): ExprValue {
    let left = this.parseAnd()
    while (this.peek()?.type === '||') {
      this.index++
      const right = this.parseAnd()
      left = isTruthy(left) ? left : right
    }
    return left
  }

  parseAnd (): ExprValue {
    let left = this.parseComparison()
    while (this.peek()?.type === '&&') {
      this.index++
      if (isFalsy(left)) {
        this.parseComparison()
        continue
      }
      left = this.parseComparison()
    }
    return left
  }

  parseComparison (): ExprValue {
    const left = this.parseUnary()
    const operator = this.peek()?.type
    if (operator !== '==' && operator !== '!=' && operator !== '>=' && operator !== '>' && operator !== '<=' && operator !== '<') {
      return left
    }
    this.index++
    const right = this.parseUnary()
    if (operator === '==') return abstractEqual(left, right)
    if (operator === '!=') return !abstractEqual(left, right)
    if (operator === '>') return abstractGreaterThan(left, right)
    if (operator === '>=') return abstractEqual(left, right) || abstractGreaterThan(left, right)
    if (operator === '<') return !abstractEqual(left, right) && !abstractGreaterThan(left, right)
    return abstractEqual(left, right) || (!abstractEqual(left, right) && !abstractGreaterThan(left, right))
  }

  parseUnary (): ExprValue {
    if (this.peek()?.type === '!') {
      this.index++
      return !isTruthy(this.parseUnary())
    }
    return this.parsePrimary()
  }

  parsePrimary (): ExprValue {
    const token = this.peek()
    if (token == null) throw new Error('unexpected end of expression')
    if (token.type === '(') {
      this.index++
      const value = this.parseOr()
      if (this.peek()?.type !== ')') throw new Error('missing )')
      this.index++
      return value
    }
    if (token.type === 'number') {
      this.index++
      return token.number ?? Number.NaN
    }
    if (token.type === 'string') {
      this.index++
      return token.value ?? ''
    }
    if (token.type === 'call') {
      this.index++
      if (this.peek()?.type !== '(') throw new Error('expected (')
      this.index++
      if (this.peek()?.type !== ')') throw new Error('expected )')
      this.index++
      if (token.value === 'always') return true
      if (token.value === 'success') return this.state.jobSuccess
      throw new Error(`unsupported function ${token.value ?? ''}`)
    }
    if (token.type === 'ident') {
      this.index++
      return resolveIdent(token.value ?? '', this.state)
    }
    throw new Error(`unexpected token ${token.type}`)
  }

  end (): void {
    if (this.peek() != null) throw new Error(`unexpected token ${this.peek()?.type ?? ''}`)
  }

  private peek (): Token | undefined {
    return this.tokens[this.index]
  }
}

function resolveIdent (path: string, state: EvalState): ExprValue {
  if (path === 'true') return true
  if (path === 'false') return false
  if (path === 'null') return null
  const parts = path.split('.')
  if (parts[0] === 'secrets') {
    return state.secrets[parts[1] ?? ''] ?? ''
  }
  if (parts[0] === 'steps' && parts[2] === 'outputs') {
    const step = state.steps[parts[1] ?? '']
    const output = step?.outputs[parts[3] ?? '']
    if (step == null || step.skipped || output === undefined) return null
    return output
  }
  throw new Error(`unsupported expression ident ${path}`)
}

function tokenize (expression: string): Token[] {
  const tokens: Token[] = []
  let index = 0
  while (index < expression.length) {
    const char = expression[index]
    if (char === ' ' || char === '\n' || char === '\t') {
      index++
      continue
    }
    const two = expression.slice(index, index + 2)
    if (two === '&&' || two === '||' || two === '>=' || two === '<=' || two === '==' || two === '!=') {
      tokens.push({ type: two })
      index += 2
      continue
    }
    if (char === '>' || char === '<' || char === '(' || char === ')' || char === '!') {
      tokens.push({ type: char })
      index++
      continue
    }
    if (char === "'") {
      let value = ''
      index++
      while (index < expression.length) {
        if (expression[index] === "'" && expression[index + 1] === "'") {
          value += "'"
          index += 2
          continue
        }
        if (expression[index] === "'") break
        value += expression[index]
        index++
      }
      index++
      tokens.push({ type: 'string', value })
      continue
    }
    if ((char >= '0' && char <= '9') || (char === '-' && expression[index + 1] >= '0' && expression[index + 1] <= '9')) {
      const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(expression.slice(index))
      if (match == null) throw new Error(`bad number at ${expression.slice(index)}`)
      tokens.push({ type: 'number', number: Number(match[0]) })
      index += match[0].length
      continue
    }
    if ((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || char === '_') {
      const start = index
      index++
      while (index < expression.length && /[A-Za-z0-9_.]/.test(expression[index])) index++
      const name = expression.slice(start, index)
      if (expression[index] === '(') tokens.push({ type: 'call', value: name })
      else tokens.push({ type: 'ident', value: name })
      continue
    }
    throw new Error(`bad expression at ${expression.slice(index)}`)
  }
  return tokens
}
