/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * Fails while the CI install that precedes a step with ALCHEMY_API_KEY
 * can still execute a newly published release of a ranged dependency.
 */

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const workflowPath = path.join(repoRoot, '.github/workflows/ci.yml')
const PLACEHOLDER = 'placeholder-alchemy-api-key'
const SECRET_EXPRESSION = '${{ secrets.ALCHEMY_API_KEY }}'

test('CI install does not let a newly published ranged dependency read ALCHEMY_API_KEY', { timeout: 300000 }, async () => {
  const workflow = fs.readFileSync(workflowPath, 'utf8')
  const jobs = parseWorkflow(workflow)
  const targets = jobs.filter(job => job.executions.length > 0)
  const sourceStillHasThePath = workflow.includes(SECRET_EXPRESSION) &&
    /(^|\n)[^\n#]*\bnpm install\b(?![^\n]*--ignore-scripts)/.test(workflow)
  assert.ok(
    targets.length > 0 || !sourceStillHasThePath,
    'workflow still installs without --ignore-scripts and references ALCHEMY_API_KEY, but no job was parsed'
  )
  if (targets.length === 0) return

  const registry = await startRegistry(collectPackages())
  try {
    const failures = []
    for (const job of targets) {
      const observed = await reproduceJob(job, registry.origin)
      if (observed.leak.includes(PLACEHOLDER)) {
        failures.push(`${job.name} exposed ALCHEMY_API_KEY to installed code:\n${observed.leak}`)
      }
    }
    assert.deepEqual(failures, [])
  } finally {
    await registry.close()
  }
})

function parseWorkflow (text) {
  const jobs = []
  let job = null
  let step = null
  let map = null
  let scalar = null
  const finishScalar = () => {
    if (!scalar) return
    const value = scalar.style === '>'
      ? scalar.lines.join(' ').trim()
      : scalar.lines.join('\n').trim()
    scalar.owner[scalar.key] = value
    scalar = null
  }

  for (const rawLine of text.split('\n')) {
    const indent = rawLine.match(/^ */)?.[0].length ?? 0
    const line = rawLine.trim()
    if (scalar && (line === '' || indent > scalar.indent)) {
      scalar.lines.push(line)
      continue
    }
    finishScalar()
    if (line === '' || line.startsWith('#')) continue

    if (indent === 2 && line.endsWith(':') && !line.startsWith('-')) {
      job = { name: unquote(line.slice(0, -1)), jobEnv: {}, steps: [] }
      jobs.push(job)
      step = null
      map = null
      continue
    }
    if (!job) continue

    if (map && indent === map.indent + 2) {
      const field = splitKey(line)
      if (!field) continue
      if (field.value === '|' || field.value === '>') {
        scalar = { owner: map.owner, key: field.key, indent, style: field.value, lines: [] }
        continue
      }
      map.owner[field.key] = unquote(field.value)
      continue
    }
    if (map && indent <= map.indent) map = null

    if (indent === 4 && line === 'env:') {
      map = { owner: job.jobEnv, indent }
      continue
    }
    if (indent === 4 && line === 'steps:') {
      map = null
      continue
    }
    if ((indent === 4 || indent === 6) && line.startsWith('- ')) {
      step = { run: '', uses: '', env: {}, with: {} }
      job.steps.push(step)
      map = null
      const field = splitKey(line.slice(2))
      if (field) step[field.key] = unquote(field.value)
      continue
    }
    if (!step || indent !== 8) continue
    const field = splitKey(line)
    if (!field) continue
    if ((field.key === 'env' || field.key === 'with') && field.value === '') {
      map = { owner: field.key === 'env' ? step.env : step.with, indent }
      continue
    }
    if (field.value === '|' || field.value === '>') {
      scalar = { owner: step, key: field.key, indent, style: field.value, lines: [] }
      map = null
      continue
    }
    step[field.key] = unquote(field.value)
  }
  finishScalar()

  return jobs.map(job => ({
    name: job.name,
    jobEnv: job.jobEnv,
    executions: executionsFor(job)
  })).filter(job => job.executions.some(step => step.secret))
}

function splitKey (line) {
  const index = line.indexOf(':')
  if (index === -1) return null
  return { key: line.slice(0, index).trim(), value: line.slice(index + 1).trim() }
}

function unquote (value) {
  if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
    return value.slice(1, -1)
  }
  return value
}

function executionsFor (job) {
  const steps = []
  for (const step of job.steps) {
    const script = step.run || ''
    const command = step.with.command || ''
    const start = step.with.start || ''
    const secret = Object.entries(step.env).some(([key, value]) => key === 'ALCHEMY_API_KEY' || value.includes('secrets.ALCHEMY_API_KEY'))
    if (script) steps.push({ kind: 'run', script, secret, env: step.env })
    if (command) steps.push({ kind: 'command', script: command, secret, env: step.env })
    if (start) steps.push({ kind: 'start', script: start, secret, env: step.env })
  }
  const installAt = steps.findIndex(step => /\bnpm (install|ci)\b/.test(step.script))
  if (installAt === -1) return []
  const laterSecret = steps.slice(installAt + 1).some(step => step.secret)
  if (!laterSecret) return []
  return steps.slice(installAt)
}

function collectPackages () {
  const root = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'))
  const frontend = JSON.parse(fs.readFileSync(path.join(repoRoot, 'frontend/package.json'), 'utf8'))
  const versions = new Map()
  const add = (name, range) => {
    if (typeof range !== 'string') return
    for (const part of range.split('||')) {
      const version = higherMatching(part.trim())
      if (!version) continue
      if (!versions.has(name)) versions.set(name, new Set())
      versions.get(name).add(version)
    }
  }
  for (const manifest of [root, frontend]) {
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [name, range] of Object.entries(manifest[field] || {})) add(name, range)
    }
  }
  add('@angular/cli', '99.0.0')
  versions.get('@angular/cli')?.add('99.0.0')
  return { versions, scripts: root.scripts, allowScripts: root.allowScripts || {} }
}

function higherMatching (spec) {
  if (spec === '99.0.0') return spec
  const match = spec.match(/^([~^])(\d+)\.(\d+)\.(\d+)/)
  if (!match) return null
  const [, operator, majorText, minorText] = match
  const major = Number(majorText)
  const minor = Number(minorText)
  // ^0.0.x and ~0.0.x admit only that patch, so a later release cannot match.
  if (major === 0 && minor === 0) return null
  if (operator === '~' || major === 0) return `${major}.${minor}.999`
  return `${major}.999.0`
}

async function startRegistry (catalog) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'alchemy-registry-'))
  const tarballs = new Map()
  for (const [name, versionSet] of catalog.versions) {
    for (const version of versionSet) {
      const filename = `${name.split('/').pop()}-${version}.tgz`
      const file = path.join(directory, `${sanitize(name)}-${version}.tgz`)
      pack(name, version, file)
      const bytes = fs.readFileSync(file)
      tarballs.set(`${name}@${version}`, {
        filename,
        bytes,
        integrity: 'sha512-' + createHash('sha512').update(bytes).digest('base64'),
        shasum: createHash('sha1').update(bytes).digest('hex')
      })
    }
  }

  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1')
    const name = packageName(url.pathname)
    const versions = name && catalog.versions.get(name)
    if (!versions) {
      response.writeHead(404)
      response.end('{}')
      return
    }
    if (url.pathname.includes('/-/')) {
      const filename = path.basename(url.pathname)
      const version = filename.replace(/\.tgz$/, '').split('-').pop()
      const packed = tarballs.get(`${name}@${version}`)
      if (!packed) {
        response.writeHead(404)
        response.end('missing tarball')
        return
      }
      response.writeHead(200, { 'content-type': 'application/octet-stream' })
      response.end(packed.bytes)
      return
    }
    const listed = [...versions].sort(compareVersions)
    const body = {
      name,
      'dist-tags': { latest: listed[listed.length - 1] },
      versions: {}
    }
    for (const version of listed) {
      const packed = tarballs.get(`${name}@${version}`)
      body.versions[version] = {
        name,
        version,
        hasInstallScript: true,
        scripts: { postinstall: 'node postinstall.js' },
        ...(name === 'nyc' ? { bin: { nyc: 'bin/nyc.js' } } : {}),
        dist: {
          tarball: `http://127.0.0.1:${server.address().port}${tarballPath(name, packed.filename)}`,
          integrity: packed.integrity,
          shasum: packed.shasum
        }
      }
    }
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify(body))
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise(resolve => server.close(() => {
      fs.rmSync(directory, { recursive: true, force: true })
      resolve()
    })),
    scripts: catalog.scripts,
    allowScripts: catalog.allowScripts,
    versions: catalog.versions
  }
}

function packageName (urlPath) {
  const parts = urlPath.split('/').filter(Boolean).map(part => decodeURIComponent(part))
  if (parts.length === 0 || parts[0] === '-') return null
  if (parts[0].startsWith('@') && parts[0].includes('/')) return parts[0]
  if (parts[0].startsWith('@')) {
    if (!parts[1] || parts[1] === '-') return null
    return `${parts[0]}/${parts[1]}`
  }
  return parts[0]
}

function tarballPath (name, filename) {
  if (name.startsWith('@')) {
    const [scope, pkg] = name.split('/')
    return `/${scope}/${pkg}/-/${filename}`
  }
  return `/${name}/-/${filename}`
}

function sanitize (name) {
  return name.replace(/[^a-zA-Z0-9._-]+/g, '_')
}

function compareVersions (left, right) {
  const a = left.split('.').map(Number)
  const b = right.split('.').map(Number)
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0)
  }
  return 0
}

function pack (name, version, destination) {
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'alchemy-pack-'))
  const folder = path.join(staging, 'package')
  fs.mkdirSync(path.join(folder, 'bin'), { recursive: true })
  const manifest = {
    name,
    version,
    main: 'index.js',
    scripts: { postinstall: 'node postinstall.js' }
  }
  if (name === 'nyc') manifest.bin = { nyc: 'bin/nyc.js' }
  if (name === 'tsx') {
    manifest.type = 'module'
    manifest.exports = './index.js'
  }
  fs.writeFileSync(path.join(folder, 'package.json'), JSON.stringify(manifest))
  fs.writeFileSync(path.join(folder, 'index.js'), payloadMain(name))
  fs.writeFileSync(path.join(folder, 'postinstall.js'), payloadInstall())
  if (name === 'nyc') fs.writeFileSync(path.join(folder, 'bin/nyc.js'), payloadNyc())
  const result = spawnSync('tar', ['-czf', destination, '-C', staging, 'package'], { encoding: 'utf8' })
  fs.rmSync(staging, { recursive: true, force: true })
  if (result.status !== 0) throw new Error(result.stderr || 'tar failed')
}

function payloadInstall () {
  const prelude = [
    "import { appendFileSync as plantedAppend } from 'node:fs'",
    "plantedAppend(process.env.LEAK_LOG, 'planted:' + (process.env.ALCHEMY_API_KEY || '') + '\\n')"
  ].join('\n') + '\n'
  return `
const fs = require('node:fs')
const path = require('node:path')
if (process.env.LEAK_LOG) {
  fs.appendFileSync(process.env.LEAK_LOG, 'install:' + (process.env.ALCHEMY_API_KEY || '') + '\\n')
}
const marker = 'plantedAppend'
const prelude = ${JSON.stringify(prelude)}
function plant (file) {
  if (!file || !fs.existsSync(file)) return
  const source = fs.readFileSync(file, 'utf8')
  if (source.includes(marker)) return
  fs.writeFileSync(file, prelude + source)
}
const roots = []
if (process.env.INIT_CWD) roots.push(process.env.INIT_CWD)
let dir = __dirname
for (let i = 0; i < 8; i++) {
  roots.push(dir)
  const parent = path.dirname(dir)
  if (parent === dir) break
  dir = parent
}
for (const root of roots) plant(path.join(root, 'test/api/helpers/test-env.mjs'))
`
}

function payloadMain (name) {
  if (name === 'tsx') {
    return `
import fs from 'node:fs'
if (process.env.LEAK_LOG) {
  fs.appendFileSync(process.env.LEAK_LOG, 'main:tsx:' + (process.env.ALCHEMY_API_KEY || '') + '\\n')
}
`
  }
  return `
const fs = require('node:fs')
if (process.env.LEAK_LOG) {
  fs.appendFileSync(process.env.LEAK_LOG, 'main:${name}:' + (process.env.ALCHEMY_API_KEY || '') + '\\n')
}
module.exports = { validRange () { return null }, valid () { return null } }
`
}

function payloadNyc () {
  return `
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
if (process.env.LEAK_LOG) {
  fs.appendFileSync(process.env.LEAK_LOG, 'bin:nyc:' + (process.env.ALCHEMY_API_KEY || '') + '\\n')
}
const index = process.argv.indexOf('npm')
if (index === -1) process.exit(0)
const child = spawnSync(process.argv[index], process.argv.slice(index + 1), { stdio: 'inherit', env: process.env })
process.exit(child.status == null ? 1 : child.status)
`
}

async function reproduceJob (job, registry) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), `alchemy-${job.name}-`))
  const leakLog = path.join(sandbox, 'leak.log')
  fs.writeFileSync(leakLog, '')
  fs.mkdirSync(path.join(sandbox, 'test/api/helpers'), { recursive: true })
  fs.writeFileSync(path.join(sandbox, 'test/api/helpers/test-env.mjs'), "process.env.NODE_ENV = 'test'\n")
  fs.copyFileSync(path.join(repoRoot, '.npmrc'), path.join(sandbox, '.npmrc'))
  const rootManifest = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'))
  const frontendManifest = JSON.parse(fs.readFileSync(path.join(repoRoot, 'frontend/package.json'), 'utf8'))
  const floating = (manifest) => {
    const deps = {}
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [name, range] of Object.entries(manifest[field] || {})) {
        if (typeof range === 'string' && higherMatching(range.split('||')[0].trim())) deps[name] = range
      }
    }
    return deps
  }
  const rootDeps = floating(rootManifest)
  fs.writeFileSync(path.join(sandbox, 'package.json'), JSON.stringify({
    name: 'ci-sandbox',
    version: '0.0.0',
    private: true,
    allowScripts: rootManifest.allowScripts || {},
    scripts: {
      postinstall: rootManifest.scripts.postinstall,
      'build:frontend': rootManifest.scripts['build:frontend'],
      'build:server': rootManifest.scripts['build:server'],
      start: rootManifest.scripts.start,
      'test:api': rootManifest.scripts['test:api'],
      'test:api:coverage': rootManifest.scripts['test:api:coverage']
    },
    dependencies: rootDeps
  }))
  fs.mkdirSync(path.join(sandbox, 'frontend'), { recursive: true })
  fs.writeFileSync(path.join(sandbox, 'frontend/package.json'), JSON.stringify({
    name: 'frontend',
    version: '0.0.0',
    private: true,
    scripts: { build: 'node -e "process.exit(0)"' },
    dependencies: floating(frontendManifest)
  }))
  fs.copyFileSync(path.join(repoRoot, 'frontend/.npmrc'), path.join(sandbox, 'frontend/.npmrc'))
  const names = Object.keys(rootDeps)
  fs.mkdirSync(path.join(sandbox, 'build'), { recursive: true })
  fs.writeFileSync(path.join(sandbox, 'build/app.js'), `
const names = ${JSON.stringify(names)}
for (const name of names) {
  try { require(name) } catch (error) {}
}
`)
  fs.writeFileSync(path.join(sandbox, 'test/api/dependency-load.test.ts'), names.map(name => `import ${JSON.stringify(name)}`).join('\n') + '\n')

  const home = path.join(sandbox, 'home')
  const prefix = path.join(sandbox, 'npm-global')
  fs.mkdirSync(home, { recursive: true })
  fs.mkdirSync(prefix, { recursive: true })
  let output = ''
  try {
    for (const step of job.executions) {
      const env = stepEnvironment({ home, prefix, registry, leakLog, jobEnv: job.jobEnv, stepEnv: step.env, secret: step.secret })
      const result = await runScript(step.script, sandbox, env)
      output += `\n$ ${step.script}\nexit ${result.code}\n${tail(result.out)}`
      const install = /\bnpm (install|ci)\b/.test(step.script)
      if (install && result.code !== 0) {
        if (installFailedClosed(result.out)) {
          return { leak: fs.readFileSync(leakLog, 'utf8'), log: output }
        }
        throw new Error(`install step failed before the secret step\n${output}`)
      }
    }
    return { leak: fs.readFileSync(leakLog, 'utf8'), log: output }
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true })
  }
}

function stepEnvironment ({ home, prefix, registry, leakLog, jobEnv, stepEnv, secret }) {
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    TMPDIR: os.tmpdir(),
    LANG: 'C.UTF-8',
    npm_config_registry: registry,
    npm_config_prefix: prefix,
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    LEAK_LOG: leakLog
  }
  for (const [key, value] of Object.entries(jobEnv)) {
    if (value.includes('${{')) continue
    env[key] = value
  }
  if (secret) {
    for (const [key, value] of Object.entries(stepEnv)) {
      env[key] = value.includes(SECRET_EXPRESSION) || key === 'ALCHEMY_API_KEY' ? PLACEHOLDER : value
    }
  }
  return env
}

function installFailedClosed (output) {
  return output.includes('package-lock.json') ||
    output.includes('npm-shrinkwrap.json') ||
    output.includes('ESTRICTALLOWSCRIPTS') ||
    output.includes('not covered by allowScripts')
}

function runScript (script, cwd, env) {
  const file = path.join(cwd, `.step-${process.hrtime.bigint()}.sh`)
  fs.writeFileSync(file, script + '\n')
  return new Promise(resolve => {
    const child = spawn('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', file], { cwd, env })
    let out = ''
    const keep = (chunk) => {
      out += chunk.toString()
      if (out.length > 80000) out = out.slice(-80000)
    }
    child.stdout.on('data', keep)
    child.stderr.on('data', keep)
    child.on('close', code => resolve({ code: code ?? 1, out }))
  })
}

function tail (text) {
  const lines = text.trim().split('\n')
  return lines.slice(-40).join('\n')
}
