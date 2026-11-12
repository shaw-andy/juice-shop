/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * These tests fail while the lint-fix workflow can install a package from a
 * version range and push files that package writes. They pass once that
 * stops happening.
 */

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const workflowPath = join(repoRoot, '.github', 'workflows', 'lint-fixer.yml')

const cases = [
  {
    name: 'neostandard',
    manifest: 'package.json',
    entry: 'library'
  },
  {
    name: 'globals',
    manifest: 'package.json',
    entry: 'library'
  },
  {
    name: 'eslint',
    manifest: 'package.json',
    entry: 'bin'
  },
  {
    name: 'angular-eslint',
    manifest: join('frontend', 'package.json'),
    entry: 'library'
  }
]

test('lint-fixer does not run or push an in-range package release', { timeout: 45 * 60 * 1000 }, async () => {
  const workflow = readFileSync(workflowPath, 'utf8')
  assert.match(workflow, /^on:\s*\[push\]/m)
  const failures = []
  for (const item of cases) {
    try {
      await runCase(workflow, item)
    } catch (error) {
      failures.push(`${item.name}: ${error.message}`)
    }
  }
  assert.deepEqual(failures, [])
})

async function runCase (workflow, item) {
  const root = join(tmpdir(), `lint-fixer-${item.name}-${process.pid}`)
  rmSync(root, { recursive: true, force: true })
  mkdirSync(root)
  const cache = join(tmpdir(), `lint-fixer-npm-cache-${process.pid}`)
  mkdirSync(cache, { recursive: true })
  try {
    const spec = dependencySpec(join(repoRoot, item.manifest), item.name)
    const version = inRangeVersion(spec)
    const tarball = await pack(root, item, version)
    const registry = await startRegistry(item.name, version, tarball)
    try {
      console.log(`case ${item.name}: registry ${registry.url} version ${version} spec ${spec}`)
      const work = join(root, 'work')
      const bare = join(root, 'remote.git')
      await run('git', ['clone', '--local', repoRoot, work])
      await run('git', ['checkout', '-B', 'feature-under-test'], work)
      await run('git', ['init', '--bare', bare])
      await run('git', ['remote', 'set-url', 'origin', bare], work)
      await run('git', ['push', '-u', 'origin', 'feature-under-test'], work)

      const importMarker = join(work, 'attacker-import-wrote.txt')
      const lifecycleMarker = join(work, 'attacker-lifecycle-wrote.txt')
      const env = {
        ...process.env,
        npm_config_registry: registry.url,
        npm_config_cache: cache,
        ATTACK_IMPORT_MARKER: importMarker,
        ATTACK_LIFECYCLE_MARKER: lifecycleMarker
      }
      const scripts = extractRunScripts(workflow)
      assert.ok(scripts.length >= 2, 'workflow no longer has the install and lint run steps')
      let lintCode = 0
      const logs = []
      for (const script of scripts) {
        const scriptPath = join(root, `step-${logs.length}.sh`)
        writeFileSync(scriptPath, script)
        const result = await run('bash', ['-e', scriptPath], work, env, true, true)
        logs.push(result)
        if (result.code !== 0) {
          lintCode = result.code
          break
        }
      }
      const installed = installedVersion(work, item)
      if (!existsSync(importMarker) && !existsSync(lifecycleMarker) && installed === version && item.manifest.startsWith('frontend')) {
        const follow = await run('bash', ['-e', '-c', 'cd frontend && npm run lint:fix'], work, env, true, true)
        logs.push(follow)
      }
      let pushed = false
      if (lintCode === 0 && workflow.includes('stefanzweifel/git-auto-commit-action@')) {
        pushed = await autoCommit(workflow, work, root, bare)
      }
      const problems = []
      if (existsSync(importMarker) || existsSync(lifecycleMarker)) {
        problems.push(`package code wrote a file during the workflow (import=${existsSync(importMarker)} lifecycle=${existsSync(lifecycleMarker)} pushed=${pushed})`)
      }
      if (pushed) problems.push('git-auto-commit pushed that file onto the branch')
      if (stillFloats(workflow, work) && installed !== version) {
        const tail = logs.map(entry => entry.output.trim().split('\n').slice(-40).join('\n')).join('\n---\n')
        problems.push(`in-range ${item.name}@${version} was not installed (got ${installed || 'nothing'}). log tail:\n${tail}`)
      }
      if (stillFloats(workflow, work) && installed === version && !existsSync(importMarker) && !existsSync(lifecycleMarker)) {
        const tail = logs.map(entry => entry.output.trim().split('\n').slice(-40).join('\n')).join('\n---\n')
        problems.push(`harness installed ${item.name}@${version} but its code did not run. log tail:\n${tail}`)
      }
      assert.deepEqual(problems, [], problems.join('\n'))
    } finally {
      await registry.close()
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

function dependencySpec (manifestPath, name) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const spec = manifest.dependencies?.[name] || manifest.devDependencies?.[name]
  assert.equal(typeof spec, 'string', `${name} is not a dependency of ${manifestPath}`)
  return spec
}

function inRangeVersion (spec) {
  const match = spec.match(/^\^(\d+)\.(\d+)\.(\d+)$/)
  assert.ok(match, `cannot choose an in-range release for ${spec}`)
  const major = Number(match[1])
  const minor = Number(match[2])
  if (major === 0) return `0.${minor}.999`
  return `${major}.999.0`
}

function stillFloats (workflow, work) {
  const install = extractRunScripts(workflow)[0] || ''
  const usesCi = /\bnpm ci\b/.test(install)
  const lock = existsSync(join(work, 'package-lock.json')) || existsSync(join(work, 'npm-shrinkwrap.json'))
  const npmrc = existsSync(join(work, '.npmrc')) ? readFileSync(join(work, '.npmrc'), 'utf8') : ''
  const ignoresLock = /^package-lock\s*=\s*false\s*$/m.test(npmrc)
  return !usesCi && (!lock || ignoresLock)
}

function installedVersion (work, item) {
  const candidates = [
    join(work, 'node_modules', item.name, 'package.json'),
    join(work, 'frontend', 'node_modules', item.name, 'package.json')
  ]
  for (const path of candidates) {
    if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8')).version
  }
  return null
}

async function pack (root, item, version) {
  const dir = join(root, 'pack', 'package')
  mkdirSync(dir, { recursive: true })
  const manifest = {
    name: item.name,
    version,
    main: 'index.js'
  }
  if (item.entry === 'bin') {
    manifest.bin = { eslint: 'index.js' }
  }
  manifest.scripts = {
    preinstall: 'node -e "require(\'fs\').writeFileSync(process.env.ATTACK_LIFECYCLE_MARKER,\'lifecycle\\n\')"'
  }
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest))
  writeFileSync(join(dir, 'index.js'), librarySource())
  chmodSync(join(dir, 'index.js'), 0o755)
  const tarballPath = join(root, `${item.name}.tgz`)
  await run('tar', ['-czf', tarballPath, '-C', join(root, 'pack'), 'package'])
  return readFileSync(tarballPath)
}

function librarySource () {
  return `'use strict'
const fs = require('fs')
const path = require('path')
fs.writeFileSync(process.env.ATTACK_IMPORT_MARKER, 'ran\\n')
try {
  const pkgPath = path.join(process.cwd(), 'frontend', 'package.json')
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  pkg.scripts['lint:fix'] = 'node -e "process.exit(0)"'
  fs.writeFileSync(pkgPath, JSON.stringify(pkg))
} catch (err) {}
process.exit(0)
module.exports = function () { return [] }
`
}

async function startRegistry (name, version, tarball) {
  const integrity = 'sha512-' + createHash('sha512').update(tarball).digest('base64')
  const shasum = createHash('sha1').update(tarball).digest('hex')
  let port = 0
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://127.0.0.1')
      const pathname = decodeURIComponent(url.pathname)
      if (request.method === 'GET' && pathname === `/${name}/-/${name}-${version}.tgz`) {
        response.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': tarball.length
        })
        response.end(tarball)
        return
      }
      const chunks = []
      for await (const chunk of request) chunks.push(chunk)
      const requestBody = Buffer.concat(chunks)
      const headers = {
        accept: request.headers.accept || '*/*',
        'user-agent': request.headers['user-agent'] || 'lint-fixer-test'
      }
      if (request.headers['content-type']) headers['content-type'] = request.headers['content-type']
      const upstream = await fetch('https://registry.npmjs.org' + url.pathname + url.search, {
        method: request.method,
        headers,
        body: request.method === 'GET' || request.method === 'HEAD' ? undefined : requestBody
      })
      let body = Buffer.from(await upstream.arrayBuffer())
      if (request.method === 'GET' && (pathname === `/${name}` || pathname === `/${name}/`)) {
        const json = JSON.parse(body.toString('utf8'))
        const sample = json.versions[Object.keys(json.versions)[0]]
        json.versions[version] = {
          name,
          version,
          dist: {
            tarball: `http://127.0.0.1:${port}/${name}/-/${name}-${version}.tgz`,
            shasum,
            integrity
          }
        }
        if (name === 'eslint') json.versions[version].bin = { eslint: 'index.js' }
        void sample
        body = Buffer.from(JSON.stringify(json))
      }
      response.writeHead(upstream.status, {
        'content-type': upstream.headers.get('content-type') || 'application/octet-stream',
        'content-length': body.length
      })
      response.end(body)
    } catch (error) {
      response.writeHead(502, { 'content-type': 'text/plain' })
      response.end(String(error && error.stack || error))
    }
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  port = server.address().port
  return {
    url: `http://127.0.0.1:${port}/`,
    close () {
      server.closeAllConnections()
      return new Promise(resolve => server.close(resolve))
    }
  }
}

function extractRunScripts (workflow) {
  const scripts = []
  const lines = workflow.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const inline = lines[i].match(/^\s*run:\s+'(.*)'\s*$/)
    if (inline) {
      scripts.push(inline[1])
      continue
    }
    const folded = lines[i].match(/^(\s*)run:\s+\|\s*$/)
    if (!folded) continue
    const indent = folded[1].length + 2
    const body = []
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === '') {
        body.push('')
        i = j
        continue
      }
      const width = lines[j].match(/^ */)[0].length
      if (width < indent) break
      body.push(lines[j].slice(indent))
      i = j
    }
    scripts.push(body.join('\n'))
  }
  return scripts
}

async function autoCommit (workflow, work, root, bare) {
  const sha = workflow.match(/stefanzweifel\/git-auto-commit-action@([0-9a-f]{40})/)[1]
  const actionDir = join(root, 'action')
  mkdirSync(actionDir)
  for (const file of ['action.yml', 'index.js', 'entrypoint.sh']) {
    const response = await fetch(`https://raw.githubusercontent.com/stefanzweifel/git-auto-commit-action/${sha}/${file}`)
    assert.equal(response.status, 200, `action file ${file} at ${sha}`)
    writeFileSync(join(actionDir, file), Buffer.from(await response.arrayBuffer()))
  }
  chmodSync(join(actionDir, 'entrypoint.sh'), 0o755)
  const defaults = parseActionDefaults(readFileSync(join(actionDir, 'action.yml'), 'utf8'))
  const overrides = parseWorkflowInputs(workflow)
  const inputs = { ...defaults, ...overrides }
  inputs.branch = substitutePushExpressions(inputs.branch || '')
  inputs.commit_author = substitutePushExpressions(inputs.commit_author || '')
  const output = join(root, 'github-output.txt')
  writeFileSync(output, '')
  const env = { ...process.env, GITHUB_OUTPUT: output }
  for (const [key, value] of Object.entries(inputs)) {
    env[`INPUT_${key.toUpperCase()}`] = value
  }
  env.INPUT_INTERNAL_GIT_BINARY = env.INPUT_INTERNAL_GIT_BINARY || 'git'
  const result = await run('node', [join(actionDir, 'index.js')], work, env, true, true)
  assert.equal(result.code, 0, `auto-commit failed\n${result.output}`)
  const tree = await run('git', ['--git-dir', bare, 'ls-tree', '-r', '--name-only', 'refs/heads/feature-under-test'], undefined, process.env, true)
  return tree.output.split('\n').includes('attacker-import-wrote.txt') ||
    tree.output.split('\n').includes('attacker-lifecycle-wrote.txt')
}

function parseActionDefaults (yaml) {
  const defaults = {}
  let inInputs = false
  let key = null
  for (const line of yaml.split('\n')) {
    if (line === 'inputs:') {
      inInputs = true
      continue
    }
    if (inInputs && /^[a-z]/.test(line)) break
    const keyMatch = line.match(/^  ([a-z0-9_]+):\s*$/)
    if (inInputs && keyMatch) {
      key = keyMatch[1]
      continue
    }
    const valueMatch = line.match(/^    default:\s*(.*)\s*$/)
    if (inInputs && key && valueMatch) {
      defaults[key] = unquote(valueMatch[1].trim())
    }
  }
  return defaults
}

function parseWorkflowInputs (workflow) {
  const inputs = {}
  const lines = workflow.split('\n')
  const start = lines.findIndex(line => line.includes('git-auto-commit-action@'))
  let inWith = false
  for (let i = start + 1; i < lines.length; i++) {
    if (!inWith) {
      if (/^\s+with:\s*$/.test(lines[i])) {
        inWith = true
        continue
      }
      if (lines[i].trim() !== '') break
      continue
    }
    const match = lines[i].match(/^\s+([a-z0-9_]+):\s*(.*)\s*$/)
    if (!match) break
    inputs[match[1]] = unquote(match[2].trim())
  }
  return inputs
}

function unquote (value) {
  if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) {
    return value.slice(1, -1)
  }
  return value
}

function substitutePushExpressions (value) {
  return value
    .replaceAll('${{ github.head_ref }}', '')
    .replaceAll('${{ github.actor }}', 'pusher')
}

function run (command, args, cwd = undefined, env = process.env, capture = false, echo = false) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit' })
    let output = ''
    if (capture) {
      child.stdout.on('data', chunk => {
        output += chunk
        if (echo) process.stdout.write(chunk)
      })
      child.stderr.on('data', chunk => {
        output += chunk
        if (echo) process.stderr.write(chunk)
      })
    }
    child.on('error', reject)
    child.on('exit', code => resolve({ code, output }))
  })
}
