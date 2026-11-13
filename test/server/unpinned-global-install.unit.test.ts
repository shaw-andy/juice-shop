/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'

const PLACEHOLDER_ENV = 'DEVCONTAINER_CREDENTIAL_PLACEHOLDER'
const PLACEHOLDER_VALUE = 'placeholder-not-a-secret'
const WORKSPACE_PACKAGE = 'workspace-install-sentinel'
const LATEST_VERSION = '9.9.9'

interface MarkerEvent {
  package: string
  version: string
  event: string
  credentialPlaceholderVisible: boolean
}

interface GlobalInstall {
  label: string
  command: string | string[]
  env: Record<string, string>
}

void describe('unpinned global npm installs', () => {
  void it('devcontainer postCreateCommand does not run registry lifecycle scripts', { timeout: 180000 }, async () => {
    const root = repoRoot()
    const raw = JSON.parse(fs.readFileSync(path.join(root, '.devcontainer.json'), 'utf8')) as { postCreateCommand?: unknown }
    const commands = commandsFrom(raw.postCreateCommand)
    assert.ok(commands.length > 0, 'postCreateCommand is missing')
    for (const command of commands) {
      await assertGlobalInstallIsPinnedAndScriptless({
        label: '.devcontainer.json postCreateCommand',
        command,
        env: {}
      }, root)
    }
  })

  void it('workflow global installs do not run registry lifecycle scripts', { timeout: 180000 }, async () => {
    const installs = workflowGlobalInstalls(repoRoot())
    assert.ok(installs.length > 0, 'expected global npm installs in workflow files')
    const failures: string[] = []
    for (const install of installs) {
      try {
        await assertGlobalInstallIsPinnedAndScriptless(install, repoRoot())
      } catch (error) {
        failures.push(error instanceof Error ? error.message : String(error))
      }
    }
    assert.equal(failures.length, 0, failures.join('\n\n'))
  })
})

async function assertGlobalInstallIsPinnedAndScriptless (install: GlobalInstall, root: string): Promise<void> {
  const commandText = commandString(install.command)
  const expanded = expandGitHubExpressions(commandText, install.env)
  const specs = globalInstallSpecs(expanded)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'unpinned-global-'))
  const marker = path.join(tmp, 'marker.log')
  const registry = await startRegistry(tmp, specs, install.env)
  const workspace = path.join(tmp, 'workspace')
  const prefix = path.join(tmp, 'prefix')
  const cache = path.join(tmp, 'cache')
  const home = path.join(tmp, 'home')
  fs.mkdirSync(workspace, { recursive: true })
  fs.mkdirSync(prefix, { recursive: true })
  fs.mkdirSync(cache, { recursive: true })
  fs.mkdirSync(home, { recursive: true })
  fs.writeFileSync(path.join(home, '.npmrc'), '')
  const projectNpmrc = path.join(root, '.npmrc')
  if (fs.existsSync(projectNpmrc)) {
    fs.copyFileSync(projectNpmrc, path.join(workspace, '.npmrc'))
  }
  fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify({
    name: WORKSPACE_PACKAGE,
    version: '0.0.0',
    scripts: {
      preinstall: 'node ./shop-preinstall.js'
    }
  }))
  fs.writeFileSync(path.join(workspace, 'shop-preinstall.js'), `
const fs = require('fs')
fs.appendFileSync(process.env.UNPINNED_INSTALL_MARKER, JSON.stringify({
  package: ${JSON.stringify(WORKSPACE_PACKAGE)},
  version: '0.0.0',
  event: 'preinstall',
  credentialPlaceholderVisible: Object.prototype.hasOwnProperty.call(process.env, ${JSON.stringify(PLACEHOLDER_ENV)})
}) + '\\n')
`)
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: home,
    TMPDIR: tmp,
    npm_config_registry: registry.url,
    npm_config_prefix: prefix,
    npm_config_cache: cache,
    npm_config_userconfig: path.join(home, '.npmrc'),
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    npm_config_fetch_retries: '0',
    UNPINNED_INSTALL_MARKER: marker,
    [PLACEHOLDER_ENV]: PLACEHOLDER_VALUE
  }
  for (const [key, value] of Object.entries(install.env)) {
    env[key] = value
  }
  let result: { status: number | null, stderr: string, stdout: string }
  try {
    result = await runLifecycleCommand(install.command, expanded, workspace, env)
  } finally {
    await registry.close()
  }
  const events = readMarker(marker)
  const lifecycle = events.filter(event => event.package !== WORKSPACE_PACKAGE)
  const installed = specs.map(spec => {
    const version = readInstalledVersion(prefix, spec.name)
    return { name: spec.name, version, exact: version != null && isExactPin(expanded, install.env, spec.name, version) }
  })
  const detail = [
    install.label,
    `command: ${expanded}`,
    `exit: ${String(result.status)}`,
    `registry requests: ${registry.requests.join(' ') || '(none)'}`,
    `marker: ${JSON.stringify(events)}`,
    `installed: ${JSON.stringify(installed)}`,
    `stderr: ${String(result.stderr || '').slice(-2000)}`
  ].join('\n')
  for (const spec of specs) {
    const wanted = `/${registryPath(spec.name)}`
    assert.ok(
      registry.requests.some(request => request.includes(wanted) || request.includes(`/${spec.name}`)),
      `global install did not fetch ${spec.name} from the registry\n${detail}`
    )
  }
  assert.equal(result.status, 0, `global install command failed\n${detail}`)
  assert.deepEqual(lifecycle, [], `registry package lifecycle scripts ran before the following install\n${detail}`)
  for (const item of installed) {
    if (item.version == null) continue
    assert.equal(item.exact, true, `${item.name}@${item.version} was installed without an exact version pin\n${detail}`)
  }
}

async function runLifecycleCommand (command: string | string[], expanded: string, cwd: string, env: NodeJS.ProcessEnv) {
  const child = Array.isArray(command)
    ? spawn(command[0], command.slice(1), { cwd, env })
    : spawn('/bin/sh', ['-c', expanded], { cwd, env })
  return await new Promise<{ status: number | null, stderr: string, stdout: string }>((resolve, reject) => {
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => child.kill('SIGKILL'), 90000)
    child.stdout?.on('data', chunk => { stdout += String(chunk) })
    child.stderr?.on('data', chunk => { stderr += String(chunk) })
    child.on('error', error => {
      clearTimeout(timer)
      reject(error)
    })
    child.on('close', status => {
      clearTimeout(timer)
      resolve({ status, stderr, stdout })
    })
  })
}

function workflowGlobalInstalls (root: string): GlobalInstall[] {
  const dir = path.join(root, '.github', 'workflows')
  if (!fs.existsSync(dir)) return []
  const installs: GlobalInstall[] = []
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.yml') && !name.endsWith('.yaml')) continue
    const file = path.join(dir, name)
    const text = fs.readFileSync(file, 'utf8')
    const env = workflowEnv(text)
    const lines = text.split(/\r?\n/)
    let group: string[] = []
    const flush = () => {
      if (group.length === 0) return
      installs.push({
        label: `${path.relative(root, file)}: ${group[0].trim()}`,
        command: group.join('\n'),
        env
      })
      group = []
    }
    for (const line of lines) {
      const trimmed = line.trim()
      const inline = trimmed.match(/^run:\s+(npm\s+(?:install|i)\s+-g\b.*|npm\s+-g\s+(?:install|i)\b.*)$/)
      if (inline != null) {
        flush()
        group.push(inline[1])
        flush()
      } else if (/^npm(?:\s+install|\s+i)\s+-g\b/.test(trimmed) || /^npm\s+-g\s+(?:install|i)\b/.test(trimmed)) {
        group.push(trimmed)
      } else if (trimmed !== '' && !trimmed.startsWith('#')) {
        flush()
      }
    }
    flush()
  }
  return installs
}

function workflowEnv (text: string): Record<string, string> {
  const env: Record<string, string> = {}
  const re = /^\s*([A-Z][A-Z0-9_]*):\s*(?:'([^']*)'|"([^"]*)"|([^#\s]+))/gm
  for (const match of text.matchAll(re)) {
    env[match[1]] = match[2] ?? match[3] ?? match[4]
  }
  return env
}

function commandsFrom (value: unknown): Array<string | string[]> {
  if (typeof value === 'string' && value.trim() !== '') return [value]
  if (Array.isArray(value) && value.length > 0 && value.every(item => typeof item === 'string')) {
    return [value as string[]]
  }
  if (value && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).flatMap(item => commandsFrom(item))
  }
  return []
}

function commandString (command: string | string[]): string {
  return Array.isArray(command) ? command.join(' ') : command
}

function expandGitHubExpressions (command: string, env: Record<string, string>): string {
  return command.replace(/\$\{\{\s*env\.([A-Z0-9_]+)\s*\}\}/g, (_all, name: string) => env[name] ?? '')
}

interface PackageSpec {
  name: string
  requested: string | null
}

function globalInstallSpecs (command: string): PackageSpec[] {
  const specs: PackageSpec[] = []
  const re = /\bnpm\s+(?:install|i)\s+-g\s+([^\n&;]+)/g
  for (const match of command.matchAll(re)) {
    for (const token of match[1].trim().split(/\s+/)) {
      if (token === '' || token.startsWith('-')) continue
      specs.push(splitSpec(token))
    }
  }
  return specs
}

function splitSpec (spec: string): PackageSpec {
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/')
    const at = spec.indexOf('@', slash + 1)
    if (at === -1) return { name: spec, requested: null }
    return { name: spec.slice(0, at), requested: spec.slice(at + 1) }
  }
  const at = spec.indexOf('@')
  if (at === -1) return { name: spec, requested: null }
  return { name: spec.slice(0, at), requested: spec.slice(at + 1) }
}

function versionsFor (requested: string | null, env: Record<string, string>): string[] {
  const versions = new Set<string>([LATEST_VERSION])
  const sources = [requested ?? '']
  for (const match of (requested ?? '').matchAll(/\$\{([A-Z0-9_]+)\}|\$([A-Z0-9_]+)/g)) {
    sources.push(env[match[1] || match[2]] ?? '')
  }
  for (const source of sources) {
    for (const match of source.matchAll(/(\d+\.\d+\.\d+)/g)) {
      versions.add(match[1])
    }
  }
  return [...versions]
}

function isExactPin (command: string, env: Record<string, string>, name: string, version: string): boolean {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const pinned = new RegExp(`${escapedName}@${escapedVersion}(?!\\d)`)
  if (pinned.test(command)) return true
  const refs = command.matchAll(/\$\{\{\s*env\.([A-Z0-9_]+)\s*\}\}|\$\{([A-Z0-9_]+)\}|\$([A-Z0-9_]+)/g)
  for (const ref of refs) {
    const value = env[ref[1] || ref[2] || ref[3]]
    if (value === version || value === `${name}@${version}`) return true
  }
  return false
}

function readInstalledVersion (prefix: string, name: string): string | null {
  const pkgJson = path.join(prefix, 'lib', 'node_modules', ...name.split('/'), 'package.json')
  if (!fs.existsSync(pkgJson)) return null
  const parsed = JSON.parse(fs.readFileSync(pkgJson, 'utf8')) as { version?: string }
  return parsed.version ?? null
}

function readMarker (marker: string): MarkerEvent[] {
  if (!fs.existsSync(marker)) return []
  return fs.readFileSync(marker, 'utf8')
    .split('\n')
    .filter(line => line.trim() !== '')
    .map(line => JSON.parse(line) as MarkerEvent)
}

function repoRoot (): string {
  let dir = process.cwd()
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, '.devcontainer.json'))) return dir
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return process.cwd()
}

async function startRegistry (tmp: string, specs: PackageSpec[], env: Record<string, string>) {
  const packages = new Map<string, Map<string, string>>()
  for (const spec of specs) {
    let versions = packages.get(spec.name)
    if (versions == null) {
      versions = new Map()
      packages.set(spec.name, versions)
    }
    for (const version of versionsFor(spec.requested, env)) {
      if (!versions.has(version)) {
        versions.set(version, packTarball(tmp, spec.name, version))
      }
    }
  }
  const tarballs = new Map<string, string>()
  const requests: string[] = []
  const server = http.createServer((req, res) => {
    const pathname = (req.url || '/').split('?')[0]
    requests.push(`${req.method || 'GET'} ${pathname}`)
    const tarball = tarballs.get(pathname)
    if (tarball != null) {
      const body = fs.readFileSync(tarball)
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': body.length })
      res.end(body)
      return
    }
    let packumentName: string | null = null
    for (const name of packages.keys()) {
      if (pathname === `/${registryPath(name)}` || pathname === `/${name}`) {
        packumentName = name
        break
      }
    }
    if (packumentName == null) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'not found' }))
      return
    }
    const versions = packages.get(packumentName) as Map<string, string>
    const versionManifests: Record<string, unknown> = {}
    for (const [version, file] of versions) {
      const body = fs.readFileSync(file)
      const route = `/tarballs/${registryPath(packumentName)}/${version}.tgz`
      tarballs.set(route, file)
      versionManifests[version] = manifestFor(packumentName, version, body, route)
    }
    const host = req.headers.host || '127.0.0.1'
    const packument = {
      name: packumentName,
      'dist-tags': { latest: LATEST_VERSION },
      versions: Object.fromEntries(Object.entries(versionManifests).map(([version, manifest]) => {
        const copy = manifest as { dist: { tarball: string } }
        copy.dist.tarball = `http://${host}${copy.dist.tarball}`
        return [version, copy]
      }))
    }
    const payload = Buffer.from(JSON.stringify(packument))
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': payload.length })
    res.end(payload)
  })
  await new Promise<void>(resolve => {
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address()
  if (address == null || typeof address === 'string') {
    throw new Error('registry failed to bind')
  }
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close: async () => await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

function manifestFor (name: string, version: string, tarball: Buffer, route: string) {
  return {
    name,
    version,
    dist: {
      tarball: route,
      shasum: createHash('sha1').update(tarball).digest('hex'),
      integrity: 'sha512-' + createHash('sha512').update(tarball).digest('base64')
    },
    scripts: {
      preinstall: 'node ./record.js',
      install: 'node ./record.js',
      postinstall: 'node ./record.js'
    }
  }
}

function packTarball (tmp: string, name: string, version: string): string {
  const id = `${name.replace(/[^a-z0-9]+/gi, '_')}-${version}`
  const folder = path.join(tmp, 'packs', id, 'package')
  fs.mkdirSync(folder, { recursive: true })
  fs.writeFileSync(path.join(folder, 'package.json'), JSON.stringify({
    name,
    version,
    scripts: {
      preinstall: 'node ./record.js',
      install: 'node ./record.js',
      postinstall: 'node ./record.js'
    }
  }))
  fs.writeFileSync(path.join(folder, 'record.js'), `
const fs = require('fs')
const marker = process.env.UNPINNED_INSTALL_MARKER
if (marker) {
  fs.appendFileSync(marker, JSON.stringify({
    package: process.env.npm_package_name || '',
    version: process.env.npm_package_version || '',
    event: process.env.npm_lifecycle_event || '',
    credentialPlaceholderVisible: Object.prototype.hasOwnProperty.call(process.env, ${JSON.stringify(PLACEHOLDER_ENV)})
  }) + '\\n')
}
`)
  const tarball = path.join(tmp, 'packs', `${id}.tgz`)
  const packed = spawnSync('tar', ['-czf', tarball, '-C', path.dirname(folder), 'package'], { encoding: 'utf8' })
  if (packed.status !== 0) {
    throw new Error(`tar failed: ${packed.stderr}`)
  }
  return tarball
}

function registryPath (name: string): string {
  return name.replace('/', '%2f')
}
