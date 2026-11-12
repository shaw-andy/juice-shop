/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const effectName = 'release-install-script-effect.txt'
const binEffectName = 'release-tool-bin-effect.txt'
const compromisedMarker = 'COMPROMISED_RELEASE_ARCHIVE'
const pinnedVersions = ['2.0.0', '2.1.0', '4.2.1', '6.0.3', '8.0.0']
const floatingVersions = ['2.99.0', '3.99.0', '4.99.0', '6.99.0', '99.0.0']
const versions = [...pinnedVersions, ...floatingVersions]

interface Packed {
  bytes: Buffer
  integrity: string
  shasum: string
}

interface Registry {
  server: Server
  origin: string
  close: () => Promise<void>
}

function workflowEnv (yaml: string): Record<string, string> {
  const top = yaml.split(/^jobs:/m)[0]
  const env: Record<string, string> = {}
  for (const match of top.matchAll(/^ {2}([A-Z0-9_]+):\s*(?:'([^']*)'|"([^"]*)"|(\S+))/gm)) {
    env[match[1]] = match[2] ?? match[3] ?? match[4]
  }
  const jobEnv = yaml.match(/^\s{4}env:\n((?:\s{6}[A-Z0-9_]+:.*\n)+)/m)
  if (jobEnv != null) {
    for (const match of jobEnv[1].matchAll(/^ {6}([A-Z0-9_]+):\s*(?:'([^']*)'|"([^"]*)"|(\S+))/gm)) {
      env[match[1]] = match[2] ?? match[3] ?? match[4]
    }
  }
  return env
}

function installScripts (yaml: string): string[] {
  const scripts: string[] = []
  const lines = yaml.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const single = lines[i].match(/run:\s*(npm install -g\b.*)$/)
    if (single != null) {
      scripts.push(single[1])
      continue
    }
    if (!/run:\s*\|/.test(lines[i])) continue
    const indent = lines[i].match(/^ */)?.[0].length ?? 0
    const body: string[] = []
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === '') {
        body.push('')
        continue
      }
      const width = lines[j].match(/^ */)?.[0].length ?? 0
      if (width <= indent) break
      body.push(lines[j].trim())
    }
    const script = body.join('\n').trim()
    if (script.includes('npm install -g')) scripts.push(script)
  }
  return scripts
}

function substituteExpressions (script: string, env: Record<string, string>): string {
  return script.replace(/\$\{\{\s*env\.([A-Z0-9_]+)\s*\}\}/g, (_all, name: string) => {
    const value = env[name]
    if (value == null) throw new Error(`workflow env ${name} is not defined`)
    return value
  })
}

function dockerfileInstalls (dockerfile: string): { script: string, env: Record<string, string> } {
  const arg = dockerfile.match(/^ARG\s+CYCLONEDX_NPM_VERSION='([^']+)'/m)
  const runs = [...dockerfile.matchAll(/^RUN\s+(npm install -g\b.*)$/gm)].map(match => match[1])
  return {
    script: runs.join('\n'),
    env: { CYCLONEDX_NPM_VERSION: arg?.[1] ?? '' }
  }
}

function bashSegment (line: string): string {
  const quote = line.indexOf("'")
  if (quote !== -1 && line.indexOf('||', quote) !== -1) return line
  return line.split('||')[0].trim()
}

function pack (files: Record<string, string>): Promise<Buffer> {
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'pack-'))
  const root = path.join(stage, 'package')
  fs.mkdirSync(root, { recursive: true })
  for (const [name, contents] of Object.entries(files)) {
    const file = path.join(root, name)
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, contents)
  }
  const tarball = path.join(stage, 'pkg.tgz')
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['-czf', tarball, '-C', stage, 'package'])
    child.on('error', reject)
    child.on('exit', (code) => {
      if (code !== 0) reject(new Error(`tar exited ${code}`))
      else resolve(fs.readFileSync(tarball))
    })
  })
}

function describeTarball (bytes: Buffer): Packed {
  return {
    bytes,
    integrity: 'sha512-' + createHash('sha512').update(bytes).digest('base64'),
    shasum: createHash('sha1').update(bytes).digest('hex')
  }
}

const preinstall = `
const fs = require('fs')
const path = require('path')
const workspace = process.env.GITHUB_WORKSPACE
if (!workspace) process.exit(0)
let line = (process.env.npm_package_name || '') + ' ' + (process.env.npm_lifecycle_event || '')
try {
  const config = fs.readFileSync(path.join(workspace, '.git', 'config'), 'utf8')
  const included = config.match(/^\\s*path\\s*=\\s*(.+\\.config)\\s*$/m)
  if (included) {
    const credential = fs.readFileSync(included[1].trim(), 'utf8')
    const encoded = credential.split('AUTHORIZATION: basic ')[1]
    if (encoded) {
      const decoded = Buffer.from(encoded.trim(), 'base64').toString('utf8')
      if (decoded.startsWith('x-access-token:')) line += ' read-checkout-credential'
    }
  }
} catch {}
fs.appendFileSync(path.join(workspace, ${JSON.stringify(effectName)}), line + '\\n')
`

const binScript = `#!/usr/bin/env node
const fs = require('fs')
const path = require('path')
const workspace = process.env.GITHUB_WORKSPACE
if (workspace) fs.writeFileSync(path.join(workspace, ${JSON.stringify(binEffectName)}), 'ran\\n')
`

const archiverModule = `
const { EventEmitter } = require('events')
class Archive extends EventEmitter {
  pipe (dest) { this.dest = dest; return dest }
  file () { return this }
  finalize () { this.dest.end(${JSON.stringify(compromisedMarker)}) }
}
module.exports = { TarArchive: Archive, ZipArchive: Archive }
`

const benignArchiver = `
const { EventEmitter } = require('events')
const fs = require('fs')
const zlib = require('zlib')
function header (name, size) {
  const buf = Buffer.alloc(512)
  buf.write(name)
  buf.write('0000644\\0', 100)
  buf.write('0001750\\0', 108)
  buf.write('0001750\\0', 116)
  buf.write(size.toString(8).padStart(11, '0') + '\\0', 124)
  buf.write('00000000000\\0', 136)
  buf.write('        ', 148)
  buf.write('0', 156)
  buf.write('ustar\\0', 257)
  buf.write('00', 263)
  let sum = 0
  for (const byte of buf) sum += byte
  buf.write(sum.toString(8).padStart(6, '0') + '\\0 ', 148)
  return buf
}
class Archive extends EventEmitter {
  constructor () { super(); this.entries = [] }
  pipe (dest) { this.dest = dest; return dest }
  file (filepath, data) { this.entries.push({ filepath, name: data.name }); return this }
  finalize () {
    const parts = []
    for (const entry of this.entries) {
      const body = fs.readFileSync(entry.filepath)
      parts.push(header(entry.name, body.length))
      parts.push(body)
      const pad = (512 - (body.length % 512)) % 512
      if (pad !== 0) parts.push(Buffer.alloc(pad))
    }
    parts.push(Buffer.alloc(1024))
    this.dest.end(zlib.gzipSync(Buffer.concat(parts)))
  }
}
module.exports = { TarArchive: Archive, ZipArchive: Archive }
`

const cleanBin = '#!/usr/bin/env node\nprocess.exit(0)\n'

async function startRegistry (): Promise<Registry> {
  const cache = new Map<string, Packed>()
  let origin = 'http://127.0.0.1:0'
  const tarballFor = async (name: string, version: string): Promise<Packed> => {
    const key = `${name}@${version}`
    const cached = cache.get(key)
    if (cached != null) return cached
    const hostile = floatingVersions.includes(version)
    const manifest: Record<string, unknown> = {
      name,
      version,
      scripts: { preinstall: 'node preinstall.js' }
    }
    if (hostile && name !== 'lifecycle-probe') manifest.dependencies = { 'lifecycle-probe': '1.0.0' }
    const files: Record<string, string> = {
      'package.json': JSON.stringify(manifest),
      'preinstall.js': preinstall,
      'index.js': name === 'archiver' && hostile ? archiverModule : (name === 'archiver' ? benignArchiver : 'module.exports = {}\n')
    }
    if (name === '@cyclonedx/cyclonedx-npm') {
      manifest.bin = { 'cyclonedx-npm': 'bin.js' }
      files['package.json'] = JSON.stringify(manifest)
      files['bin.js'] = hostile ? binScript : cleanBin
    }
    const packed = describeTarball(await pack(files))
    cache.set(key, packed)
    return packed
  }

  const server = createServer((req, res) => {
    void (async () => {
      const url = decodeURIComponent((req.url ?? '/').split('?')[0])
      const tarball = url.match(/^\/(.+)\/-\/([^/]+)-([0-9]+\.[0-9]+\.[0-9]+)\.tgz$/)
      if (tarball != null) {
        const scope = tarball[1]
        const name = scope.startsWith('@') ? scope : tarball[2]
        const packed = await tarballFor(name, tarball[3])
        res.statusCode = 200
        res.end(packed.bytes)
        return
      }
      if (req.method !== 'GET' || url === '/npm' || url.startsWith('/-/')) {
        res.statusCode = 404
        res.end('not found')
        return
      }
      const name = url.replace(/^\//, '')
      if (name === '' || name.includes('/-/')) {
        res.statusCode = 404
        res.end('not found')
        return
      }
      const offered = name === 'lifecycle-probe' ? ['1.0.0'] : versions
      const latest = name === 'lifecycle-probe' ? '1.0.0' : '99.0.0'
      const bodyVersions: Record<string, unknown> = {}
      for (const version of offered) {
        const packed = await tarballFor(name, version)
        const filename = `${name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name}-${version}.tgz`
        const distName = name.startsWith('@') ? name : name
        const hostile = floatingVersions.includes(version)
        const meta: Record<string, unknown> = {
          name,
          version,
          hasInstallScript: true,
          scripts: { preinstall: 'node preinstall.js' },
          dist: {
            shasum: packed.shasum,
            integrity: packed.integrity,
            tarball: `${origin}/${distName}/-/${filename}`
          }
        }
        if (hostile && name !== 'lifecycle-probe') meta.dependencies = { 'lifecycle-probe': '1.0.0' }
        if (name === '@cyclonedx/cyclonedx-npm') meta.bin = { 'cyclonedx-npm': 'bin.js' }
        bodyVersions[version] = meta
      }
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ name, 'dist-tags': { latest }, versions: bodyVersions }))
    })().catch((err: Error) => {
      res.statusCode = 500
      res.end(err.message)
    })
  })
  await new Promise<void>((resolve) => { server.listen(0, '127.0.0.1', resolve) })
  const address = server.address()
  if (address == null || typeof address === 'string') throw new Error('registry did not bind')
  origin = `http://127.0.0.1:${address.port}`
  return {
    server,
    origin,
    close: async () => {
      server.close()
      await once(server, 'close')
    }
  }
}

function writeCheckoutCredential (workspace: string): void {
  const runnerTemp = path.join(workspace, 'runner-temp')
  fs.mkdirSync(runnerTemp, { recursive: true })
  const credential = path.join(runnerTemp, 'git-credentials-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.config')
  const placeholder = 'PLACEHOLDER_JOB_TOKEN'
  const basic = Buffer.from(`x-access-token:${placeholder}`, 'utf8').toString('base64')
  fs.mkdirSync(path.join(workspace, '.git'), { recursive: true })
  spawnSyncOrThrow('git', ['init', '-q'], workspace)
  spawnSyncOrThrow('git', [
    'config', '--file', credential,
    'http.https://github.com/.extraheader',
    `AUTHORIZATION: basic ${basic}`
  ], workspace)
  const gitDir = path.join(workspace, '.git').replace(/\\/g, '/')
  spawnSyncOrThrow('git', [
    'config', '--local', `includeIf.gitdir:${gitDir}.path`, credential
  ], workspace)
}

function spawnSyncOrThrow (command: string, args: string[], cwd: string): void {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed: ${result.stderr}`)
  }
}

function runBash (script: string, cwd: string, env: NodeJS.ProcessEnv): Promise<{ status: number, stdout: string, stderr: string }> {
  const file = path.join(cwd, 'install-tools.sh')
  fs.writeFileSync(file, script + '\n')
  return new Promise((resolve, reject) => {
    const child = spawn('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', file], {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8') })
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8') })
    child.on('error', reject)
    child.on('exit', (status) => { resolve({ status: status ?? 1, stdout, stderr }) })
  })
}

async function runGlobalInstalls (script: string, extraEnv: Record<string, string>): Promise<{ workspace: string, prefix: string, registry: Registry }> {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'release-install-'))
  const prefix = path.join(workspace, 'prefix')
  const cache = path.join(workspace, 'cache')
  fs.mkdirSync(prefix, { recursive: true })
  fs.copyFileSync(path.join(repoRoot, '.npmrc'), path.join(workspace, '.npmrc'))
  writeCheckoutCredential(workspace)
  const registry = await startRegistry()
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ...extraEnv,
    HOME: path.join(workspace, 'home'),
    npm_config_registry: registry.origin,
    npm_config_prefix: prefix,
    npm_config_cache: cache,
    npm_config_userconfig: path.join(workspace, 'home', '.npmrc'),
    GITHUB_WORKSPACE: workspace
  }
  fs.mkdirSync(childEnv.HOME as string, { recursive: true })
  delete childEnv.GITHUB_TOKEN
  delete childEnv.NODE_AUTH_TOKEN
  const result = await runBash(script, workspace, childEnv)
  if (result.status !== 0) {
    await registry.close()
    throw new Error(`install script exited ${result.status}\n${result.stdout}\n${result.stderr}`)
  }
  return { workspace, prefix, registry }
}

function assertNoInstallEffects (workspace: string): void {
  const effect = path.join(workspace, effectName)
  const body = fs.existsSync(effect) ? fs.readFileSync(effect, 'utf8').trim() : ''
  assert.equal(body, '', `global install lifecycle scripts ran:\n${body}`)
}

async function withInstall (script: string, env: Record<string, string>, check: (workspace: string, prefix: string) => void | Promise<void>): Promise<void> {
  if (script.trim() === '') return
  const run = await runGlobalInstalls(script, env)
  try {
    await check(run.workspace, run.prefix)
  } finally {
    await run.registry.close()
    fs.rmSync(run.workspace, { recursive: true, force: true })
  }
}

describe('release global tool install', { timeout: 180000 }, () => {
  const releaseYaml = fs.readFileSync(path.join(repoRoot, '.github/workflows/release.yml'), 'utf8')
  const ciYaml = fs.readFileSync(path.join(repoRoot, '.github/workflows/ci.yml'), 'utf8')
  const dockerfile = fs.readFileSync(path.join(repoRoot, 'Dockerfile'), 'utf8')
  const releaseEnv = workflowEnv(releaseYaml)
  const ciEnv = workflowEnv(ciYaml)
  const releaseScripts = installScripts(releaseYaml).map(script => substituteExpressions(script, releaseEnv))
  const ciScripts = installScripts(ciYaml).map(script => substituteExpressions(script, ciEnv))
  let globLinks: string[] = []

  before(async () => {
    const globDir = path.join(repoRoot, 'node_modules', 'glob')
    if (fs.existsSync(globDir)) return
    const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-'))
    const install = spawn('npm', ['install', '--prefix', prefix, 'glob@10.4.5', '--ignore-scripts', '--no-audit', '--no-fund'], {
      stdio: 'inherit'
    })
    const code = await new Promise<number>((resolve, reject) => {
      install.on('error', reject)
      install.on('exit', (status) => { resolve(status ?? 1) })
    })
    if (code !== 0) throw new Error('failed to install glob for package.mjs')
    fs.mkdirSync(path.join(repoRoot, 'node_modules'), { recursive: true })
    for (const entry of fs.readdirSync(path.join(prefix, 'node_modules'))) {
      const dest = path.join(repoRoot, 'node_modules', entry)
      if (fs.existsSync(dest)) continue
      fs.symlinkSync(path.join(prefix, 'node_modules', entry), dest)
      globLinks.push(dest)
    }
  })

  after(() => {
    for (const link of globLinks) fs.rmSync(link, { recursive: true, force: true })
    globLinks = []
  })

  void it('does not run lifecycle scripts for the release workflow global installs', async () => {
    const script = releaseScripts.find(item => item.includes('archiver')) ?? ''
    await withInstall(script, releaseEnv, (workspace) => {
      assertNoInstallEffects(workspace)
    })
  })

  void it('does not run lifecycle scripts for the smoke-test global installs', async () => {
    const script = ciScripts.find(item => item.includes('archiver')) ?? ''
    await withInstall(script, ciEnv, (workspace) => {
      assertNoInstallEffects(workspace)
    })
  })

  void it('does not run lifecycle scripts for the unpinned Angular CLI install', async () => {
    const script = ciScripts.find(item => item.includes('@angular/cli')) ?? ''
    await withInstall(bashSegment(script), ciEnv, (workspace) => {
      assertNoInstallEffects(workspace)
    })
  })

  void it('does not run lifecycle scripts for the image build global installs', async () => {
    const docker = dockerfileInstalls(dockerfile)
    await withInstall(docker.script, docker.env, (workspace) => {
      assertNoInstallEffects(workspace)
    })
  })

  void it('does not execute a registry-supplied cyclonedx bin while generating the SBOM', async () => {
    const script = releaseScripts.find(item => item.includes('cyclonedx')) ?? ''
    const sbom = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).scripts.sbom as string
    await withInstall(script, releaseEnv, async (workspace, prefix) => {
      const pkg = { name: 'juice-shop', version: '0.0.0', scripts: { sbom } }
      fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify(pkg))
      const result = await runBash('npm run --silent sbom', workspace, {
        ...process.env,
        HOME: path.join(workspace, 'home'),
        PATH: `${path.join(prefix, 'bin')}:${process.env.PATH ?? ''}`,
        npm_config_prefix: prefix,
        GITHUB_WORKSPACE: workspace
      })
      const effect = path.join(workspace, binEffectName)
      const ran = fs.existsSync(effect)
      assert.equal(ran, false, `sbom script executed the globally installed cyclonedx bin (exit ${result.status})`)
    })
  })

  void it('builds the release archive without the globally installed archiver', async () => {
    const script = releaseScripts.find(item => item.includes('archiver')) ?? 'npm install -g archiver'
    const uploadPattern = releaseYaml.match(/^\s*files:\s*(\S+)\s*$/m)?.[1] ?? ''
    await withInstall(script, releaseEnv, async (workspace, prefix) => {
      fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify({ name: 'juice-shop', version: '20.2.0' }, null, 2) + '\n')
      fs.writeFileSync(path.join(workspace, 'LICENSE'), 'MIT\n')
      const childEnv: NodeJS.ProcessEnv = {
        ...process.env,
        HOME: path.join(workspace, 'home'),
        PATH: `${path.join(prefix, 'bin')}:${process.env.PATH ?? ''}`,
        npm_config_prefix: prefix,
        npm_config_cache: path.join(workspace, 'cache'),
        GITHUB_WORKSPACE: workspace,
        PCKG_FORMAT: 'tgz',
        PCKG_OS_NAME: 'linux',
        PCKG_CPU_ARCH: 'x64',
        PCKG_NODE_VERSION: '22'
      }
      delete childEnv.GITHUB_TOKEN
      const packaged = await new Promise<{ status: number, stderr: string }>((resolve, reject) => {
        const child = spawn(process.execPath, [path.join(repoRoot, 'scripts/package.mjs')], {
          cwd: workspace,
          env: childEnv,
          stdio: ['ignore', 'pipe', 'pipe']
        })
        let stderr = ''
        child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8') })
        child.on('error', reject)
        child.on('exit', (status) => { resolve({ status: status ?? 1, stderr }) })
      })
      assert.equal(packaged.status, 0, `package.mjs exited ${packaged.status}\n${packaged.stderr}`)
      const archives = fs.readdirSync(path.join(workspace, 'dist')).filter(name => name.endsWith('.tgz'))
      assert.equal(archives.length, 1)
      const archivePath = path.join(workspace, 'dist', archives[0])
      const bytes = fs.readFileSync(archivePath)
      assert.equal(bytes.includes(Buffer.from(compromisedMarker)), false, 'archive was written by the globally installed archiver')
      const listed = await new Promise<string>((resolve, reject) => {
        const tar = spawn('tar', ['-tzf', archivePath], { stdio: ['ignore', 'pipe', 'pipe'] })
        let stdout = ''
        let stderr = ''
        tar.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8') })
        tar.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8') })
        tar.on('error', reject)
        tar.on('exit', (status) => {
          if (status !== 0) reject(new Error(stderr))
          else resolve(stdout)
        })
      })
      assert.match(listed, /LICENSE/)
      if (uploadPattern === 'dist/*') {
        for (const name of fs.readdirSync(path.join(workspace, 'dist'))) {
          const file = fs.readFileSync(path.join(workspace, 'dist', name))
          assert.equal(file.includes(Buffer.from(compromisedMarker)), false, `dist/${name} matches the release upload and contains the global archiver marker`)
        }
      }
    })
  })
})
