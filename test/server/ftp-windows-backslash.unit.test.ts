/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import Module from 'node:module'
import { servePublicFiles } from '../../routes/fileServer'
import { serveKeyFiles } from '../../routes/keyServer'
import { serveLogFiles } from '../../routes/logfileServer'
import { serveQuarantineFiles } from '../../routes/quarantineServer'

const require = createRequire(import.meta.url)
const savedResolve = path.resolve
const savedStat = fs.stat
const savedOpen = fs.open
const savedCwd = process.cwd

const driveRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ftp-win-'))
const opened: string[] = []

function toLinux (winPathName: string): string | null {
  let value = winPathName
  if (value.startsWith('\\\\?\\')) value = value.slice(4)
  if (!/^c:[\\/]/i.test(value)) return null
  return driveRoot + value.slice(2).replaceAll('\\', '/')
}

function installFsMap (): void {
  fs.stat = function (p: fs.PathLike, options?: unknown, cb?: unknown) {
    if (typeof options === 'function') {
      cb = options
      options = undefined
    }
    const linux = toLinux(String(p))
    opened.push(String(p))
    if (linux == null) {
      const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      process.nextTick(() => (cb as (err: Error) => void)(err))
      return
    }
    return savedStat.call(fs, linux, options as never, cb as never)
  } as typeof fs.stat
  fs.open = function (p: fs.PathLike, flags: fs.OpenMode, mode?: unknown, cb?: unknown) {
    if (typeof mode === 'function') {
      cb = mode
      mode = 0o666
    }
    const linux = toLinux(String(p))
    opened.push(String(p))
    if (linux == null) {
      const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      process.nextTick(() => (cb as (err: Error) => void)(err))
      return
    }
    return savedOpen.call(fs, linux, flags, mode as never, cb as never)
  } as typeof fs.open
}

const winPath = new Proxy(path, {
  get (target, prop, receiver) {
    if (prop === 'win32' || prop === 'posix') return target[prop]
    if (Object.prototype.hasOwnProperty.call(target.win32, prop)) {
      return target.win32[prop as keyof typeof target.win32]
    }
    const value = Reflect.get(target, prop, receiver)
    return typeof value === 'function' ? value.bind(target) : value
  }
})

const origRequire = Module.prototype.require
Module.prototype.require = function (id: string) {
  if (id === 'path') return winPath
  return origRequire.apply(this, arguments)
}
for (const key of Object.keys(require.cache)) {
  if (key.includes(`${path.sep}express${path.sep}`) || key.includes(`${path.sep}send${path.sep}`) || key.includes(`${path.sep}serve-index${path.sep}`)) {
    delete require.cache[key]
  }
}
const express = require('express')
const serveIndex = require('serve-index')
Module.prototype.require = origRequire

function outsideRoot (winPathName: string, root: string): boolean {
  const resolvedRoot = path.win32.resolve(root)
  const resolved = path.win32.resolve(winPathName)
  const prefix = resolvedRoot.endsWith('\\') ? resolvedRoot : resolvedRoot + '\\'
  return resolved.toLowerCase() !== resolvedRoot.toLowerCase() && !resolved.toLowerCase().startsWith(prefix.toLowerCase())
}

interface RunningApp {
  baseUrl: string
  close: () => Promise<void>
}

function listen (app: { listen: Function }): Promise<RunningApp> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const address = server.address()
      const port = typeof address === 'object' && address != null ? address.port : 0
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((resolve, reject) => {
          server.close((err?: Error) => err ? reject(err) : resolve())
        })
      })
    })
  })
}

function mountError (app: { use: Function }): void {
  app.use((err: { status?: number, statusCode?: number, message?: string }, _req: unknown, res: { status: Function, end: Function }, _next: unknown) => {
    res.status(err.status || err.statusCode || 500).end(String(err.message))
  })
}

let stacked: RunningApp
let bare: RunningApp

before(async () => {
  fs.mkdirSync(path.join(driveRoot, 'shop', 'ftp', 'quarantine'), { recursive: true })
  fs.mkdirSync(path.join(driveRoot, 'shop', 'data'), { recursive: true })
  fs.mkdirSync(path.join(driveRoot, 'shop', 'encryptionkeys'), { recursive: true })
  fs.mkdirSync(path.join(driveRoot, 'shop', 'logs'), { recursive: true })
  fs.mkdirSync(path.join(driveRoot, 'data'), { recursive: true })
  fs.writeFileSync(path.join(driveRoot, 'shop', 'ftp', 'legal.md'), 'LEGAL_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'shop', 'ftp', 'quarantine', 'note.pdf'), 'QUARANTINE_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'shop', 'encryptionkeys', 'premium.key'), 'KEY_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'shop', 'logs', 'access.log'), 'LOG_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'shop', 'README.md'), 'SHOP_README_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'README.md'), 'PARENT_README_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'shop', 'data', 'juiceshop.sqlite'), 'SHOP_DB_MARKER')
  fs.writeFileSync(path.join(driveRoot, 'data', 'juiceshop.sqlite'), 'PARENT_DB_MARKER')

  installFsMap()
  process.cwd = () => 'C:\\shop'
  path.resolve = path.win32.resolve

  const slash = (req: { url: string }, _res: unknown, next: () => void) => {
    req.url = req.url.replace(/[/]+/g, '/')
    next()
  }

  const stackedApp = express()
  stackedApp.use(slash)
  stackedApp.use('/ftp', serveIndex('ftp', { icons: true }))
  stackedApp.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  stackedApp.use('/ftp/quarantine/:file', serveQuarantineFiles())
  stackedApp.use('/encryptionkeys', serveIndex('encryptionkeys', { icons: true }))
  stackedApp.use('/encryptionkeys/:file', serveKeyFiles())
  stackedApp.use('/support/logs', serveIndex('logs', { icons: true }))
  stackedApp.use('/support/logs/:file', serveLogFiles())
  mountError(stackedApp)

  const bareApp = express()
  bareApp.use(slash)
  bareApp.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  mountError(bareApp)

  stacked = await listen(stackedApp)
  bare = await listen(bareApp)
})

after(async () => {
  path.resolve = savedResolve
  fs.stat = savedStat
  fs.open = savedOpen
  process.cwd = savedCwd
  await stacked.close()
  await bare.close()
  fs.rmSync(driveRoot, { recursive: true, force: true })
})

async function get (baseUrl: string, urlPath: string): Promise<{ status: number, body: string, opened: string[] }> {
  opened.length = 0
  const res = await fetch(baseUrl + urlPath)
  const body = await res.text()
  return { status: res.status, body, opened: [...opened] }
}

function assertContained (res: { body: string, opened: string[] }, root: string, markers: string[]): void {
  for (const marker of markers) {
    assert.equal(res.body.includes(marker), false)
  }
  assert.ok(res.opened.every((entry) => !outsideRoot(entry, root)))
}

void describe('Windows backslash FTP traversal through the mounted routes', () => {
  void it('serves a markdown file that stays inside ftp', async () => {
    const res = await get(stacked.baseUrl, '/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.equal(res.body, 'LEGAL_MARKER')
    assert.ok(res.opened.every((entry) => !outsideRoot(entry, 'C:\\shop\\ftp')))
  })

  void it('does not return a file outside ftp for a drive-absolute backslash name', async () => {
    const res = await get(stacked.baseUrl, '/ftp/C:%5Cshop%5CREADME.md')
    assertContained(res, 'C:\\shop\\ftp', ['SHOP_README_MARKER', 'PARENT_README_MARKER'])
  })

  void it('does not return a file outside ftp for dot-dot backslash names', async () => {
    const two = await get(stacked.baseUrl, '/ftp/..%5C..%5CREADME.md')
    const one = await get(stacked.baseUrl, '/ftp/..%5CREADME.md')
    assertContained(two, 'C:\\shop\\ftp', ['PARENT_README_MARKER', 'SHOP_README_MARKER'])
    assertContained(one, 'C:\\shop\\ftp', ['SHOP_README_MARKER'])
  })

  void it('does not return the shop database when a drive-absolute name is cut at a percent-encoded null', async () => {
    const absolute = await get(stacked.baseUrl, '/ftp/C:%5Cshop%5Cdata%5Cjuiceshop.sqlite%2500.md')
    assertContained(absolute, 'C:\\shop\\ftp', ['SHOP_DB_MARKER', 'PARENT_DB_MARKER'])
  })

  void it('does not return the shop database when a dot-dot backslash name is cut at a percent-encoded null', async () => {
    const relative = await get(stacked.baseUrl, '/ftp/..%5Cdata%5Cjuiceshop.sqlite%2500.md')
    assertContained(relative, 'C:\\shop\\ftp', ['SHOP_DB_MARKER', 'PARENT_DB_MARKER'])
  })

  void it('does not leave the encryption key directory via a backslash name', async () => {
    const key = await get(stacked.baseUrl, '/encryptionkeys/C:%5Cshop%5CREADME.md')
    assertContained(key, 'C:\\shop\\encryptionkeys', ['SHOP_README_MARKER'])
  })

  void it('does not leave the log directory via a backslash name', async () => {
    const log = await get(stacked.baseUrl, '/support/logs/C:%5Cshop%5CREADME.md')
    assertContained(log, 'C:\\shop\\logs', ['SHOP_README_MARKER'])
  })

  void it('does not leave the quarantine directory via a backslash name', async () => {
    const quarantine = await get(stacked.baseUrl, '/ftp/quarantine/C:%5Cshop%5CREADME.md')
    assertContained(quarantine, 'C:\\shop\\ftp\\quarantine', ['SHOP_README_MARKER'])
  })
})

void describe('public file handler without the directory listing middleware', () => {
  void it('does not return a file outside ftp for a drive-absolute backslash name', async () => {
    const absolute = await get(bare.baseUrl, '/ftp/C:%5Cshop%5CREADME.md')
    assertContained(absolute, 'C:\\shop\\ftp', ['SHOP_README_MARKER'])
  })

  void it('does not return a file outside ftp for a dot-dot backslash name', async () => {
    const relative = await get(bare.baseUrl, '/ftp/..%5CREADME.md')
    assertContained(relative, 'C:\\shop\\ftp', ['SHOP_README_MARKER'])
  })

  void it('does not return the shop database when a drive-absolute name is cut at a percent-encoded null', async () => {
    const database = await get(bare.baseUrl, '/ftp/C:%5Cshop%5Cdata%5Cjuiceshop.sqlite%2500.md')
    assertContained(database, 'C:\\shop\\ftp', ['SHOP_DB_MARKER'])
  })
})
