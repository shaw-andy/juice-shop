/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import type { IncomingMessage } from 'node:http'
import { createTestApp } from './helpers/setup'

const sourcePrivateDir = path.resolve('frontend/src/assets/private')
const distRoot = path.resolve('frontend/dist/frontend')
const wallpaperName = 'JuiceShop_Wallpaper_1920x1080_VR.jpg'
const demoName = 'threejs-demo.html'
const sentinelName = 'sentinel-private-asset.txt'
const sentinelBody = Buffer.from('PRIVATE_ASSET_MARKER')
const symlinkPath = path.join(distRoot, 'assets/public/private-wallpaper-link.jpg')
const sentinelPath = path.join(distRoot, 'assets/private', sentinelName)
const paywallPath = '/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us'
const easterEggPath = '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'
const placeholderCookie = 'token=placeholder'

const privateFiles = fs.readdirSync(sourcePrivateDir)
  .filter((name) => fs.statSync(path.join(sourcePrivateDir, name)).isFile())
  .sort()

let app: Express

function readSource (name: string) {
  return fs.readFileSync(path.join(sourcePrivateDir, name))
}

function collectBody (res: IncomingMessage, callback: (err: Error | null, body: Buffer) => void) {
  const chunks: Buffer[] = []
  res.on('data', (chunk: Buffer) => {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  })
  res.on('end', () => {
    callback(null, Buffer.concat(chunks))
  })
}

async function getBytes (urlPath: string, headers: Record<string, string> = {}) {
  const req = request(app)
    .get(urlPath)
    .set('Accept-Encoding', 'identity')
    .buffer(true)
    .parse(collectBody)
  for (const [name, value] of Object.entries(headers)) {
    req.set(name, value)
  }
  return await req
}

function exposesFile (body: unknown, file: Buffer) {
  if (!Buffer.isBuffer(body) || body.length === 0 || file.length === 0) {
    return false
  }
  if (body.equals(file) || body.includes(file)) {
    return true
  }
  return body.length < file.length && file.subarray(0, body.length).equals(body)
}

function assertHidden (body: unknown, file: Buffer) {
  assert.equal(exposesFile(body, file), false)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  fs.rmSync(symlinkPath, { force: true })
  fs.rmSync(sentinelPath, { force: true })
})

void describe('private frontend assets are not published by the static handler', () => {
  for (const name of privateFiles) {
    const file = readSource(name)

    void it(`GET /assets/private/${name} does not return that file without a session`, async () => {
      const res = await getBytes('/assets/private/' + name)
      assertHidden(res.body, file)
    })

    void it(`GET /assets/public/%2e%2e/private/${name} does not return that file`, async () => {
      const res = await getBytes('/assets/public/%2e%2e/private/' + name)
      assertHidden(res.body, file)
    })

    void it(`HEAD /assets/private/${name} does not advertise that file`, async () => {
      const res = await request(app)
        .head('/assets/private/' + name)
        .set('Accept-Encoding', 'identity')
      const length = String(res.headers['content-length'] ?? '')
      const type = String(res.headers['content-type'] ?? '')
      assert.equal(res.status === 200 && length === String(file.length) && type.length > 0, false)
    })
  }

  void it('GET of the wallpaper still fails when the slash before the file name is encoded', async () => {
    const res = await getBytes('/assets/private%2f' + wallpaperName)
    assertHidden(res.body, readSource(wallpaperName))
  })

  void it('GET of the wallpaper still fails for a dot segment, a collapsed slash, and a query string', async () => {
    const file = readSource(wallpaperName)
    const paths = [
      '/assets/private/./' + wallpaperName,
      '/assets/private/' + wallpaperName + '/.',
      '//assets//private//' + wallpaperName,
      '/assets/private/' + wallpaperName + '?download=1',
      '/assets/public/../private/' + wallpaperName,
      '/assets/public/images/../../private/' + wallpaperName,
      '/assets/private/' + wallpaperName.replace('.', '%2e')
    ]
    for (const urlPath of paths) {
      const res = await getBytes(urlPath)
      assertHidden(res.body, file)
    }
  })

  void it('GET of the planet demo still fails when the request is not the literal private path', async () => {
    const file = readSource(demoName)
    const paths = [
      '/assets/private%2f' + demoName,
      '/assets/public/../private/' + demoName,
      '/assets/private/./' + demoName
    ]
    for (const urlPath of paths) {
      const res = await getBytes(urlPath)
      assertHidden(res.body, file)
    }
  })

  void it('GET of the wallpaper with a placeholder cookie or authorization header does not return the file', async () => {
    const file = readSource(wallpaperName)
    const withCookie = await getBytes('/assets/private/' + wallpaperName, { Cookie: placeholderCookie })
    const withAuthorization = await getBytes('/assets/private/' + wallpaperName, { Authorization: 'Bearer placeholder' })
    assertHidden(withCookie.body, file)
    assertHidden(withAuthorization.body, file)
  })

  void it('a byte range of the wallpaper is not returned', async () => {
    const file = readSource(wallpaperName)
    const ranges = [
      { header: 'bytes=0-15', start: 0, end: 16 },
      { header: 'bytes=100-115', start: 100, end: 116 }
    ]
    for (const range of ranges) {
      const res = await getBytes('/assets/private/' + wallpaperName, { Range: range.header })
      const slice = file.subarray(range.start, range.end)
      assert.equal(Buffer.isBuffer(res.body) && res.body.equals(slice), false)
      assertHidden(res.body, file)
    }
  })

  void it('a file placed in the private directory after startup is not returned', async () => {
    fs.mkdirSync(path.dirname(sentinelPath), { recursive: true })
    fs.writeFileSync(sentinelPath, sentinelBody)
    const res = await getBytes('/assets/private/' + sentinelName)
    assertHidden(res.body, sentinelBody)
  })

  void it('a public symlink to the wallpaper is not returned', async () => {
    fs.rmSync(symlinkPath, { force: true })
    fs.symlinkSync('../private/' + wallpaperName, symlinkPath)
    const res = await getBytes('/assets/public/private-wallpaper-link.jpg')
    assertHidden(res.body, readSource(wallpaperName))
  })

  void it('GET a public image is still served', async () => {
    const file = fs.readFileSync(path.resolve('frontend/src/assets/public/images/padding/1px.png'))
    const res = await getBytes('/assets/public/images/padding/1px.png')
    assert.equal(res.status, 200)
    assert.equal(Buffer.isBuffer(res.body) && res.body.equals(file), true)
  })

  void it('the paywall route still returns the wallpaper', async () => {
    const res = await getBytes(paywallPath)
    assert.equal(res.status, 200)
    assert.equal(Buffer.isBuffer(res.body) && res.body.equals(readSource(wallpaperName)), true)
  })

  void it('the easter egg route still returns the planet demo', async () => {
    const res = await getBytes(easterEggPath)
    assert.equal(res.status, 200)
    assert.equal(Buffer.isBuffer(res.body) && res.body.equals(readSource(demoName)), true)
  })
})
