/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'
import net, { type AddressInfo } from 'node:net'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

// A few hundred kilobytes. Sibling multipart uploads are capped at 200000 bytes.
const MAX_PROFILE_IMAGE_URL_BYTES = 512 * 1024
// Idle undici body timeout is 300s. The endpoint must stop well before that.
const MAX_STALL_MS = 8_000
const OVERSIZE_BODY_BYTES = 2 * 1024 * 1024
const CHUNK_BYTES = 16 * 1024
const UPLOAD_DIR = 'frontend/dist/frontend/assets/public/images/uploads'
const placeholderPassword = 'placeholder-password'

let app: Express
let imageServer: http.Server
let imagePort: number
let token: string
let userId: number
const sockets = new Set<net.Socket>()

before(async () => {
  const result = await createTestApp()
  app = result.app
  fs.mkdirSync(UPLOAD_DIR, { recursive: true })

  const email = `profile-image-url-size-${Date.now()}@localhost`
  await register(app, { email, password: placeholderPassword })
  const authentication = await login(app, { email, password: placeholderPassword })
  token = authentication.token
  userId = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).data.id

  imageServer = http.createServer((req, res) => {
    const pathname = req.url?.split('?')[0]
    if (pathname === '/small.jpg') {
      const body = Buffer.alloc(2048, 7)
      res.writeHead(200, {
        'Content-Type': 'image/jpeg',
        'Content-Length': String(body.length)
      })
      res.end(body)
      return
    }
    if (pathname === '/huge.jpg' || pathname === '/declared-huge.jpg') {
      streamOversized(req, res, pathname === '/declared-huge.jpg')
      return
    }
    if (pathname === '/stall.jpg') {
      res.writeHead(200, { 'Content-Type': 'image/jpeg' })
      res.write(Buffer.alloc(4096, 3))
      return
    }
    res.statusCode = 404
    res.end()
  })
  imageServer.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => { sockets.delete(socket) })
  })
  await new Promise<void>((resolve) => { imageServer.listen(0, '127.0.0.1', resolve) })
  imagePort = (imageServer.address() as AddressInfo).port
}, { timeout: 60000 })

after(async () => {
  destroyImageSockets()
  if (imageServer) {
    await new Promise<void>((resolve, reject) => {
      imageServer.close((err) => { err != null ? reject(err) : resolve() })
    })
  }
  removeProfileImages()
})

void describe('POST /profile/image/url downloaded body limits', { concurrency: false }, () => {
  void it('saves a body that is under the cap', async () => {
    const filePath = profileImagePath('jpg')
    fs.rmSync(filePath, { force: true })

    const res = await postImageUrl(`http://127.0.0.1:${imagePort}/small.jpg`)

    assert.equal(res.status, 302)
    assert.equal(fs.statSync(filePath).size, 2048)
  })

  void it('stops a chunked body with no Content-Length before the file can fill the disk', async () => {
    await assertOversizedDownload(`http://127.0.0.1:${imagePort}/huge.jpg`)
  })

  void it('stops a body whose Content-Length is already above the cap', async () => {
    await assertOversizedDownload(`http://127.0.0.1:${imagePort}/declared-huge.jpg`)
  })

  void it('stops a response that sends headers and then never ends', async () => {
    const filePath = profileImagePath('jpg')
    fs.rmSync(filePath, { force: true })
    const started = Date.now()

    try {
      await Promise.race([
        postImageUrl(`http://127.0.0.1:${imagePort}/stall.jpg`),
        delay(MAX_STALL_MS).then(() => {
          throw new Error(`profile image URL request was still reading the body after ${MAX_STALL_MS}ms`)
        })
      ])
    } finally {
      destroyImageSockets()
    }

    const elapsed = Date.now() - started
    assert.ok(elapsed < MAX_STALL_MS, `request took ${elapsed}ms`)
    const size = await fileSize(filePath)
    assert.ok(
      size <= MAX_PROFILE_IMAGE_URL_BYTES,
      `stalled download left ${size} bytes at ${filePath}`
    )
    const later = await delay(300).then(async () => await fileSize(filePath))
    assert.equal(later, size, 'stalled download kept writing after the response returned')
  })
})

async function assertOversizedDownload (imageUrl: string) {
  const filePath = profileImagePath('jpg')
  fs.rmSync(filePath, { force: true })
  const transfer = transferFor(imageUrl)
  const peak = { size: 0 }
  const timer = setInterval(() => {
    void fileSize(filePath).then((size) => {
      if (size > peak.size) peak.size = size
    })
  }, 10)

  try {
    await postImageUrl(imageUrl)
  } finally {
    clearInterval(timer)
    peak.size = Math.max(peak.size, await fileSize(filePath))
  }

  const finalSize = await fileSize(filePath)
  assert.ok(
    peak.size <= MAX_PROFILE_IMAGE_URL_BYTES,
    `download wrote ${peak.size} bytes to ${filePath}; cap is ${MAX_PROFILE_IMAGE_URL_BYTES}`
  )
  assert.equal(finalSize, 0, `partial download was left on disk (${finalSize} bytes at ${filePath})`)
  assert.ok(
    transfer.sent < OVERSIZE_BODY_BYTES,
    `handler read the entire ${OVERSIZE_BODY_BYTES}-byte body (${transfer.sent} bytes written by the origin)`
  )
}

function streamOversized (req: http.IncomingMessage, res: http.ServerResponse, declareLength: boolean) {
  const headers: http.OutgoingHttpHeaders = { 'Content-Type': 'image/jpeg' }
  if (declareLength) headers['Content-Length'] = String(OVERSIZE_BODY_BYTES)
  res.writeHead(200, headers)

  const transfer = transferFor(`http://127.0.0.1${req.url ?? ''}`)
  transfer.sent = 0
  const chunk = Buffer.alloc(CHUNK_BYTES, 9)
  let stopped = false
  const stop = () => { stopped = true }
  req.on('aborted', stop)
  req.on('close', stop)
  res.on('close', stop)

  const pump = () => {
    if (stopped) return
    if (transfer.sent >= OVERSIZE_BODY_BYTES) {
      res.end()
      return
    }
    const ok = res.write(chunk)
    transfer.sent += chunk.length
    if (ok) setTimeout(pump, 15)
    else res.once('drain', () => { setTimeout(pump, 15) })
  }
  pump()
}

const transfersByPath = new Map<string, { sent: number }>()

function transferFor (imageUrl: string) {
  const pathname = new URL(imageUrl).pathname
  let record = transfersByPath.get(pathname)
  if (record == null) {
    record = { sent: 0 }
    transfersByPath.set(pathname, record)
  }
  return record
}

function postImageUrl (imageUrl: string) {
  return request(app)
    .post('/profile/image/url')
    .set('Cookie', `token=${token}`)
    .type('form')
    .send({ imageUrl })
    .redirects(0)
}

function profileImagePath (ext: string) {
  return path.join(UPLOAD_DIR, `${userId}.${ext}`)
}

async function fileSize (filePath: string) {
  try {
    return (await fs.promises.stat(filePath)).size
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 0
    throw error
  }
}

function delay (ms: number) {
  return new Promise<void>((resolve) => { setTimeout(resolve, ms) })
}

function destroyImageSockets () {
  for (const socket of sockets) socket.destroy()
}

function removeProfileImages () {
  for (const ext of ['jpg', 'jpeg', 'png', 'svg', 'gif']) {
    fs.rmSync(profileImagePath(ext), { force: true })
  }
}
