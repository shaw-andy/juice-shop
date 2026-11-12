/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import { type AddressInfo } from 'node:net'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

// Same cap as the complaint upload storage in server.ts (uploadToMemory).
const COMPLAINT_UPLOAD_BYTE_LIMIT = 200000
const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')

let app: Express

before(async () => {
  fs.mkdirSync(uploadDir, { recursive: true })
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  for (const name of fs.readdirSync(uploadDir)) {
    if (name.startsWith('probe-memory-')) {
      fs.rmSync(path.join(uploadDir, name), { force: true })
    }
  }
})

interface UploadTracker {
  created: string[]
  restore: () => void
}

function trackUploadWrites (): UploadTracker {
  const created: string[] = []
  const note = (filePath: fs.PathLike) => {
    const resolved = path.resolve(String(filePath))
    if (resolved === uploadDir || resolved.startsWith(uploadDir + path.sep)) {
      created.push(resolved)
    }
  }
  const originalCreateWriteStream = fs.createWriteStream
  const originalWriteFile = fs.writeFile
  const originalWriteFileSync = fs.writeFileSync
  const originalAppendFile = fs.appendFile
  const originalPromisesWriteFile = fs.promises.writeFile

  fs.createWriteStream = ((filePath: fs.PathLike, options?: Parameters<typeof originalCreateWriteStream>[1]) => {
    note(filePath)
    return originalCreateWriteStream(filePath, options)
  }) as typeof fs.createWriteStream

  fs.writeFile = ((filePath: fs.PathLike, data: string | NodeJS.ArrayBufferView, ...rest: unknown[]) => {
    note(filePath)
    return (originalWriteFile as (...args: unknown[]) => unknown)(filePath, data, ...rest)
  }) as typeof fs.writeFile

  fs.writeFileSync = ((filePath: fs.PathLike, data: string | NodeJS.ArrayBufferView, ...rest: unknown[]) => {
    note(filePath)
    return (originalWriteFileSync as (...args: unknown[]) => unknown)(filePath, data, ...rest)
  }) as typeof fs.writeFileSync

  fs.appendFile = ((filePath: fs.PathLike, data: string | NodeJS.ArrayBufferView, ...rest: unknown[]) => {
    note(filePath)
    return (originalAppendFile as (...args: unknown[]) => unknown)(filePath, data, ...rest)
  }) as typeof fs.appendFile

  fs.promises.writeFile = (async (filePath: fs.PathLike, data: string | NodeJS.ArrayBufferView, options?: fs.WriteFileOptions) => {
    note(filePath)
    return await originalPromisesWriteFile(filePath, data, options)
  }) as typeof fs.promises.writeFile

  return {
    created,
    restore () {
      fs.createWriteStream = originalCreateWriteStream
      fs.writeFile = originalWriteFile
      fs.writeFileSync = originalWriteFileSync
      fs.appendFile = originalAppendFile
      fs.promises.writeFile = originalPromisesWriteFile
    }
  }
}

function snapshotUploads (): Set<string> {
  return new Set(fs.readdirSync(uploadDir))
}

function uploadsAddedSince (before: Set<string>): string[] {
  return fs.readdirSync(uploadDir).filter((name) => !before.has(name))
}

function assertNothingStored (created: string[], added: string[], label: string) {
  const createdDetails = created.map((filePath) => {
    const size = fs.existsSync(filePath) ? fs.statSync(filePath).size : 'removed'
    return `${path.basename(filePath)} (${size} bytes)`
  })
  const addedDetails = added.map((name) => {
    const size = fs.statSync(path.join(uploadDir, name)).size
    return `${name} (${size} bytes)`
  })
  assert.deepEqual(created, [], `${label} opened an upload file before the request was refused: ${createdDetails.join(', ')}`)
  assert.deepEqual(added, [], `${label} left an upload file after the request was refused: ${addedDetails.join(', ')}`)
}

function removeTracked (created: string[], before: Set<string>) {
  for (const filePath of created) {
    fs.rmSync(filePath, { force: true })
  }
  for (const name of uploadsAddedSince(before)) {
    fs.rmSync(path.join(uploadDir, name), { force: true })
  }
}

async function postMemory (options: {
  body: Buffer
  filename: string
  contentType: string
  authorization?: string
}) {
  const req = request(app)
    .post('/rest/memories')
    .attach('image', options.body, { filename: options.filename, contentType: options.contentType })
  if (options.authorization !== undefined) {
    req.set('Authorization', options.authorization)
  }
  return await req
}

function postMemoryChunked (options: {
  size: number
  filename: string
  contentType: string
  authorization?: string
}): Promise<{ status: number, body: string, requestContentLength: number | undefined }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const boundary = '----MemoryUploadProbe'
      const head = Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="image"; filename="${options.filename}"\r\n` +
        `Content-Type: ${options.contentType}\r\n\r\n`
      )
      const tail = Buffer.from(`\r\n--${boundary}--\r\n`)
      const payload = Buffer.alloc(options.size, 0x61)
      const address = server.address() as AddressInfo
      const headers: http.OutgoingHttpHeaders = {
        'Content-Type': `multipart/form-data; boundary=${boundary}`
      }
      if (options.authorization !== undefined) {
        headers.Authorization = options.authorization
      }
      const req = http.request({
        host: '127.0.0.1',
        port: address.port,
        method: 'POST',
        path: '/rest/memories',
        headers
      }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
        res.on('end', () => {
          server.close(() => {
            resolve({
              status: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf8'),
              requestContentLength: contentLengthHeader(req)
            })
          })
        })
      })
      req.on('error', (err) => {
        server.close(() => { reject(err) })
      })
      req.write(head)
      const piece = 16 * 1024
      for (let offset = 0; offset < payload.length; offset += piece) {
        req.write(payload.subarray(offset, Math.min(offset + piece, payload.length)))
      }
      req.end(tail)
    })
    server.on('error', reject)
  })
}

function contentLengthHeader (req: http.ClientRequest): number | undefined {
  const value = req.getHeader('content-length')
  if (value === undefined) return undefined
  return Number(value)
}

void describe('POST /rest/memories disk storage', { concurrency: false }, () => {
  void it('does not store an image/png part when the caller has no session', async () => {
    const before = snapshotUploads()
    const tracker = trackUploadWrites()
    try {
      const res = await postMemory({
        body: Buffer.alloc(64, 0x89),
        filename: 'probe-memory-png.png',
        contentType: 'image/png'
      })
      assert.equal(res.status, 401)
      assertNothingStored(tracker.created, uploadsAddedSince(before), 'unauthenticated image/png')
    } finally {
      tracker.restore()
      removeTracked(tracker.created, before)
    }
  })

  void it('does not store an image/jpeg part when the caller has no session', async () => {
    const before = snapshotUploads()
    const tracker = trackUploadWrites()
    try {
      const res = await postMemory({
        body: Buffer.alloc(64, 0xff),
        filename: 'probe-memory-jpeg.jpg',
        contentType: 'image/jpeg'
      })
      assert.equal(res.status, 401)
      assertNothingStored(tracker.created, uploadsAddedSince(before), 'unauthenticated image/jpeg')
    } finally {
      tracker.restore()
      removeTracked(tracker.created, before)
    }
  })

  void it('does not store an image/jpg part when the caller has no session', async () => {
    const before = snapshotUploads()
    const tracker = trackUploadWrites()
    try {
      const res = await postMemory({
        body: Buffer.alloc(64, 0xff),
        filename: 'probe-memory-jpg.jpg',
        contentType: 'image/jpg'
      })
      assert.equal(res.status, 401)
      assertNothingStored(tracker.created, uploadsAddedSince(before), 'unauthenticated image/jpg')
    } finally {
      tracker.restore()
      removeTracked(tracker.created, before)
    }
  })

  void it('does not store an image when the bearer token is not a logged-in session', async () => {
    const before = snapshotUploads()
    const tracker = trackUploadWrites()
    try {
      const res = await postMemory({
        body: Buffer.alloc(64, 0x89),
        filename: 'probe-memory-placeholder.png',
        contentType: 'image/png',
        authorization: 'Bearer placeholder-token'
      })
      assert.equal(res.status, 401)
      assertNothingStored(tracker.created, uploadsAddedSince(before), 'unknown bearer token')
    } finally {
      tracker.restore()
      removeTracked(tracker.created, before)
    }
  })

  void it('does not store a part larger than the complaint upload cap when the body is chunked and has no content-length', async () => {
    const before = snapshotUploads()
    const tracker = trackUploadWrites()
    const size = COMPLAINT_UPLOAD_BYTE_LIMIT + 1
    try {
      const res = await postMemoryChunked({
        size,
        filename: 'probe-memory-chunked.png',
        contentType: 'image/png'
      })
      assert.equal(res.requestContentLength, undefined)
      assert.equal(res.status, 401)
      assertNothingStored(tracker.created, uploadsAddedSince(before), `chunked image/png of ${size} bytes`)
    } finally {
      tracker.restore()
      removeTracked(tracker.created, before)
    }
  })

  void it('rejects an authenticated image larger than the complaint upload cap without storing it', async () => {
    const before = snapshotUploads()
    const tracker = trackUploadWrites()
    const size = COMPLAINT_UPLOAD_BYTE_LIMIT + 1
    try {
      const { token } = await login(app, {
        email: 'jim@' + config.get<string>('application.domain'),
        password: 'ncc-1701'
      })
      const res = await postMemory({
        body: Buffer.alloc(size, 0x89),
        filename: 'probe-memory-oversized.png',
        contentType: 'image/png',
        authorization: 'Bearer ' + token
      })
      assert.ok(res.status >= 400 && res.status < 600, `expected the oversized upload to be refused, got ${res.status}`)
      assertNothingStored(tracker.created, uploadsAddedSince(before), `authenticated image/png of ${size} bytes`)
    } finally {
      tracker.restore()
      removeTracked(tracker.created, before)
    }
  })
})
