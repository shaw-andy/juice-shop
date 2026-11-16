/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net, { type AddressInfo } from 'node:net'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

// body-parser's default urlencoded limit is 100kb (102400 bytes). This value
// stays under that limit and under multer/busboy's default 1MB field size, so
// the handler runs. A quadratic match of this length takes many seconds.
const LONG_IMAGE_URL = 'a'.repeat(100_000)
const RESPONSE_BUDGET_MS = 1000
const PLACEHOLDER_TOKEN = 'placeholder-token'

let app: Express
let server: http.Server
let port: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  server = http.createServer(app)
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => { resolve() })
  })
  port = (server.address() as AddressInfo).port
}, { timeout: 60_000 })

after(async () => {
  if (server !== undefined) {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => { err != null ? reject(err) : resolve() })
    })
  }
})

void describe('POST /profile/image/url does not stall the event loop', { concurrency: false }, () => {
  void it('rejects a short anonymous imageUrl without stalling', async () => {
    const result = await pipeline(port, [
      urlencodedRequest('/profile/image/url', 'https://example.test/cat.jpg', false),
      getRequest('/robots.txt', true)
    ])

    assert.ok(result.ms < RESPONSE_BUDGET_MS, `short request took ${result.ms}ms (${result.ticks} ticks)`)
    assert.equal(result.responses[0].status, 500)
    assert.ok(result.responses[0].body.includes('Blocked illegal activity'))
    assert.equal(result.responses[1].status, 200)
    assert.equal(app.locals.abused_ssrf_bug, false)
  })

  void it('rejects a long urlencoded anonymous imageUrl without stalling other requests', async () => {
    await assertNoStall(urlencodedRequest('/profile/image/url', LONG_IMAGE_URL, false))
  })

  void it('rejects a long multipart anonymous imageUrl without stalling other requests', async () => {
    await assertNoStall(multipartRequest('/profile/image/url', LONG_IMAGE_URL, false))
  })

  void it('does not stall on a long urlencoded imageUrl from a signed-in user', async () => {
    const user = await UserModel.findOne()
    assert.ok(user)
    security.authenticatedUsers.put(PLACEHOLDER_TOKEN, { data: user })

    await assertNoStall(urlencodedRequest('/profile/image/url', LONG_IMAGE_URL, false, PLACEHOLDER_TOKEN), { anonymous: false })
  })
})

async function assertNoStall (firstRequest: string, options: { anonymous?: boolean } = {}) {
  const anonymous = options.anonymous !== false
  const result = await pipeline(port, [
    firstRequest,
    getRequest('/robots.txt', true)
  ])
  const post = result.responses[0]
  const followUp = result.responses[1]

  assert.ok(
    result.ms < RESPONSE_BUDGET_MS,
    `POST /profile/image/url blocked the event loop for ${result.ms}ms (${result.ticks} timer ticks)`
  )
  assert.equal(followUp.status, 200)
  if (anonymous) {
    assert.ok(post.status >= 400, `anonymous upload returned ${post.status}`)
    assert.equal(app.locals.abused_ssrf_bug, false)
  }
}

interface ParsedResponse {
  status: number
  body: string
}

async function pipeline (portNumber: number, requests: string[]) {
  const started = Date.now()
  let ticks = 0
  const timer = setInterval(() => { ticks++ }, 50)
  const responses: ParsedResponse[] = []
  try {
    await new Promise<void>((resolve, reject) => {
      let settled = false
      const finish = (err?: Error) => {
        if (settled) return
        settled = true
        if (err !== undefined) reject(err)
        else resolve()
      }
      const socket = net.connect(portNumber, '127.0.0.1', () => {
        for (const request of requests) socket.write(request)
      })
      socket.setTimeout(45_000)
      let buf = Buffer.alloc(0)
      socket.on('data', (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk])
        while (responses.length < requests.length) {
          const parsed = parseHttpMessage(buf)
          if (parsed === null) break
          responses.push(parsed.message)
          buf = parsed.rest
        }
        if (responses.length === requests.length) {
          socket.end()
          finish()
        }
      })
      socket.on('timeout', () => {
        socket.destroy()
        finish(new Error(`timed out after ${responses.length} response(s)`))
      })
      socket.on('error', (err) => { finish(err) })
      socket.on('end', () => {
        if (responses.length < requests.length) {
          finish(new Error(`connection closed after ${responses.length} response(s)`))
        } else {
          finish()
        }
      })
    })
  } finally {
    clearInterval(timer)
  }
  return { responses, ms: Date.now() - started, ticks }
}

function parseHttpMessage (buffer: Buffer): { message: ParsedResponse, rest: Buffer } | null {
  const headerEnd = buffer.indexOf('\r\n\r\n')
  if (headerEnd === -1) return null
  const headerText = buffer.subarray(0, headerEnd).toString('utf8')
  const lines = headerText.split('\r\n')
  const status = Number(lines[0]?.split(' ')[1])
  let contentLength: number | undefined
  let chunked = false
  for (const line of lines.slice(1)) {
    const separator = line.indexOf(':')
    if (separator === -1) continue
    const name = line.slice(0, separator).trim().toLowerCase()
    const value = line.slice(separator + 1).trim().toLowerCase()
    if (name === 'content-length') contentLength = Number(value)
    if (name === 'transfer-encoding' && value.includes('chunked')) chunked = true
  }
  const bodyStart = headerEnd + 4
  if (chunked) {
    const decoded = readChunkedBody(buffer, bodyStart)
    if (decoded === null) return null
    return {
      message: { status, body: decoded.body.toString('utf8') },
      rest: buffer.subarray(decoded.end)
    }
  }
  if (contentLength === undefined || Number.isNaN(contentLength)) return null
  if (buffer.length < bodyStart + contentLength) return null
  return {
    message: {
      status,
      body: buffer.subarray(bodyStart, bodyStart + contentLength).toString('utf8')
    },
    rest: buffer.subarray(bodyStart + contentLength)
  }
}

function readChunkedBody (buffer: Buffer, offset: number): { body: Buffer, end: number } | null {
  const parts: Buffer[] = []
  let cursor = offset
  while (cursor < buffer.length) {
    const lineEnd = buffer.indexOf('\r\n', cursor)
    if (lineEnd === -1) return null
    const size = Number.parseInt(buffer.subarray(cursor, lineEnd).toString('utf8').split(';')[0], 16)
    if (Number.isNaN(size)) return null
    const dataStart = lineEnd + 2
    if (size === 0) {
      const trailerEnd = buffer.indexOf('\r\n', dataStart)
      if (trailerEnd === -1) return null
      return { body: Buffer.concat(parts), end: trailerEnd + 2 }
    }
    if (buffer.length < dataStart + size + 2) return null
    parts.push(buffer.subarray(dataStart, dataStart + size))
    cursor = dataStart + size + 2
  }
  return null
}

function urlencodedRequest (path: string, imageUrl: string, close: boolean, token?: string) {
  const body = `imageUrl=${imageUrl}`
  return requestHead('POST', path, close, {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(body),
    ...(token !== undefined ? { Cookie: `token=${token}` } : {})
  }) + body
}

function multipartRequest (path: string, imageUrl: string, close: boolean) {
  const boundary = '----profileImageUrlBoundary'
  const body =
    `--${boundary}\r\n` +
    'Content-Disposition: form-data; name="imageUrl"\r\n\r\n' +
    `${imageUrl}\r\n` +
    `--${boundary}--\r\n`
  return requestHead('POST', path, close, {
    'Content-Type': `multipart/form-data; boundary=${boundary}`,
    'Content-Length': Buffer.byteLength(body)
  }) + body
}

function getRequest (path: string, close: boolean) {
  return requestHead('GET', path, close, {})
}

function requestHead (method: string, path: string, close: boolean, headers: Record<string, string | number>) {
  const lines = [
    `${method} ${path} HTTP/1.1`,
    `Host: 127.0.0.1:${port}`,
    `Connection: ${close ? 'close' : 'keep-alive'}`
  ]
  for (const [name, value] of Object.entries(headers)) {
    lines.push(`${name}: ${value}`)
  }
  return lines.join('\r\n') + '\r\n\r\n'
}
