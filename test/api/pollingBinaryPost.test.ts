/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as http from 'node:http'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'

const RESPONSE_DEADLINE_MS = 2000

let server: http.Server
let port: number

before(async () => {
  server = http.createServer()
  registerWebsocketEvents(server)
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') {
        port = addr.port
      }
      resolve()
    })
  })
})

after(async () => {
  if (server) {
    await new Promise<void>((resolve) => {
      server.close(() => { resolve() })
    })
  }
})

function request (options: http.RequestOptions, body?: Buffer | string): Promise<{ statusCode: number, body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      req.setTimeout(0)
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8')
        })
      })
    })
    req.setTimeout(RESPONSE_DEADLINE_MS, () => {
      req.destroy()
      reject(new Error(`HTTP response was not closed within ${RESPONSE_DEADLINE_MS}ms`))
    })
    req.on('error', reject)
    if (body === undefined) {
      req.end()
    } else {
      req.end(body)
    }
  })
}

async function openPollingSession (query: string): Promise<string> {
  const response = await request({
    host: '127.0.0.1',
    port,
    method: 'GET',
    path: `/socket.io/?${query}`
  })
  assert.equal(response.statusCode, 200)
  const sid = /"sid":"([^"]+)"/.exec(response.body.replace(/\\"/g, '"'))?.[1]
  assert.ok(sid, `polling handshake did not return a session id: ${response.body}`)
  return sid
}

async function postPolling (sid: string, headers: http.OutgoingHttpHeaders, body: Buffer | string, extraQuery = '') {
  return await request({
    host: '127.0.0.1',
    port,
    method: 'POST',
    path: `/socket.io/?EIO=4&transport=polling&sid=${encodeURIComponent(sid)}${extraQuery}`,
    headers
  }, body)
}

void describe('Engine.IO polling binary POST', () => {
  void it('completes a normal text polling POST from an unauthenticated client', async () => {
    const sid = await openPollingSession('EIO=4&transport=polling')
    const response = await postPolling(sid, {
      'Content-Type': 'text/plain;charset=UTF-8'
    }, '2')
    assert.equal(response.statusCode, 200)
    assert.equal(response.body, 'ok')
  })

  void it('closes the response to an invalid application/octet-stream polling POST', async () => {
    const sid = await openPollingSession('EIO=4&transport=polling')
    const response = await postPolling(sid, {
      'Content-Type': 'application/octet-stream'
    }, Buffer.from([0x04, 0xff, 0x00, 0x01]))
    assert.equal(response.statusCode, 400)
    assert.notEqual(response.body, 'ok')
  })

  void it('closes the response to an invalid binary POST on the JSONP polling transport', async () => {
    const sid = await openPollingSession('EIO=4&transport=polling&j=1')
    const response = await postPolling(sid, {
      'Content-Type': 'application/octet-stream'
    }, Buffer.from([0x04, 0xff, 0x00, 0x01]), '&j=1')
    assert.equal(response.statusCode, 400)
    assert.notEqual(response.body, 'ok')
  })
})
