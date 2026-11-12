/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import type { AddressInfo } from 'node:net'
import { createTestApp } from './helpers/setup'

const SHORTCUT_NAMES = [
  'juicy_malware_linux_amd_64.url',
  'juicy_malware_linux_arm_64.url',
  'juicy_malware_macos_64.url',
  'juicy_malware_windows_64.exe.url'
]

const PLACED_SHORTCUT = 'placeholder-lure.url'
const PLACED_BODY = '[InternetShortcut]\nURL=http://placeholder.invalid/sample\n'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  fs.rmSync(path.resolve('ftp/quarantine', PLACED_SHORTCUT), { force: true })
})

function responseText (res: request.Response): string {
  if (typeof res.text === 'string' && res.text.length > 0) return res.text
  if (Buffer.isBuffer(res.body)) return res.body.toString('utf8')
  if (typeof res.body === 'string') return res.body
  return ''
}

function assertDoesNotDeliverShortcut (status: number, body: string) {
  assert.notEqual(status, 200)
  assert.notEqual(status, 206)
  assert.equal(body.includes('[InternetShortcut]'), false)
  assert.equal(/^URL=/m.test(body), false)
}

function assertListingHidesShortcuts (body: string) {
  for (const name of SHORTCUT_NAMES) {
    assert.equal(body.includes(name), false, name)
  }
  assert.equal(body.includes(PLACED_SHORTCUT), false)
}

interface RawResponse {
  status: number
  body: string
}

function rawRequest (method: string, requestPath: string, headers: Record<string, string> = {}): Promise<RawResponse> {
  const server = http.createServer(app)
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo
      const req = http.request({
        hostname: '127.0.0.1',
        port: address.port,
        path: requestPath,
        method,
        headers
      }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          server.close(() => {
            resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') })
          })
        })
      })
      req.on('error', (err) => {
        server.close(() => reject(err))
      })
      req.end()
    })
  })
}

void describe('quarantine malware shortcuts are not public', () => {
  for (const name of SHORTCUT_NAMES) {
    void it('GET /ftp/quarantine/' + name + ' without credentials does not deliver the shortcut', async () => {
      const res = await request(app).get('/ftp/quarantine/' + name)
      assertDoesNotDeliverShortcut(res.status, responseText(res))
    })

    void it('HEAD /ftp/quarantine/' + name + ' without credentials does not offer the shortcut', async () => {
      const res = await request(app).head('/ftp/quarantine/' + name)
      assert.notEqual(res.status, 200)
      assert.notEqual(res.status, 206)
    })
  }

  void it('GET with a percent-encoded dot still does not deliver the decoded shortcut', async () => {
    const encoded = '/ftp/quarantine/' + SHORTCUT_NAMES[0].replace('.', '%2E')
    const res = await rawRequest('GET', encoded)
    assertDoesNotDeliverShortcut(res.status, res.body)
  })

  void it('GET with a query string still does not deliver the shortcut', async () => {
    const res = await request(app).get('/ftp/quarantine/' + SHORTCUT_NAMES[1] + '?download=1')
    assertDoesNotDeliverShortcut(res.status, responseText(res))
  })

  void it('GET with a byte range does not return shortcut bytes', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/' + SHORTCUT_NAMES[3])
      .set('Range', 'bytes=0-80')
      .buffer(true)
    assertDoesNotDeliverShortcut(res.status, responseText(res))
  })

  void it('a shortcut placed in the quarantine directory is not delivered either', async () => {
    const filePath = path.resolve('ftp/quarantine', PLACED_SHORTCUT)
    fs.writeFileSync(filePath, PLACED_BODY)
    try {
      const res = await request(app).get('/ftp/quarantine/' + PLACED_SHORTCUT)
      assertDoesNotDeliverShortcut(res.status, responseText(res))
      assert.equal(responseText(res).includes('placeholder.invalid'), false)
    } finally {
      fs.rmSync(filePath, { force: true })
    }
  })

  for (const accept of ['text/html', 'text/plain', 'application/json']) {
    void it('GET /ftp/quarantine listing as ' + accept + ' does not reveal shortcut names', async () => {
      const res = await request(app).get('/ftp/quarantine').set('Accept', accept)
      assertListingHidesShortcuts(responseText(res))
    })

    void it('GET /ftp listing as ' + accept + ' does not reveal the quarantine directory', async () => {
      const res = await request(app).get('/ftp').set('Accept', accept)
      const body = responseText(res)
      assert.equal(body.includes('quarantine'), false)
      assertListingHidesShortcuts(body)
    })
  }
})
