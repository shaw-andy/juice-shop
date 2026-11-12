/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function logsDir () {
  return path.resolve('logs')
}

function accessLogNames () {
  return fs.readdirSync(logsDir()).filter((name) => name.startsWith('access.log.'))
}

async function waitForProbe (marker: string) {
  const probe = await request(app)
    .get('/api/Products')
    .query({ probe: marker })
    .set('User-Agent', 'log-disclosure-probe')

  assert.equal(probe.status, 200)

  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    for (const name of fs.readdirSync(logsDir())) {
      const full = path.join(logsDir(), name)
      if (!fs.statSync(full).isFile()) continue
      const contents = fs.readFileSync(full, 'utf8')
      if (!contents.includes(marker) || !contents.includes('log-disclosure-probe')) continue
      assert.match(contents, new RegExp('"GET /api/Products\\?probe=' + marker + ' HTTP/1\\.1"'))
      return { filename: name, contents }
    }
    await new Promise((resolve) => { setTimeout(resolve, 25) })
  }
  assert.fail('combined access log did not record the probe request')
}

function responseText (res: Response) {
  if (typeof res.text === 'string') return res.text
  if (Buffer.isBuffer(res.body)) return res.body.toString('utf8')
  if (typeof res.body === 'string') return res.body
  if (res.body == null) return ''
  return JSON.stringify(res.body)
}

function responseLeaksMarker (res: Response, marker: string) {
  const body = responseText(res)
  return body.includes(marker) || body.includes('log-disclosure-probe')
}

void describe('unauthenticated access log disclosure', { concurrency: false }, () => {
  void it('does not return combined access log lines for any method on /support/logs/:file', async () => {
    const marker = 'probe-' + crypto.randomUUID()
    const { filename, contents } = await waitForProbe(marker)
    const url = '/support/logs/' + filename
    const leaked: string[] = []

    for (const method of ['get', 'head', 'post', 'put', 'patch', 'delete', 'options'] as const) {
      const res = await request(app)[method](url).set('User-Agent', 'log-disclosure-client')
      if (method === 'head') {
        const size = fs.statSync(path.join(logsDir(), filename)).size
        const length = Number(res.headers['content-length'])
        if (res.status === 200 && length === size && size === Buffer.byteLength(contents)) leaked.push(method)
        continue
      }
      if (responseLeaksMarker(res, marker) || responseText(res) === contents) leaked.push(method)
    }

    assert.deepEqual(leaked, [])
  })

  void it('does not return access log lines to a non-admin bearer token', async () => {
    const marker = 'probe-' + crypto.randomUUID()
    const { filename } = await waitForProbe(marker)
    const token = security.authorize({ data: { role: security.roles.customer } })
    const res = await request(app)
      .get('/support/logs/' + filename)
      .set('Authorization', 'Bearer ' + token)

    assert.equal(responseLeaksMarker(res, marker), false)
  })

  void it('does not return access log lines to a placeholder bearer token', async () => {
    const marker = 'probe-' + crypto.randomUUID()
    const { filename } = await waitForProbe(marker)
    const res = await request(app)
      .get('/support/logs/' + filename)
      .set('Authorization', 'Bearer placeholder')

    assert.equal(responseLeaksMarker(res, marker), false)
  })

  void it('does not return other files stored in the logs directory', async () => {
    const auditPath = path.join(logsDir(), 'audit.json')
    const audit = fs.readFileSync(auditPath, 'utf8')
    assert.equal(audit.includes('access.log'), true)
    const res = await request(app).get('/support/logs/audit.json')

    assert.equal(responseText(res) === audit, false)
  })

  void it('does not list access logs from /support/logs', async () => {
    const names = accessLogNames()
    assert.ok(names.length > 0)
    const listed: string[] = []

    for (const url of ['/support/logs', '/support/logs/']) {
      for (const accept of ['text/html', 'application/json', 'text/plain']) {
        const res = await request(app).get(url).set('Accept', accept)
        const body = responseText(res)
        if (names.some((name) => body.includes(name))) listed.push('GET ' + url + ' ' + accept)

        const head = await request(app).head(url).set('Accept', accept)
        const headBody = responseText(head)
        const headLength = Number(head.headers['content-length'])
        const headListsLog = names.some((name) => headBody.includes(name)) ||
          (head.status === 200 && names.some((name) => body.includes(name)) && headLength === Buffer.byteLength(body))
        if (headListsLog) listed.push('HEAD ' + url + ' ' + accept)
      }
    }

    assert.deepEqual(listed, [])
  })
})
