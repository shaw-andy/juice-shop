/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as utils from '../../lib/utils'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const adminAuthorization = () => ({ Authorization: 'Bearer ' + security.authorize({ data: { role: security.roles.admin } }) })

void describe('/support/logs/:file', () => {
  void it('GET access log file for the current day', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))
      .set(adminAuthorization())

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/octet-stream'))
  })

  void it('GET access log file without authorization fails with a 403 error', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))

    assert.equal(res.status, 403)
  })

  void it('GET access log file as a customer fails with a 403 error', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))
      .set({ Authorization: 'Bearer ' + security.authorize({ data: { role: security.roles.customer } }) })

    assert.equal(res.status, 403)
  })

  void it('GET access log file with an unsigned admin token fails with a 403 error', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { role: security.roles.admin }, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))
      .set({ Authorization: 'Bearer ' + header + '.' + payload + '.' })

    assert.equal(res.status, 403)
  })

  void it('GET log directory listing without authorization fails with a 403 error', async () => {
    const res = await request(app)
      .get('/support/logs')

    assert.equal(res.status, 403)
  })

  void it('GET log file whose name contains a forward slash fails with a 403 error', async () => {
    const res = await request(app)
      .get('/support/logs/%2fetc%2fpasswd')
      .set(adminAuthorization())

    assert.equal(res.status, 403)
    assert.ok(res.text.includes('Error: File names cannot contain forward slashes!'))
  })
})
