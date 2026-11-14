/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
  })

  void it('GET no orders by injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(Object.keys(res.body.data[0]), ['orderId'])
  })

  void it('GET no orders by injecting into orderId with a customer session', async () => {
    const email = 'track-result-injection@example.test'
    const password = 'placeholder-password'
    await register(app, { email, password })
    const { token } = await login(app, { email, password })
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
      .set('Authorization', 'Bearer ' + token)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(Object.keys(res.body.data[0]), ['orderId'])
  })
})
