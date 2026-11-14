/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const password = 'placeholder-password'

let app: Express
let ownerToken: string
let otherToken: string
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  await register(app, { email: 'confirmation-owner@example.test', password })
  await register(app, { email: 'confirmation-other@example.test', password })
  const owner = await login(app, { email: 'confirmation-owner@example.test', password })
  ownerToken = owner.token
  otherToken = (await login(app, { email: 'confirmation-other@example.test', password })).token

  const headers = { Authorization: 'Bearer ' + ownerToken, 'content-type': 'application/json' }
  await request(app).post('/api/BasketItems').set(headers).send({ BasketId: owner.bid, ProductId: 1, quantity: 1 })
  const checkout = await request(app).post('/rest/basket/' + owner.bid + '/checkout').set(headers).send({})
  assert.equal(checkout.status, 200)
  orderId = checkout.body.orderConfirmation
}, { timeout: 60000 })

after(async () => {
  await fs.unlink(path.join('data/orders', 'order_' + orderId + '.pdf')).catch(() => {})
})

void describe('/rest/order-confirmation/:id', () => {
  void it('GET confirmation PDF of own order', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/' + orderId)
      .set('Authorization', 'Bearer ' + ownerToken)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET confirmation PDF of another customer order is not found', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/' + orderId)
      .set('Authorization', 'Bearer ' + otherToken)

    assert.equal(res.status, 404)
  })

  void it('GET confirmation PDF without authentication is rejected', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/' + orderId)

    assert.equal(res.status, 401)
  })

  void it('GET confirmation PDF is not served from the public ftp folder', async () => {
    const res = await request(app)
      .get('/ftp/order_' + orderId + '.pdf')

    assert.notEqual(res.status, 200)
  })
})
