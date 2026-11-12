/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/b2b/v2/orders', () => {
  void it('POST endless loop exploit in "orderLinesData" is rejected as invalid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: '(function dos() { while(true); })()'
      })

    assert.equal(res.status, 400)
    assert.equal(challenges.rceChallenge.solved, false)
  })

  void it('POST busy spinning regex attack in "orderLinesData" is rejected without being evaluated', async () => {
    const started = Date.now()
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
      })

    assert.equal(res.status, 400)
    assert.ok(Date.now() - started < 1000)
    assert.equal(challenges.rceOccupyChallenge.solved, false)
  })

  void it('POST sandbox breakout attack in "orderLinesData" is rejected as invalid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: 'this.constructor.constructor("return process")().exit()'
      })

    assert.equal(res.status, 400)
  })

  void it('POST non-string "orderLinesData" is rejected', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: { productId: 12 }
      })

    assert.equal(res.status, 400)
  })

  void it('POST JSON "orderLinesData" as documented in Swagger is accepted', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'JS0815DE',
        orderLinesData: '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'JS0815DE')
  })

  void it('POST new B2B order is forbidden without authorization token', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .send({})

    assert.equal(res.status, 401)
  })

  void it('POST new B2B order accepts arbitrary valid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        foo: 'bar',
        test: 42
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    if (res.body.cid !== undefined) assert.equal(typeof res.body.cid, 'string')
    assert.equal(typeof res.body.orderNo, 'string')
    assert.equal(typeof res.body.paymentDue, 'string')
  })

  void it('POST new B2B order has passed "cid" in response', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'test'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'test')
  })
})
