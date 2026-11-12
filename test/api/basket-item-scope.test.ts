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

const placeholderPassword = 'placeholder-password'

interface BasketLine {
  id: number
  BasketId: number
  ProductId: number
  quantity: number
}

interface CustomerSession {
  token: string
  bid: number
}

let app: Express
let customerA: CustomerSession
let customerB: CustomerSession
let ownLine: BasketLine
let otherLine: BasketLine

function bearer (token: string) {
  return {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
}

function linesFrom (body: { data?: unknown }) {
  if (!Array.isArray(body?.data)) {
    return []
  }
  return body.data as BasketLine[]
}

async function addOwnLine (customer: CustomerSession, productId: number, quantity: number) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(bearer(customer.token))
    .send({ BasketId: customer.bid, ProductId: productId, quantity })
  assert.equal(res.status, 200)
  const line = res.body.data as BasketLine
  assert.equal(line.BasketId, customer.bid)
  assert.equal(line.ProductId, productId)
  assert.equal(line.quantity, quantity)
  return line
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const emailA = 'basket-scope-a@example.test'
  const emailB = 'basket-scope-b@example.test'
  await register(app, { email: emailA, password: placeholderPassword })
  await register(app, { email: emailB, password: placeholderPassword })
  customerA = await login(app, { email: emailA, password: placeholderPassword })
  customerB = await login(app, { email: emailB, password: placeholderPassword })
  assert.equal(typeof customerA.bid, 'number')
  assert.equal(typeof customerB.bid, 'number')
  assert.notEqual(customerA.bid, customerB.bid)

  ownLine = await addOwnLine(customerA, 1, 1)
  otherLine = await addOwnLine(customerB, 2, 1)
}, { timeout: 60000 })

void describe('basket item reads stay inside the signed-in customer basket', () => {
  void it('GET /api/BasketItems lists only lines from the caller basket', async () => {
    const res = await request(app)
      .get('/api/BasketItems')
      .set(bearer(customerA.token))

    assert.equal(res.status, 200)
    const lines = linesFrom(res.body)
    assert.ok(lines.some(line => line.id === ownLine.id && line.ProductId === ownLine.ProductId && line.quantity === ownLine.quantity))
    const foreignBasketIds = lines.filter(line => line.BasketId !== customerA.bid).map(line => line.BasketId)
    assert.deepEqual(foreignBasketIds, [])
  })

  void it('GET /api/BasketItems ignores a BasketId query for another customer', async () => {
    const res = await request(app)
      .get('/api/BasketItems')
      .query({ BasketId: customerB.bid })
      .set(bearer(customerA.token))

    const lines = linesFrom(res.body)
    const foreignBasketIds = lines.filter(line => line.BasketId !== customerA.bid).map(line => line.BasketId)
    assert.deepEqual(foreignBasketIds, [])
    assert.equal(lines.some(line => line.id === otherLine.id), false)
  })

  void it('GET /api/BasketItems/:id does not return another customer line', async () => {
    const res = await request(app)
      .get('/api/BasketItems/' + otherLine.id)
      .set(bearer(customerA.token))

    assert.notEqual(res.body?.data?.id, otherLine.id)
    assert.notEqual(res.body?.data?.BasketId, otherLine.BasketId)
    assert.ok([401, 403, 404].includes(res.status), 'status ' + res.status)
  })

  void it('GET /api/BasketItems/:id returns the caller own line', async () => {
    const res = await request(app)
      .get('/api/BasketItems/' + ownLine.id)
      .set(bearer(customerA.token))

    assert.equal(res.status, 200)
    assert.equal(res.body.data.id, ownLine.id)
    assert.equal(res.body.data.BasketId, customerA.bid)
    assert.equal(res.body.data.ProductId, ownLine.ProductId)
    assert.equal(res.body.data.quantity, ownLine.quantity)
  })

  void it('PUT /api/BasketItems/:id does not change another customer line', async () => {
    const target = await addOwnLine(customerA, 7, 1)
    const updatedQuantity = 2

    const putRes = await request(app)
      .put('/api/BasketItems/' + target.id)
      .set(bearer(customerB.token))
      .send({ quantity: updatedQuantity })

    const readBack = await request(app)
      .get('/api/BasketItems/' + target.id)
      .set(bearer(customerA.token))

    assert.equal(readBack.status, 200)
    assert.equal(readBack.body.data.quantity, target.quantity)
    assert.equal(readBack.body.data.BasketId, customerA.bid)
    assert.equal(readBack.body.data.ProductId, target.ProductId)
    assert.notEqual(putRes.status, 200)
    assert.notEqual(readBack.body.data.quantity, updatedQuantity)
  })

  void it('DELETE /api/BasketItems/:id does not remove another customer line', async () => {
    const target = await addOwnLine(customerA, 8, 1)

    const deleteRes = await request(app)
      .delete('/api/BasketItems/' + target.id)
      .set(bearer(customerB.token))

    const readBack = await request(app)
      .get('/api/BasketItems/' + target.id)
      .set(bearer(customerA.token))

    assert.equal(readBack.status, 200)
    assert.equal(readBack.body.data.id, target.id)
    assert.equal(readBack.body.data.quantity, target.quantity)
    assert.equal(readBack.body.data.BasketId, customerA.bid)
    assert.equal(readBack.body.data.ProductId, target.ProductId)
    assert.notEqual(deleteRes.status, 200)
  })
})
