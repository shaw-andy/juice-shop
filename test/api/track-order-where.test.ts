/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { ordersCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'

let app: Express

const probeEmail = 'probe-buyer@example.test'
const probeProduct = 'Probe Juice'
const probeAddressId = 867530901

interface StoredOrder {
  orderId?: string
  email?: string
  totalPrice?: number
  addressId?: number
  products?: Array<{ name?: string, quantity?: number, price?: number, total?: number }>
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  await ordersCollection.insert({
    orderId: 'probe-track-order',
    email: probeEmail,
    totalPrice: 4.25,
    bonus: 0,
    products: [{ quantity: 1, name: probeProduct, price: 4.25, total: 4.25 }],
    addressId: probeAddressId,
    eta: '2',
    delivered: false
  })
}, { timeout: 60000 })

void describe('/rest/track-order/:id where-clause', () => {
  void it('returns only the order whose orderId equals the requested id', async () => {
    const stored = await ordersCollection.find({}) as StoredOrder[]
    assert.ok(stored.length >= 2)
    const target = stored.find((order) => order.orderId === 'probe-track-order')
    const other = stored.find((order) => order.orderId !== 'probe-track-order' && typeof order.email === 'string')
    assert.ok(target?.orderId)
    assert.ok(other?.email)
    assert.notEqual(target.orderId, other.orderId)

    const res = await request(app).get('/rest/track-order/' + encodeURIComponent(target.orderId))

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.ok(Array.isArray(res.body.data))
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, target.orderId)
    assert.equal(res.body.data[0].email, target.email)
    assert.equal(res.body.data[0].totalPrice, target.totalPrice)
    assert.equal(res.body.data[0].addressId, probeAddressId)
    assert.equal(res.body.data[0].products[0].name, probeProduct)
    assert.equal(JSON.stringify(res.body).includes(other.email), false)
  })

  void it('does not return stored orders when the id closes the quoted comparison', async () => {
    await assertBreakoutDoesNotLeak("' || true || '")
  })

  void it('does not return stored orders when the id omits spaces around the operators', async () => {
    await assertBreakoutDoesNotLeak("'||true||'")
  })

  void it('does not return stored orders when the id reads another order field', async () => {
    const breakout = "' || this.totalPrice >= 0 || '"
    assert.ok(breakout.length <= 60)
    await assertBreakoutDoesNotLeak(breakout)
  })

  void it('does not return stored orders when a bearer token is sent with the breakout id', async () => {
    await assertBreakoutDoesNotLeak("' || true || '", { authorization: 'Bearer ' + security.authorize() })
  })
})

async function assertBreakoutDoesNotLeak (id: string, headers?: { authorization: string }) {
  const stored = await ordersCollection.find({}) as StoredOrder[]
  assert.ok(stored.length >= 2)
  const req = request(app).get('/rest/track-order/' + encodeURIComponent(id))
  if (headers !== undefined) {
    req.set('Authorization', headers.authorization)
  }
  const res = await req
  const serialized = JSON.stringify(res.body)

  assert.ok(res.status === 200 || res.status === 400)
  assert.equal(serialized.includes(probeEmail), false)
  assert.equal(serialized.includes(probeProduct), false)
  assert.equal(serialized.includes(String(probeAddressId)), false)
  for (const order of stored) {
    if (typeof order.email === 'string' && order.orderId !== id) {
      assert.equal(serialized.includes(order.email), false)
    }
    for (const product of order.products ?? []) {
      if (typeof product.name === 'string') {
        assert.equal(serialized.includes(product.name), false)
      }
    }
  }
  if (res.status === 200) {
    assert.equal(res.body.status, 'success')
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length <= 1)
    const leaked = res.body.data.filter((row: StoredOrder) => {
      return row.orderId !== id && (row.email !== undefined || row.products !== undefined || row.totalPrice !== undefined || row.addressId !== undefined)
    })
    assert.equal(leaked.length, 0)
  }
}
