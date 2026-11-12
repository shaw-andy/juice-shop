/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

const placeholderPassword = 'placeholder-password'
const addressId = 88001

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface ExportedOrder {
  orderId: string
  totalPrice: number
  bonus: number
  products: Array<{ quantity: number, name: string, price: number, total: number, bonus: number }>
  eta: string
  addressId?: number
}

interface StoredOrder extends ExportedOrder {
  email?: string
  paymentId?: string
  delivered?: boolean
}

async function placeOrderFor (email: string) {
  await register(app, { email, password: placeholderPassword })
  const { token, bid } = await login(app, { email, password: placeholderPassword })
  const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

  const itemRes = await request(app)
    .post('/api/BasketItems')
    .set(authHeader)
    .send({ BasketId: bid, ProductId: 1, quantity: 1 })
  assert.equal(itemRes.status, 200)

  const checkoutRes = await request(app)
    .post('/rest/basket/' + bid + '/checkout')
    .set(authHeader)
    .send({ orderDetails: { addressId, paymentId: 'pay-ref', deliveryMethodId: 1 } })
  assert.equal(checkoutRes.status, 200)
  assert.equal(typeof checkoutRes.body.orderConfirmation, 'string')

  return { token, authHeader, orderId: checkoutRes.body.orderConfirmation as string }
}

void describe('orders owned by a vowel-masked email', () => {
  void it('data export returns the caller order and not an order stored for an address that differs only by vowels', async () => {
    const domain = config.get<string>('application.domain')
    const victimEmail = 'cad@' + domain
    const attackerEmail = 'cid@' + domain
    const victim = await placeOrderFor(victimEmail)

    await register(app, { email: attackerEmail, password: placeholderPassword })
    const attacker = await login(app, { email: attackerEmail, password: placeholderPassword })
    const attackerHeader = { Authorization: 'Bearer ' + attacker.token, 'content-type': 'application/json' }

    const victimExport = await request(app)
      .post('/rest/user/data-export')
      .set(victim.authHeader)
      .send({})
    assert.equal(victimExport.status, 200)
    const victimOrders = JSON.parse(victimExport.body.userData).orders as ExportedOrder[]
    const ownOrder = victimOrders.find((order) => order.orderId === victim.orderId)
    assert.ok(ownOrder)
    assert.equal(ownOrder.products.length, 1)
    assert.equal(typeof ownOrder.totalPrice, 'number')
    assert.equal(typeof ownOrder.bonus, 'number')

    const attackerExport = await request(app)
      .post('/rest/user/data-export')
      .set(attackerHeader)
      .send({})
    assert.equal(attackerExport.status, 200)
    const exported = JSON.parse(attackerExport.body.userData) as { email: string, orders: ExportedOrder[] }
    assert.equal(exported.email, attackerEmail)
    const leaked = exported.orders.filter((order) => order.orderId === victim.orderId)
    assert.deepEqual(leaked, [])
  })

  void it('order history returns the caller order and not an order stored for an address that differs only by vowels', async () => {
    const domain = config.get<string>('application.domain')
    const victimEmail = 'pad@' + domain
    const attackerEmail = 'pid@' + domain
    const victim = await placeOrderFor(victimEmail)

    await register(app, { email: attackerEmail, password: placeholderPassword })
    const attacker = await login(app, { email: attackerEmail, password: placeholderPassword })
    const attackerHeader = { Authorization: 'Bearer ' + attacker.token, 'content-type': 'application/json' }

    const victimHistory = await request(app)
      .get('/rest/order-history')
      .set(victim.authHeader)
    assert.equal(victimHistory.status, 200)
    const ownOrder = (victimHistory.body.data as StoredOrder[]).find((order) => order.orderId === victim.orderId)
    assert.ok(ownOrder)
    assert.equal(ownOrder.addressId, addressId)
    assert.equal(ownOrder.products.length, 1)
    assert.equal(typeof ownOrder.totalPrice, 'number')
    assert.equal(typeof ownOrder.bonus, 'number')
    assert.equal(ownOrder.paymentId, 'pay-ref')

    const attackerHistory = await request(app)
      .get('/rest/order-history')
      .set(attackerHeader)
    assert.equal(attackerHistory.status, 200)
    const leaked = (attackerHistory.body.data as StoredOrder[]).filter((order) => order.orderId === victim.orderId)
    assert.deepEqual(leaked, [])
  })
})
