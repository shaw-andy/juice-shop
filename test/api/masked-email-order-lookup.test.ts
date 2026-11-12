/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

const placeholderPassword = 'placeholder'

interface StoredOrder {
  orderId: string
  totalPrice: number
  eta: string
  paymentId: string | null
  addressId: string | null
  products: Array<{ quantity: number, name: string, price: number, total: number }>
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('order ownership is not a vowel-masked email', () => {
  void it('GET /rest/order-history returns only the authenticated customer orders', async () => {
    const placed = await placeOrderAs('pat.owner@example.test', 'payment-ref-owner', 'address-ref-owner')
    try {
      const ownerOrders = await orderHistory(placed.token)
      const own = ownerOrders.find((order) => order.orderId === placed.orderId)
      assert.ok(own, 'the customer who placed the order must still receive it')
      assert.equal(own.paymentId, 'payment-ref-owner')
      assert.equal(own.addressId, 'address-ref-owner')
      assert.equal(typeof own.totalPrice, 'number')
      assert.equal(typeof own.eta, 'string')
      assert.ok(own.products.length > 0)
      assert.equal(typeof own.products[0].name, 'string')
      assert.equal(typeof own.products[0].total, 'number')

      const other = await registerAndLogin('pet.awner@example.test')
      const otherOrders = await orderHistory(other.token)
      const leaked = otherOrders.find((order) => order.orderId === placed.orderId)
      assert.equal(
        leaked,
        undefined,
        `GET /rest/order-history returned another customer's order ${JSON.stringify(leaked)}`
      )
    } finally {
      await fs.rm(path.join('ftp', `order_${placed.orderId}.pdf`), { force: true })
    }
  })

  void it('POST /rest/user/data-export returns only the authenticated customer orders', async () => {
    const placed = await placeOrderAs('pat.owner2@example.test', 'payment-ref-owner-2', 'address-ref-owner-2')
    try {
      const ownerExport = await exportOrders(placed.token)
      assert.equal(ownerExport.email, 'pat.owner2@example.test')
      const own = ownerExport.orders.find((order) => order.orderId === placed.orderId)
      assert.ok(own, 'the customer who placed the order must still receive it from data export')
      assert.equal(typeof own.totalPrice, 'number')
      assert.equal(typeof own.eta, 'string')
      assert.ok(own.products.length > 0)
      assert.equal(typeof own.products[0].name, 'string')
      assert.equal(typeof own.products[0].total, 'number')

      const other = await registerAndLogin('pet.awner2@example.test')
      const otherExport = await exportOrders(other.token)
      const leaked = otherExport.orders.find((order) => order.orderId === placed.orderId)
      assert.equal(
        leaked,
        undefined,
        `POST /rest/user/data-export returned another customer's order ${JSON.stringify(leaked)}`
      )
    } finally {
      await fs.rm(path.join('ftp', `order_${placed.orderId}.pdf`), { force: true })
    }
  })
})

async function registerAndLogin (email: string) {
  await register(app, { email, password: placeholderPassword })
  return await login(app, { email, password: placeholderPassword })
}

async function placeOrderAs (email: string, paymentId: string, addressId: string) {
  const { token, bid } = await registerAndLogin(email)
  const auth = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

  const basketItem = await request(app)
    .post('/api/BasketItems')
    .set(auth)
    .send({ ProductId: 1, BasketId: bid, quantity: 1 })
  assert.equal(basketItem.status, 200, basketItem.text)

  const checkout = await request(app)
    .post(`/rest/basket/${bid}/checkout`)
    .set(auth)
    .send({ orderDetails: { paymentId, addressId } })
  assert.equal(checkout.status, 200, checkout.text)
  assert.equal(typeof checkout.body.orderConfirmation, 'string')

  return { token, orderId: checkout.body.orderConfirmation as string }
}

async function orderHistory (token: string): Promise<StoredOrder[]> {
  const res = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
  assert.equal(res.status, 200, res.text)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data as StoredOrder[]
}

async function exportOrders (token: string): Promise<{ email: string, orders: StoredOrder[] }> {
  const res = await request(app)
    .post('/rest/user/data-export')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({ format: '1' })
  assert.equal(res.status, 200, res.text)
  const parsed = JSON.parse(res.body.userData) as { email: string, orders: StoredOrder[] }
  assert.ok(Array.isArray(parsed.orders))
  return parsed
}
