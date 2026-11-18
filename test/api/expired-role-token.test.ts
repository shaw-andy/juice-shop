/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'
import * as security from '../../lib/insecurity'
import { ordersCollection } from '../../data/mongodb'
import { BasketItemModel } from '../../models/basketitem'
import { DeliveryModel } from '../../models/delivery'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'

const SIX_HOURS_MS = 6 * 60 * 60 * 1000
const jsonHeader = { 'content-type': 'application/json' }

let app: Express
let users: StaticUser[]

before(async () => {
  const result = await createTestApp()
  app = result.app
  users = await loadStaticUserData()
}, { timeout: 60000 })

function credentials (key: string) {
  const user = users.find((entry) => entry.key === key)
  assert.ok(user, 'seed user ' + key)
  const domain = config.get<string>('application.domain')
  const email = user.customDomain === true ? user.email : user.email + '@' + domain
  return { email, password: user.password }
}

async function loginAs (key: string) {
  return await login(app, credentials(key))
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, ...jsonHeader }
}

function forgetSessions () {
  for (const token of Object.keys(security.authenticatedUsers.tokenMap)) {
    delete security.authenticatedUsers.tokenMap[token]
  }
  for (const id of Object.keys(security.authenticatedUsers.idMap)) {
    delete security.authenticatedUsers.idMap[id]
  }
}

async function afterSixHourLifetime (token: string, run: () => Promise<void>) {
  const decoded = security.decode(token) as { iat?: number } | null
  assert.equal(typeof decoded?.iat, 'number')
  const pastLifetime = (decoded.iat * 1000) + SIX_HOURS_MS + 60 * 1000
  mock.timers.enable({ apis: ['Date'], now: pastLifetime })
  try {
    assert.ok(Date.now() > (decoded.iat * 1000) + SIX_HOURS_MS)
    await run()
  } finally {
    mock.timers.reset()
  }
}

async function withChangedPassword (token: string, key: string, run: () => Promise<void>) {
  const { email, password } = credentials(key)
  const replacement = 'replacement-' + Math.random().toString(36).slice(2)
  const res = await request(app)
    .get('/rest/user/change-password')
    .set(bearer(token))
    .query({ current: password, new: replacement, repeat: replacement })
  try {
    if (res.status !== 200) {
      throw new Error('password change failed with status ' + res.status)
    }
    await run()
  } finally {
    const user = await UserModel.findOne({ where: { email } })
    assert.ok(user)
    await user.update({ password })
  }
}

function assertDenied (res: Response) {
  assert.ok(res.status === 401 || res.status === 403, 'privileged request was not denied: ' + res.status)
}

async function orderState () {
  const orders = await ordersCollection.find()
  return orders.map((order: { _id: unknown, delivered: unknown, eta: unknown }) => ({
    id: String(order._id),
    delivered: order.delivered,
    eta: order.eta
  }))
}

async function deliveryPrices (token: string, url: string) {
  return await request(app).get(url).set(bearer(token))
}

async function assertRegularDeliveryPrice (token: string, url: string) {
  const customer = await loginAs('jim')
  const regular = await deliveryPrices(customer.token, url)
  assert.equal(regular.status, 200)
  const res = await deliveryPrices(token, url)
  if (res.status === 401 || res.status === 403) {
    return
  }
  assert.equal(res.status, 200)
  assert.equal(res.body.data.length, regular.body.data.length)
  for (let i = 0; i < regular.body.data.length; i++) {
    assert.equal(res.body.data[i].id, regular.body.data[i].id)
    assert.equal(res.body.data[i].price, regular.body.data[i].price)
  }
}

async function limitedProduct () {
  const quantity = await QuantityModel.findOne({ where: { limitPerUser: 5 } })
  assert.ok(quantity)
  const product = await ProductModel.findByPk(quantity.ProductId)
  assert.ok(product)
  return { productId: product.id, limit: quantity.limitPerUser as number }
}

async function assertPurchaseCap (token: string, basketId: number) {
  const { productId, limit } = await limitedProduct()
  await BasketItemModel.destroy({ where: { BasketId: basketId, ProductId: productId } })
  const before = await BasketItemModel.count({ where: { BasketId: basketId, ProductId: productId } })
  const res = await request(app)
    .post('/api/BasketItems')
    .set(bearer(token))
    .send({ BasketId: basketId, ProductId: productId, quantity: limit + 1 })
  const after = await BasketItemModel.count({ where: { BasketId: basketId, ProductId: productId } })
  assertDenied(res)
  assert.equal(after, before)
}

async function assertRegularCheckout (token: string, basketId: number) {
  const product = await ProductModel.findOne({ where: { name: 'Orange Juice (1000ml)' } })
  const delivery = await DeliveryModel.findOne({ where: { name: 'One Day Delivery' } })
  assert.ok(product)
  assert.ok(delivery)
  assert.notEqual(Number(product.deluxePrice), Number(product.price))
  assert.notEqual(Number(delivery.deluxePrice), Number(delivery.price))
  await BasketItemModel.destroy({ where: { BasketId: basketId } })
  const added = await request(app)
    .post('/api/BasketItems')
    .set(bearer(token))
    .send({ BasketId: basketId, ProductId: product.id, quantity: 1 })
  assert.equal(added.status, 200)
  const beforeIds = new Set((await ordersCollection.find()).map((order: { _id: unknown }) => String(order._id)))
  const ftpBefore = new Set(fs.readdirSync('ftp'))
  const res = await request(app)
    .post('/rest/basket/' + basketId + '/checkout')
    .set(bearer(token))
    .send({ orderDetails: { deliveryMethodId: delivery.id, paymentId: 'card' } })
  const created = (await ordersCollection.find()).filter((order: { _id: unknown }) => !beforeIds.has(String(order._id)))
  const newPdfs = fs.readdirSync('ftp').filter((name) => name.endsWith('.pdf') && !ftpBefore.has(name))
  try {
    if (res.status === 401 || res.status === 403) {
      assert.equal(created.length, 0)
      assert.equal(newPdfs.length, 0)
      return
    }
    assert.equal(res.status, 200)
    assert.equal(created.length, 1)
    const order = created[0] as { products: Array<{ price: number }>, deliveryPrice: number }
    assert.equal(Number(order.products[0].price), Number(product.price))
    assert.equal(Number(order.deliveryPrice), Number(delivery.price))
  } finally {
    for (const name of newPdfs) {
      fs.unlinkSync(path.join('ftp', name))
    }
  }
}

async function assertAccountingOrdersDenied (token: string) {
  const res = await request(app).get('/rest/order-history/orders').set(bearer(token))
  assertDenied(res)
  assert.equal(res.body?.data, undefined)
}

async function assertDeliveryStatusUnchanged (token: string) {
  const before = await orderState()
  assert.ok(before.length > 0)
  const target = before[0]
  const res = await request(app)
    .put('/rest/order-history/' + target.id + '/delivery-status')
    .set(bearer(token))
    .send({ deliveryStatus: target.delivered })
  const after = await orderState()
  assertDenied(res)
  assert.deepEqual(after, before)
}

async function assertQuantityRouteDenied (token: string) {
  const res = await request(app).get('/api/Quantitys/1').set(bearer(token))
  assert.equal(res.status, 403)
  assert.equal(res.body.error, 'Malicious activity detected')
}

void describe('accounting bearer tokens', () => {
  void it('still allows a fresh in-session accounting token to read orders', async () => {
    const { token } = await loginAs('accountant')
    const res = await request(app).get('/rest/order-history/orders').set(bearer(token))
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length > 0)
  })

  for (const [name, arrange] of accountingCases()) {
    void it('rejects order history ' + name, async () => {
      const { token } = await loginAs('accountant')
      await arrange(token, 'accountant', async () => { await assertAccountingOrdersDenied(token) })
    })

    void it('rejects delivery status updates ' + name, async () => {
      const { token } = await loginAs('accountant')
      await arrange(token, 'accountant', async () => { await assertDeliveryStatusUnchanged(token) })
    })

    void it('rejects the quantity route ' + name, async () => {
      const { token } = await loginAs('accountant')
      await arrange(token, 'accountant', async () => { await assertQuantityRouteDenied(token) })
    })
  }
})

type Arrange = (token: string, key: string, run: () => Promise<void>) => Promise<void>

function accountingCases (): Array<[string, Arrange]> {
  return [
    ['after the six hour lifetime', async (token, _key, run) => { await afterSixHourLifetime(token, run) }],
    ['after the password changes', async (token, key, run) => { await withChangedPassword(token, key, run) }],
    ['after the in-memory session list is cleared', async (_token, _key, run) => { forgetSessions(); await run() }]
  ]
}

void describe('deluxe bearer tokens', () => {
  void it('still gives a fresh in-session deluxe token the deluxe delivery price', async () => {
    const { token } = await loginAs('ciso')
    const customer = await loginAs('jim')
    const deluxe = await deliveryPrices(token, '/api/Deliverys')
    const regular = await deliveryPrices(customer.token, '/api/Deliverys')
    assert.equal(deluxe.status, 200)
    assert.equal(regular.status, 200)
    assert.notEqual(deluxe.body.data[0].price, regular.body.data[0].price)
  })

  for (const [name, arrange] of accountingCases()) {
    void it('charges regular delivery prices ' + name, async () => {
      const { token } = await loginAs('ciso')
      await arrange(token, 'ciso', async () => {
        await assertRegularDeliveryPrice(token, '/api/Deliverys')
        await assertRegularDeliveryPrice(token, '/api/Deliverys/1')
      })
    })

    void it('enforces the per-customer purchase cap on insert ' + name, async () => {
      const { token, bid } = await loginAs('ciso')
      await arrange(token, 'ciso', async () => { await assertPurchaseCap(token, bid) })
    })

    void it('enforces the per-customer purchase cap on update ' + name, async () => {
      const { token, bid } = await loginAs('ciso')
      const { productId } = await limitedProduct()
      await BasketItemModel.destroy({ where: { BasketId: bid, ProductId: productId } })
      const created = await request(app)
        .post('/api/BasketItems')
        .set(bearer(token))
        .send({ BasketId: bid, ProductId: productId, quantity: 1 })
      assert.equal(created.status, 200)
      const itemId = created.body.data.id
      await arrange(token, 'ciso', async () => {
        const { limit } = await limitedProduct()
        const res = await request(app)
          .put('/api/BasketItems/' + itemId)
          .set(bearer(token))
          .send({ quantity: limit + 1 })
        const stored = await BasketItemModel.findByPk(itemId)
        assertDenied(res)
        assert.equal(stored?.quantity, 1)
      })
    })

    void it('charges regular checkout prices ' + name, async () => {
      const { token, bid } = await loginAs('ciso')
      await arrange(token, 'ciso', async () => { await assertRegularCheckout(token, bid) })
    })

    void it('does not keep deluxe membership ' + name, async () => {
      const { token } = await loginAs('ciso')
      await arrange(token, 'ciso', async () => {
        const membership = await request(app).get('/rest/deluxe-membership').set(bearer(token))
        assert.notEqual(membership.body?.error, 'You are already a deluxe member!')
      })
    })
  }

  void it('does not treat a customer token as a customer after the six hour lifetime', async () => {
    const { token } = await loginAs('jim')
    await afterSixHourLifetime(token, async () => {
      const res = await request(app).get('/rest/deluxe-membership').set(bearer(token))
      assert.equal(res.body?.data?.membershipCost, undefined)
    })
  })
})
