/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { UserModel } from '../../models/user'
import { QuantityModel } from '../../models/quantity'
import { DeliveryModel } from '../../models/delivery'
import { BasketItemModel } from '../../models/basketitem'
import { ordersCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'

const placeholderPassword = 'placeholder-password'
const jsonHeader = { 'content-type': 'application/json' }
const customerProfileImage = '/assets/public/images/uploads/default.svg'

let app: Express
let sequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface TokenPayload {
  data?: {
    role?: string
    email?: string
    deluxeToken?: string
  }
}

function payloadFromLoginToken (token: string): TokenPayload {
  const part = token.split('.')[1]
  let output = part.replace(/-/g, '+').replace(/_/g, '/')
  switch (output.length % 4) {
    case 2:
      output += '=='
      break
    case 3:
      output += '='
      break
    default:
      break
  }
  const decoded = decodeURIComponent(atob(output).replace(/(.)/g, (_match, char: string) => {
    let code = char.charCodeAt(0).toString(16).toUpperCase()
    if (code.length < 2) {
      code = '0' + code
    }
    return '%' + code
  }))
  return JSON.parse(decoded) as TokenPayload
}

function administrationGuardAllows (payload: TokenPayload) {
  return Boolean(payload?.data && payload.data.role === 'admin')
}

function accountingGuardAllows (payload: TokenPayload) {
  return Boolean(payload?.data && payload.data.role === 'accounting')
}

function deluxeGuardAllows (payload: TokenPayload) {
  return Boolean(payload?.data && payload.data.role === 'deluxe')
}

async function register (email: string, extra: Record<string, unknown>) {
  return await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email,
      password: placeholderPassword,
      ...extra
    })
}

async function storedUser (email: string) {
  return await UserModel.findOne({ where: { email } })
}

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function orderSnapshots () {
  const orders = await ordersCollection.find()
  return orders.map((order: { _id: string, delivered: boolean, eta: string }) => ({
    _id: String(order._id),
    delivered: order.delivered,
    eta: order.eta
  }))
}

void describe('public registration ignores a chosen role', { concurrency: 1 }, () => {
  void it('keeps an accounting registration as a customer and does not expose or change orders', async () => {
    const email = `accounting-${++sequence}@registration-role.test`
    const beforeOrders = await orderSnapshots()
    assert.ok(beforeOrders.length > 0)
    const target = beforeOrders[0]
    const quantityBefore = await QuantityModel.findByPk(1)
    assert.ok(quantityBefore)
    const quantityValue = quantityBefore.quantity

    const created = await register(email, { role: 'accounting', privilege: 'admin' })

    assert.equal(created.status, 201)
    assert.equal(created.body.data.role, 'customer')
    const user = await storedUser(email)
    assert.ok(user)
    assert.equal(user.role, 'customer')
    assert.equal(user.profileImage, customerProfileImage)

    const { token } = await login(app, { email, password: placeholderPassword })
    const payload = payloadFromLoginToken(token)
    const serverPayload = security.decode(token) as TokenPayload
    assert.equal(payload.data?.role, 'customer')
    assert.equal(serverPayload.data?.role, 'customer')
    assert.equal(accountingGuardAllows(payload), false)
    assert.equal(administrationGuardAllows(payload), false)

    const orders = await request(app)
      .get('/rest/order-history/orders')
      .set(authHeader(token))
    assert.equal(orders.status, 403)
    assert.equal(orders.body.error, 'Malicious activity detected')

    const delivery = await request(app)
      .put('/rest/order-history/' + target._id + '/delivery-status')
      .set(authHeader(token))
      .send({ deliveryStatus: target.delivered })
    assert.equal(delivery.status, 403)
    assert.equal(delivery.body.error, 'Malicious activity detected')
    assert.deepEqual(await orderSnapshots(), beforeOrders)

    const quantityRead = await request(app)
      .get('/api/Quantitys/1')
      .set(authHeader(token))
    assert.equal(quantityRead.status, 403)
    assert.equal(quantityRead.body.error, 'Malicious activity detected')

    const quantityWrite = await request(app)
      .put('/api/Quantitys/1')
      .set(authHeader(token))
      .send({ quantity: quantityValue + 1 })
    assert.equal(quantityWrite.status, 403)
    assert.equal(quantityWrite.body.error, 'Malicious activity detected')
    const quantityAfter = await QuantityModel.findByPk(1)
    assert.equal(quantityAfter?.quantity, quantityValue)
  })

  void it('keeps an accounting registration as a customer when passwordRepeat is sent', async () => {
    const email = `accounting-repeat-${++sequence}@registration-role.test`
    const created = await register(email, {
      passwordRepeat: placeholderPassword,
      role: 'accounting'
    })
    assert.equal(created.status, 201)
    assert.equal(created.body.data.role, 'customer')
    const user = await storedUser(email)
    assert.equal(user?.role, 'customer')
    const { token } = await login(app, { email, password: placeholderPassword })
    assert.equal(payloadFromLoginToken(token).data?.role, 'customer')
    assert.equal(accountingGuardAllows(payloadFromLoginToken(token)), false)
  })

  void it('keeps an admin registration as a customer so the administration guard stays closed', async () => {
    const email = `admin-${++sequence}@registration-role.test`
    const created = await register(email, { role: 'admin', privilege: 'admin' })
    assert.equal(created.status, 201)
    assert.equal(created.body.data.role, 'customer')
    assert.equal(created.body.data.profileImage, customerProfileImage)
    const user = await storedUser(email)
    assert.ok(user)
    assert.equal(user.role, 'customer')
    assert.equal(user.profileImage, customerProfileImage)

    const { token } = await login(app, { email, password: placeholderPassword })
    const payload = payloadFromLoginToken(token)
    assert.equal(payload.data?.role, 'customer')
    assert.equal(payload.data?.email, email)
    assert.equal(administrationGuardAllows(payload), false)
    assert.equal(accountingGuardAllows(payload), false)
  })

  void it('ignores a deluxe role, deluxe token, and privilege field', async () => {
    const email = `deluxe-${++sequence}@registration-role.test`
    const suppliedDeluxeToken = security.deluxeToken(email)
    const created = await register(email, {
      passwordRepeat: placeholderPassword,
      role: 'deluxe',
      deluxeToken: suppliedDeluxeToken,
      privilege: 'admin'
    })
    assert.equal(created.status, 201)
    assert.equal(created.body.data.role, 'customer')
    assert.ok(!created.body.data.deluxeToken)
    const user = await storedUser(email)
    assert.ok(user)
    assert.equal(user.role, 'customer')
    assert.ok(!user.deluxeToken)

    const { token, bid } = await login(app, { email, password: placeholderPassword })
    const payload = payloadFromLoginToken(token)
    assert.equal(payload.data?.role, 'customer')
    assert.ok(!payload.data?.deluxeToken)
    assert.equal(deluxeGuardAllows(payload), false)
    assert.equal(security.isDeluxe({ headers: { authorization: 'Bearer ' + token } } as never), false)

    const methods = await DeliveryModel.findAll()
    const list = await request(app)
      .get('/api/Deliverys')
      .set(authHeader(token))
    assert.equal(list.status, 200)
    for (const method of methods) {
      const listed = list.body.data.find((row: { id: number }) => row.id === method.id)
      assert.equal(listed.price, method.price)
    }
    const one = await request(app)
      .get('/api/Deliverys/1')
      .set(authHeader(token))
    const first = methods.find((method) => method.id === 1)
    assert.ok(first)
    assert.equal(one.status, 200)
    assert.equal(one.body.data.price, first.price)

    const limited = (await QuantityModel.findAll()).find((row) =>
      row.limitPerUser != null && row.quantity > row.limitPerUser
    )
    assert.ok(limited)
    const beforeCount = await BasketItemModel.count({ where: { BasketId: bid } })
    const overLimit = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({
        BasketId: bid,
        ProductId: limited.ProductId,
        quantity: limited.limitPerUser + 1
      })
    assert.equal(overLimit.status, 400)
    assert.equal(await BasketItemModel.count({ where: { BasketId: bid } }), beforeCount)
  })

  void it('still registers a customer when the body does not choose a role', async () => {
    const email = `customer-${++sequence}@registration-role.test`
    const created = await register(email, { passwordRepeat: placeholderPassword })
    assert.equal(created.status, 201)
    assert.equal(created.body.data.role, 'customer')
    const user = await storedUser(email)
    assert.equal(user?.role, 'customer')
    const { token } = await login(app, { email, password: placeholderPassword })
    const payload = payloadFromLoginToken(token)
    assert.equal(payload.data?.role, 'customer')
    assert.equal(administrationGuardAllows(payload), false)
    assert.equal(accountingGuardAllows(payload), false)
    assert.equal(deluxeGuardAllows(payload), false)
  })
})
