/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import type { Request } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { BasketItemModel } from '../../models/basketitem'
import { DeliveryModel } from '../../models/delivery'
import { UserModel } from '../../models/user'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const password = 'placeholder-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function uniqueEmail () {
  return `client-deluxe-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
}

async function postRegistration (body: Record<string, string>) {
  return await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send(body)
}

async function registerWithClientDeluxeToken (includePasswordRepeat: boolean) {
  const email = uniqueEmail()
  const body: Record<string, string> = {
    email,
    password,
    role: security.roles.deluxe,
    deluxeToken: security.deluxeToken(email)
  }
  if (includePasswordRepeat) {
    body.passwordRepeat = password
  }
  const registration = await postRegistration(body)
  return { email, registration }
}

function assertRegistrationRejectedOrCreated (status: number) {
  if (status === 201) {
    return
  }
  assert.ok(status >= 400 && status < 500, `registration status ${status}`)
}

async function limitedProduct () {
  const product = await ProductModel.findOne({ where: { name: 'Apple Juice (1000ml)' } })
  assert.ok(product)
  assert.notEqual(Number(product.price), Number(product.deluxePrice))
  const stock = await QuantityModel.findOne({ where: { ProductId: product.id } })
  assert.ok(stock)
  assert.ok(stock.limitPerUser != null && stock.limitPerUser > 0)
  assert.ok(stock.quantity > stock.limitPerUser)
  return { product, stock, overLimit: stock.limitPerUser + 1 }
}

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

void describe('client-supplied deluxe membership', { concurrency: 1 }, () => {
  void it('does not let registration without passwordRepeat skip the per-user purchase cap', async () => {
    const { email, registration } = await registerWithClientDeluxeToken(false)
    assertRegistrationRejectedOrCreated(registration.status)
    if (registration.status !== 201) {
      return
    }
    assert.equal(registration.body.data.email, email)

    const { token, bid } = await login(app, { email, password })
    assert.equal(security.isDeluxe({ headers: { authorization: 'Bearer ' + token } } as unknown as Request), false)

    const { product, overLimit } = await limitedProduct()
    const before = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({ BasketId: bid, ProductId: product.id, quantity: overLimit })
    assert.equal(res.status, 400)
    const after = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    assert.equal(after, before)
  })

  void it('does not let registration that also sends passwordRepeat skip the per-user purchase cap', async () => {
    const { email, registration } = await registerWithClientDeluxeToken(true)
    assertRegistrationRejectedOrCreated(registration.status)
    if (registration.status !== 201) {
      return
    }
    assert.equal(registration.body.data.email, email)

    const { token, bid } = await login(app, { email, password })
    const { product, overLimit } = await limitedProduct()
    const before = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({ BasketId: bid, ProductId: product.id, quantity: overLimit })
    assert.equal(res.status, 400)
    const after = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    assert.equal(after, before)
  })

  void it('does not let a client deluxe token raise an existing basket line above the cap', async () => {
    const { email, registration } = await registerWithClientDeluxeToken(true)
    assertRegistrationRejectedOrCreated(registration.status)
    if (registration.status !== 201) {
      return
    }

    const { token, bid } = await login(app, { email, password })
    const { product, overLimit } = await limitedProduct()
    const created = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({ BasketId: bid, ProductId: product.id, quantity: 1 })
    assert.equal(created.status, 200)

    const updated = await request(app)
      .put('/api/BasketItems/' + created.body.data.id)
      .set(authHeader(token))
      .send({ quantity: overLimit })
    assert.equal(updated.status, 400)
    const row = await BasketItemModel.findByPk(created.body.data.id)
    assert.equal(row?.quantity, 1)
  })

  void it('charges list product and delivery prices after registration with a client deluxe token', async () => {
    const { email, registration } = await registerWithClientDeluxeToken(true)
    assertRegistrationRejectedOrCreated(registration.status)
    if (registration.status !== 201) {
      return
    }

    const { token, bid } = await login(app, { email, password })
    const { product } = await limitedProduct()
    const delivery = await DeliveryModel.findOne({ where: { name: 'One Day Delivery' } })
    assert.ok(delivery)
    assert.notEqual(Number(delivery.price), Number(delivery.deluxePrice))

    const added = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({ BasketId: bid, ProductId: product.id, quantity: 1 })
    assert.equal(added.status, 200)

    const checkout = await request(app)
      .post('/rest/basket/' + bid + '/checkout')
      .set(authHeader(token))
      .send({ orderDetails: { deliveryMethodId: delivery.id } })
    assert.equal(checkout.status, 200)
    const orderId = checkout.body.orderConfirmation
    assert.equal(typeof orderId, 'string')

    try {
      const history = await request(app)
        .get('/rest/order-history')
        .set(authHeader(token))
      assert.equal(history.status, 200)
      const order = history.body.data.find((entry: { orderId: string }) => entry.orderId === orderId)
      assert.ok(order)
      assert.equal(order.products.length, 1)
      assert.equal(Number(order.products[0].price), Number(product.price))
      assert.notEqual(Number(order.products[0].price), Number(product.deluxePrice))
      assert.equal(Number(order.deliveryPrice), Number(delivery.price))
      assert.notEqual(Number(order.deliveryPrice), Number(delivery.deluxePrice))
      const expectedTotal = Number(product.price) + Number(delivery.price)
      assert.equal(Number(order.totalPrice).toFixed(2), expectedTotal.toFixed(2))
    } finally {
      await fs.unlink(path.join('ftp', `order_${orderId}.pdf`)).catch(() => undefined)
    }
  })

  void it('does not apply a client deluxe token submitted to the user update route', async () => {
    const email = uniqueEmail()
    const registration = await postRegistration({ email, password })
    assert.equal(registration.status, 201)
    const userId = registration.body.data.id

    const { token, bid } = await login(app, { email, password })
    const update = await request(app)
      .put('/api/Users/' + userId)
      .set(authHeader(token))
      .send({
        role: security.roles.deluxe,
        deluxeToken: security.deluxeToken(email)
      })
    assert.equal(update.status, 401)

    const user = await UserModel.findByPk(userId)
    assert.equal(user?.role, security.roles.customer)
    assert.equal(security.isDeluxe({ headers: { authorization: 'Bearer ' + token } } as unknown as Request), false)

    const { product, overLimit } = await limitedProduct()
    const before = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({ BasketId: bid, ProductId: product.id, quantity: overLimit })
    assert.equal(res.status, 400)
    const after = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    assert.equal(after, before)
  })

  void it('does not apply a client deluxe token submitted to the profile form', async () => {
    const email = uniqueEmail()
    const registration = await postRegistration({ email, password })
    assert.equal(registration.status, 201)
    const userId = registration.body.data.id
    const { token, bid } = await login(app, { email, password })

    const profile = await request(app)
      .post('/profile')
      .set({ Cookie: `token=${token}`, 'content-type': 'application/json' })
      .send({
        username: 'placeholder-name',
        role: security.roles.deluxe,
        deluxeToken: security.deluxeToken(email)
      })
    assert.ok(profile.status === 302 || profile.status === 200)

    const user = await UserModel.findByPk(userId)
    assert.equal(user?.role, security.roles.customer)
    assert.equal(security.isDeluxe({ headers: { authorization: 'Bearer ' + token } } as unknown as Request), false)

    const { product, overLimit } = await limitedProduct()
    const before = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(token))
      .send({ BasketId: bid, ProductId: product.id, quantity: overLimit })
    assert.equal(res.status, 400)
    const after = await BasketItemModel.count({ where: { BasketId: bid, ProductId: product.id } })
    assert.equal(after, before)
  })
})
