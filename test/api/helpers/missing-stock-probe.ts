/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import request from 'supertest'
import { createTestApp } from './setup'
import { login, register } from './auth'
import { BasketItemModel } from '../../../models/basketitem'
import { QuantityModel } from '../../../models/quantity'
import { UserModel } from '../../../models/user'

const placeholderPassword = 'placeholder-password'

function report (payload: Record<string, unknown>) {
  console.log('PROBE_RESULT ' + JSON.stringify(payload))
}

async function customerSession (email: string) {
  const { app } = await createTestApp()
  const registered = await register(app, { email, password: placeholderPassword })
  assert.equal(registered.body.data.role, 'customer')
  const authentication = await login(app, { email, password: placeholderPassword })
  const headers = {
    Authorization: 'Bearer ' + authentication.token,
    'content-type': 'application/json'
  }
  return { app, email, headers, basketId: authentication.bid as number, userId: registered.body.data.id as number }
}

async function createProduct (app: Parameters<typeof request>[0], headers: Record<string, string>, name: string) {
  const res = await request(app)
    .post('/api/Products')
    .set(headers)
    .send({
      name,
      description: 'Created by a customer with no stock row',
      price: 1.25,
      image: 'missing-stock.jpg'
    })
  assert.equal(res.status, 201)
  return res.body.data.id as number
}

async function stockedProductId (app: Parameters<typeof request>[0], headers: Record<string, string>, excludedProductId: number) {
  const res = await request(app).get('/api/Quantitys').set(headers)
  assert.equal(res.status, 200)
  const row = (res.body.data as Array<{ ProductId: number, quantity: number }>).find((item) => {
    return item.ProductId !== excludedProductId && item.quantity >= 1
  })
  assert.ok(row, 'expected a seeded product with stock')
  return row.ProductId
}

async function customerProbe () {
  const session = await customerSession('missing-stock-customer@juice-sh.op')
  const uncheckedProductId = await createProduct(session.app, session.headers, 'Unstocked customer juice')
  const checkedProductId = await stockedProductId(session.app, session.headers, uncheckedProductId)

  const direct = await request(session.app)
    .post('/api/BasketItems')
    .set(session.headers)
    .send({ ProductId: uncheckedProductId, BasketId: session.basketId, quantity: 1 })
  assert.ok(direct.status >= 400, `direct add of a product with no stock returned ${direct.status}`)
  assert.equal(await BasketItemModel.count({ where: { ProductId: uncheckedProductId } }), 0)

  const nested = await request(session.app)
    .post('/api/BasketItems')
    .set(session.headers)
    .send({
      ProductId: checkedProductId,
      BasketId: session.basketId,
      quantity: 1,
      detail: { ProductId: uncheckedProductId }
    })

  const persistedUnchecked = await BasketItemModel.findAll({ where: { ProductId: uncheckedProductId } })
  if (persistedUnchecked.length > 0) {
    await request(session.app)
      .put('/api/BasketItems/' + persistedUnchecked[0].id)
      .set(session.headers)
      .send({ quantity: 1 })
    assert.fail(`basket line ${persistedUnchecked[0].id} stored product ${uncheckedProductId}; the stock check validated product ${checkedProductId}`)
  }

  if (nested.status < 400) {
    assert.equal(Number(nested.body.data.ProductId), checkedProductId)
    const updated = await request(session.app)
      .put('/api/BasketItems/' + nested.body.data.id)
      .set(session.headers)
      .send({ quantity: 1 })
    assert.equal(updated.status, 200)
  }

  const followUp = await request(session.app).get('/api/Products/' + uncheckedProductId)
  assert.equal(followUp.status, 200)
  const user = await UserModel.findByPk(session.userId)
  assert.equal(user?.email, session.email)

  report({
    role: 'customer',
    checkedProductId,
    uncheckedProductId,
    uncheckedProductPersisted: false,
    nestedStatus: nested.status,
    followUpStatus: followUp.status,
    userStillPresent: true
  })
}

async function updateProbe () {
  const session = await customerSession('missing-stock-update@juice-sh.op')
  const productId = await createProduct(session.app, session.headers, 'Unstocked update juice')
  await QuantityModel.destroy({ where: { ProductId: productId } })
  const line = await BasketItemModel.create({
    ProductId: productId,
    BasketId: session.basketId,
    quantity: 1
  })

  const updated = await request(session.app)
    .put('/api/BasketItems/' + line.id)
    .set(session.headers)
    .send({ quantity: 2 })
  assert.ok(updated.status === 400 || updated.status === 500, `expected a handled error, got ${updated.status}`)

  const stored = await BasketItemModel.findByPk(line.id)
  assert.equal(stored?.quantity, 1)
  const followUp = await request(session.app).get('/api/Products/' + productId)
  assert.equal(followUp.status, 200)
  const user = await UserModel.findByPk(session.userId)
  assert.equal(user?.email, session.email)

  report({
    putStatus: updated.status,
    quantity: stored?.quantity,
    followUpStatus: followUp.status,
    userStillPresent: true
  })
}

const mode = process.argv[2]
if (process.listenerCount('unhandledRejection') !== 0 || process.listenerCount('uncaughtException') !== 0) {
  console.error('probe must observe Node default unhandled-rejection behavior')
  process.exit(2)
}

const run = mode === 'update' ? updateProbe : customerProbe
run().catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
