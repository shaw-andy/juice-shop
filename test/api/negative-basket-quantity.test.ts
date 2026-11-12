/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const PLACEHOLDER_PASSWORD = 'placeholder'
const FTP_DIR = 'ftp'

let app: Express
let orderPdfsBefore: string[] = []

interface Session {
  email: string
  userId: number
  basketId: number
  authHeader: { Authorization: string, 'content-type': string }
}

interface CatalogProduct {
  id: number
  name: string
  price: number
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  orderPdfsBefore = listOrderPdfs()
}, { timeout: 60000 })

after(() => {
  for (const name of listOrderPdfs()) {
    if (!orderPdfsBefore.includes(name)) {
      fs.unlinkSync(path.join(FTP_DIR, name))
    }
  }
})

void describe('negative basket quantities', { concurrency: 1 }, () => {
  void it('rejects a negative quantity that passes the per-user limit and the stock check, and does not credit the wallet', async () => {
    const session = await openSession()
    const product = await productByName('Melon Bike (Comeback-Product 2018 Edition)')
    const balanceBefore = await walletBalance(session)
    const outcome = await addQuantityAndCheckout(session, product.id, -1, balanceBefore)

    assert.equal(outcome.addStatus, 400, outcome.detail)
    assert.equal(outcome.negativeItems, 0, outcome.detail)
    assert.ok(outcome.balanceAfter <= balanceBefore, outcome.detail)
  })

  void it('rejects a negative quantity for a product with no per-user limit, and does not credit the wallet', async () => {
    const session = await openSession()
    const product = await productByName('Orange Juice (1000ml)')
    const quantityRow = await QuantityModel.findOne({ where: { ProductId: product.id } })
    assert.equal(quantityRow?.limitPerUser ?? null, null)
    const balanceBefore = await walletBalance(session)
    const outcome = await addQuantityAndCheckout(session, product.id, -1, balanceBefore)

    assert.equal(outcome.addStatus, 400, outcome.detail)
    assert.equal(outcome.negativeItems, 0, outcome.detail)
    assert.ok(outcome.balanceAfter <= balanceBefore, outcome.detail)
  })

  void it('rejects a negative quantity from a deluxe customer, whose per-user limit is skipped', async () => {
    const session = await openSession()
    await UserModel.update({
      role: security.roles.deluxe,
      deluxeToken: security.deluxeToken(session.email)
    }, { where: { id: session.userId } })
    const deluxeLogin = await login(app, { email: session.email, password: PLACEHOLDER_PASSWORD })
    session.authHeader = {
      Authorization: 'Bearer ' + deluxeLogin.token,
      'content-type': 'application/json'
    }
    session.basketId = deluxeLogin.bid
    const product = await productByName('Apple Juice (1000ml)')
    const balanceBefore = await walletBalance(session)
    const outcome = await addQuantityAndCheckout(session, product.id, -1, balanceBefore)

    assert.equal(outcome.addStatus, 400, outcome.detail)
    assert.equal(outcome.negativeItems, 0, outcome.detail)
    assert.ok(outcome.balanceAfter <= balanceBefore, outcome.detail)
  })

  void it('rejects a zero quantity before saving a basket item', async () => {
    const session = await openSession()
    const product = await productByName('Apple Juice (1000ml)')
    const res = await request(app)
      .post('/api/BasketItems')
      .set(session.authHeader)
      .send({ BasketId: session.basketId, ProductId: product.id, quantity: 0 })
    const stored = await BasketItemModel.findAll({ where: { BasketId: session.basketId, ProductId: product.id, quantity: 0 } })

    assert.equal(res.status, 400, `quantity 0 was stored (${res.status} ${JSON.stringify(res.body)})`)
    assert.equal(stored.length, 0)
  })

  void it('rejects an update that changes a stored quantity to a negative number', async () => {
    const session = await openSession()
    const product = await productByName('Lemon Juice (500ml)')
    const created = await request(app)
      .post('/api/BasketItems')
      .set(session.authHeader)
      .send({ BasketId: session.basketId, ProductId: product.id, quantity: 1 })
    assert.equal(created.status, 200)
    const itemId = created.body.data.id

    const updated = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(session.authHeader)
      .send({ quantity: -1 })
    const stored = await BasketItemModel.findByPk(itemId)

    assert.equal(updated.status, 400, `update accepted negative quantity (${updated.status} ${JSON.stringify(updated.body)})`)
    assert.equal(Number(stored?.quantity), 1)
  })

  void it('does not persist a negative quantity that the stock check did not see', async () => {
    const session = await openSession()
    const product = await productByName('Banana Juice (1000ml)')
    const balanceBefore = await walletBalance(session)
    const body = JSON.stringify({
      ProductId: product.id,
      BasketId: session.basketId,
      quantity: 1,
      nested: { quantity: -5 }
    })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(session.authHeader)
      .send(body)
    const stored = await BasketItemModel.findAll({ where: { BasketId: session.basketId, ProductId: product.id } })
    const checkout = await checkoutWallet(session, session.userId)
    const balanceAfter = await walletBalance(session)
    const negativeItems = stored.filter((item) => Number(item.quantity) < 1)
    const detail = `stored ${JSON.stringify(stored.map((item) => Number(item.quantity)))} from ${res.status} ${JSON.stringify(res.body)} wallet ${balanceBefore} -> ${balanceAfter} checkout ${checkout.status} ${JSON.stringify(checkout.body)}`

    assert.equal(negativeItems.length, 0, detail)
    assert.ok(balanceAfter <= balanceBefore, detail)
  })

  void it('does not credit a wallet, change stock, or write an order when the basket total is already negative', async () => {
    const session = await openSession()
    const bystander = await openSession()
    const product = await productByName('Melon Bike (Comeback-Product 2018 Edition)')
    const stockBefore = Number((await QuantityModel.findOne({ where: { ProductId: product.id } }))?.quantity)
    const balanceBefore = await walletBalance(session)
    const bystanderBefore = await walletBalance(bystander)
    const pdfsBefore = listOrderPdfs()
    const ordersBefore = await orderHistory(session)
    const seeded = await BasketItemModel.create({
      ProductId: product.id,
      BasketId: session.basketId,
      quantity: -1
    })

    const checkout = await request(app)
      .post('/rest/basket/' + session.basketId + '/checkout')
      .set(session.authHeader)
      .send({
        UserId: bystander.userId,
        orderDetails: { paymentId: 'wallet' }
      })

    const balanceAfter = await walletBalance(session)
    const bystanderAfter = await walletBalance(bystander)
    const stockAfter = Number((await QuantityModel.findOne({ where: { ProductId: product.id } }))?.quantity)
    const persisted = await BasketItemModel.findByPk(seeded.id)
    const ordersAfter = await orderHistory(session)
    const newPdfs = listOrderPdfs().filter((name) => !pdfsBefore.includes(name))
    const negativeOrders = ordersAfter.filter((order) => Number(order.totalPrice) < 0)
    const detail = `checkout ${checkout.status} ${JSON.stringify(checkout.body)} wallet ${balanceBefore} -> ${balanceAfter} bystander ${bystanderBefore} -> ${bystanderAfter} stock ${stockBefore} -> ${stockAfter} item ${String(persisted?.quantity)} orders ${ordersBefore.length} -> ${ordersAfter.length} negativeOrders ${negativeOrders.length} pdfs ${newPdfs.join(',')}`

    assert.ok(balanceAfter <= balanceBefore, detail)
    assert.ok(checkout.status >= 400, detail)
    assert.equal(bystanderAfter, bystanderBefore, detail)
    assert.ok(stockAfter <= stockBefore, detail)
    assert.equal(Number(persisted?.quantity), -1, detail)
    assert.equal(negativeOrders.length, 0, detail)
    assert.equal(ordersAfter.length, ordersBefore.length, detail)
    assert.deepEqual(newPdfs, [], detail)
  })

  void it('does not apply a negative quantity when checkout uses a non-wallet payment', async () => {
    const session = await openSession()
    const product = await productByName('Melon Bike (Comeback-Product 2018 Edition)')
    const balanceBefore = await walletBalance(session)
    const stockBefore = Number((await QuantityModel.findOne({ where: { ProductId: product.id } }))?.quantity)
    await BasketItemModel.create({
      ProductId: product.id,
      BasketId: session.basketId,
      quantity: -1
    })

    const checkout = await request(app)
      .post('/rest/basket/' + session.basketId + '/checkout')
      .set(session.authHeader)
      .send({ orderDetails: { paymentId: 'card' } })
    const balanceAfter = await walletBalance(session)
    const stockAfter = Number((await QuantityModel.findOne({ where: { ProductId: product.id } }))?.quantity)

    assert.ok(balanceAfter <= balanceBefore, `wallet ${balanceBefore} -> ${balanceAfter} stock ${stockBefore} -> ${stockAfter} checkout ${checkout.status} ${JSON.stringify(checkout.body)}`)
    assert.ok(stockAfter <= stockBefore, `stock rose from ${stockBefore} to ${stockAfter} on a negative card checkout`)
  })
})

async function openSession (): Promise<Session> {
  const email = `negative-quantity-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  const registered = await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  return {
    email,
    userId: registered.body.data.id,
    basketId: authentication.bid,
    authHeader: {
      Authorization: 'Bearer ' + authentication.token,
      'content-type': 'application/json'
    }
  }
}

async function productByName (name: string): Promise<CatalogProduct> {
  const res = await request(app).get('/api/Products')
  assert.equal(res.status, 200)
  const product = (res.body.data as CatalogProduct[]).find((candidate) => candidate.name === name)
  assert.ok(product, `missing product ${name}`)
  assert.ok(product.price > 0)
  return product
}

async function walletBalance (session: Session): Promise<number> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await request(app).get('/rest/wallet/balance').set(session.authHeader)
    if (res.status === 200) {
      return Number(res.body.data)
    }
    await new Promise((resolve) => { setTimeout(resolve, 50) })
  }
  throw new Error('wallet was not created for the registered user')
}

async function checkoutWallet (session: Session, userIdInBody: number) {
  return await request(app)
    .post('/rest/basket/' + session.basketId + '/checkout')
    .set(session.authHeader)
    .send({ UserId: userIdInBody, orderDetails: { paymentId: 'wallet' } })
}

async function addQuantityAndCheckout (session: Session, productId: number, quantity: number, balanceBefore: number) {
  const added = await request(app)
    .post('/api/BasketItems')
    .set(session.authHeader)
    .send({ BasketId: session.basketId, ProductId: productId, quantity })
  const stored = await BasketItemModel.findAll({ where: { BasketId: session.basketId, ProductId: productId } })
  const checkout = await checkoutWallet(session, session.userId)
  const balanceAfter = await walletBalance(session)
  const negativeItems = stored.filter((item) => Number(item.quantity) < 1).length
  const detail = `add ${added.status} ${JSON.stringify(added.body)} checkout ${checkout.status} ${JSON.stringify(checkout.body)} wallet ${balanceBefore} -> ${balanceAfter} stored ${JSON.stringify(stored.map((item) => Number(item.quantity)))}`
  return { addStatus: added.status, negativeItems, balanceAfter, detail }
}

async function orderHistory (session: Session): Promise<Array<{ totalPrice: number }>> {
  const res = await request(app).get('/rest/order-history').set(session.authHeader)
  assert.equal(res.status, 200)
  return res.body.data
}

function listOrderPdfs (): string[] {
  return fs.readdirSync(FTP_DIR).filter((name) => name.startsWith('order_') && name.endsWith('.pdf')).sort()
}
