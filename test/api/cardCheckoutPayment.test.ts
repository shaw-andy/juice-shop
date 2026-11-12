/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'

const PLACEHOLDER_PASSWORD = 'placeholder-password'
const ftpDir = path.resolve('ftp')

let app: Express
let productId: number
let customerSequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
  const product = await ProductModel.findOne({ where: { name: 'OWASP Juice Shop T-Shirt' } })
  assert.ok(product)
  productId = product.id
  const quantity = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(quantity)
  assert.ok(quantity.quantity >= 5)
}, { timeout: 60000 })

void describe('card checkout must not record a sale without a verified charge', { concurrency: 1 }, () => {
  void it('refuses checkout when orderDetails is missing', async () => {
    const customer = await newCustomer()
    await assertNoSale(customer, undefined)
  })

  void it('refuses checkout when paymentId is missing', async () => {
    const customer = await newCustomer()
    await assertNoSale(customer, {})
  })

  void it('refuses checkout when paymentId is null', async () => {
    const customer = await newCustomer()
    await assertNoSale(customer, { paymentId: null })
  })

  void it('refuses checkout when paymentId is an empty string', async () => {
    const customer = await newCustomer()
    await assertNoSale(customer, { paymentId: '' })
  })

  void it('refuses checkout when paymentId is not wallet and not a charge', async () => {
    const customer = await newCustomer()
    await assertNoSale(customer, { paymentId: 'not-a-card' })
  })

  void it('refuses checkout when paymentId is a card id that does not exist', async () => {
    const customer = await newCustomer()
    await assertNoSale(customer, { paymentId: 999999 })
  })

  void it('refuses checkout when paymentId is only the caller saved card', async () => {
    const customer = await newCustomer()
    const cardId = await saveCard(customer.token)
    await assertNoSale(customer, { paymentId: cardId })
  })

  void it('refuses checkout when paymentId is another customer card', async () => {
    const payer = await newCustomer()
    const other = await newCustomer()
    const cardId = await saveCard(other.token)
    await assertNoSale(payer, { paymentId: cardId })
  })

  void it('refuses checkout when paymentId is a card id string with no charge for this total', async () => {
    const customer = await newCustomer()
    const cardId = await saveCard(customer.token)
    await assertNoSale(customer, { paymentId: String(cardId) })
  })

  void it('refuses wallet checkout that cannot cover the total without sale side effects', async () => {
    const customer = await newCustomer()
    const wallet = await WalletModel.findOne({ where: { UserId: customer.userId } })
    assert.ok(wallet)
    assert.equal(Number(wallet.balance), 0)
    await assertNoSale(customer, { paymentId: 'wallet' })
  })

  void it('debits the wallet by the stored order total when paymentId is wallet', async () => {
    const customer = await newCustomer()
    await WalletModel.update({ balance: 500 }, { where: { UserId: customer.userId } })
    const before = await capture(customer)
    const seen = watchNewOrderPdfs(before.pdfs)
    try {
      const res = await placeCheckout(customer, { paymentId: 'wallet' })
      assert.equal(res.status, 200, res.text.slice(0, 300))
      assert.equal(typeof res.body.orderConfirmation, 'string')
      const order = await findOrder(res.body.orderConfirmation)
      assert.ok(order)
      assert.equal(order.paymentId, 'wallet')
      assert.ok(Number(order.totalPrice) > 0)
      const after = await capture(customer)
      assert.equal(after.stock, before.stock - 1)
      assert.equal(after.itemCount, 0)
      assert.equal(after.orderCount, before.orderCount + 1)
      assert.equal(after.wallet, before.wallet - Number(order.totalPrice) + Number(order.bonus))
      const newPdfs = [...after.pdfs].filter((name) => !before.pdfs.has(name))
      assert.equal(newPdfs.length, 1)
    } finally {
      seen.stop()
      deleteNewPdfs(before.pdfs)
    }
  })
})

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function newCustomer () {
  customerSequence += 1
  const email = `card-checkout-${customerSequence}@example.test`
  await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  const basketId = Number(authentication.bid)
  const added = await request(app)
    .post('/api/BasketItems')
    .set(authHeader(authentication.token))
    .send({ BasketId: basketId, ProductId: productId, quantity: 1 })
  assert.equal(added.status, 200, added.text.slice(0, 300))
  const items = await BasketItemModel.findAll({ where: { BasketId: basketId } })
  assert.equal(items.length, 1)
  return { token: authentication.token as string, basketId, userId: user.id }
}

async function saveCard (token: string) {
  const created = await request(app)
    .post('/api/Cards')
    .set(authHeader(token))
    .send({ fullName: 'Checkout Test', cardNum: 4000000000000000, expMonth: 12, expYear: 2099 })
  assert.equal(created.status, 201, created.text.slice(0, 300))
  const cardId = Number(created.body?.data?.id)
  assert.ok(Number.isInteger(cardId) && cardId > 0)
  return cardId
}

async function placeCheckout (customer: { token: string, basketId: number }, orderDetails: Record<string, unknown> | undefined) {
  const call = request(app)
    .post('/rest/basket/' + customer.basketId + '/checkout')
    .set(authHeader(customer.token))
  if (orderDetails === undefined) {
    return await call.send({})
  }
  return await call.send({ orderDetails })
}

async function capture (customer: { token: string, basketId: number, userId: number }) {
  const quantity = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(quantity)
  const wallet = await WalletModel.findOne({ where: { UserId: customer.userId } })
  assert.ok(wallet)
  const items = await BasketItemModel.findAll({ where: { BasketId: customer.basketId } })
  const orders = await listOrders()
  return {
    stock: Number(quantity.quantity),
    wallet: Number(wallet.balance),
    itemCount: items.length,
    orderCount: orders.length,
    orderIds: new Set(orders.map((order) => order.orderId)),
    pdfs: new Set(listOrderPdfs())
  }
}

async function listOrders () {
  const orders = await db.ordersCollection.find({})
  return orders as Array<{ orderId: string, paymentId: unknown, totalPrice: number, bonus: number }>
}

async function findOrder (orderId: string) {
  const orders = await listOrders()
  return orders.find((order) => order.orderId === orderId)
}

function listOrderPdfs () {
  return fs.readdirSync(ftpDir).filter((name) => name.startsWith('order_') && name.endsWith('.pdf'))
}

function watchNewOrderPdfs (existing: Set<string>) {
  const seen = new Set<string>()
  const watcher = fs.watch(ftpDir, (_event, filename) => {
    if (typeof filename === 'string' && filename.startsWith('order_') && filename.endsWith('.pdf') && !existing.has(filename)) {
      seen.add(filename)
    }
  })
  return {
    seen,
    stop () {
      watcher.close()
    }
  }
}

function deleteNewPdfs (existing: Set<string>) {
  for (const name of listOrderPdfs()) {
    if (!existing.has(name)) {
      fs.unlinkSync(path.join(ftpDir, name))
    }
  }
}

async function assertNoSale (customer: { token: string, basketId: number, userId: number }, orderDetails: Record<string, unknown> | undefined) {
  const before = await capture(customer)
  const seen = watchNewOrderPdfs(before.pdfs)
  try {
    const res = await placeCheckout(customer, orderDetails)
    await new Promise((resolve) => setImmediate(resolve))
    const after = await capture(customer)
    const newPdfs = [...after.pdfs].filter((name) => !before.pdfs.has(name))
    const orders = await listOrders()
    const newOrders = orders.filter((order) => !before.orderIds.has(order.orderId))
    const problems: string[] = []
    if (res.status < 400 || res.body?.orderConfirmation !== undefined) {
      problems.push(`status ${res.status} body ${String(res.text).slice(0, 200)}`)
    }
    if (after.stock !== before.stock) problems.push(`stock ${before.stock} -> ${after.stock}`)
    if (after.wallet !== before.wallet) problems.push(`wallet ${before.wallet} -> ${after.wallet}`)
    if (after.itemCount !== before.itemCount) problems.push(`items ${before.itemCount} -> ${after.itemCount}`)
    if (newOrders.length > 0) {
      problems.push(`orders ${newOrders.map((order) => `${order.orderId} paymentId=${String(order.paymentId)} total=${order.totalPrice}`).join('; ')}`)
    }
    if (newPdfs.length > 0) problems.push(`pdfs ${newPdfs.join(',')}`)
    if (seen.seen.size > 0) problems.push(`watched pdfs ${[...seen.seen].join(',')}`)
    assert.deepEqual(problems, [])
  } finally {
    seen.stop()
    deleteNewPdfs(before.pdfs)
  }
}
