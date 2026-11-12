/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import type { Model, ModelStatic } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

const placeholderPassword = 'placeholder-password'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('parallel checkout of one basket', () => {
  void it('charges the signed-in wallet once when two wallet checkouts overlap', async (t) => {
    const buyer = await registerCustomer('buyer-wallet')
    const bystander = await registerCustomer('bystander-wallet')
    const price = 10
    const quantity = 1
    const bonus = Math.round(price / 10) * quantity
    const productId = await createStockedProduct(buyer.auth, price)
    await addToBasket(buyer, productId, quantity)
    await setBalance(buyer.userId, price)
    await setBalance(bystander.userId, 80)
    const ordersBefore = await currentOrderIds()
    const pdfsBefore = orderPdfNames()

    const responses = await overlapReads(t, WalletModel, async () => {
      return await Promise.all([
        checkout(buyer, { paymentId: 'wallet', UserId: bystander.userId }),
        checkout(buyer, { paymentId: 'wallet', UserId: bystander.userId })
      ])
    })

    try {
      const placed = responses.filter((res) => res.status === 200 && typeof res.body?.orderConfirmation === 'string')
      const createdOrders = await ordersSince(ordersBefore)
      const createdPdfs = orderPdfNames().filter((name) => !pdfsBefore.includes(name))
      const buyerBalance = await balanceOf(buyer.userId)
      const bystanderBalance = await balanceOf(bystander.userId)
      const remainingItems = await BasketItemModel.count({ where: { BasketId: buyer.basketId } })

      assert.deepEqual({
        placed: placed.length,
        orders: createdOrders.length,
        pdfs: createdPdfs.length,
        buyerBalance,
        bystanderBalance,
        remainingItems
      }, {
        placed: 1,
        orders: 1,
        pdfs: 1,
        buyerBalance: bonus,
        bystanderBalance: 80,
        remainingItems: 0
      })
      assert.equal(createdOrders.length, 1)
      assert.equal(createdOrders[0].paymentId, 'wallet')
      assert.equal(Number(createdOrders[0].totalPrice), price)
      assert.equal(Number(createdOrders[0].bonus), bonus)
      assert.equal(createdOrders[0].orderId, placed[0].body.orderConfirmation)
      assert.deepEqual(createdPdfs, [`order_${placed[0].body.orderConfirmation}.pdf`])
      assert.equal(buyerBalance, bonus)
      assert.equal(bystanderBalance, 80)
      assert.equal(remainingItems, 0)
    } finally {
      removeNewPdfs(pdfsBefore)
    }
  }, { timeout: 30000 })

  void it('records one order when two non-wallet checkouts of the same basket overlap', async (t) => {
    const buyer = await registerCustomer('buyer-card')
    const bystander = await registerCustomer('bystander-card')
    const price = 10
    const quantity = 1
    const bonus = Math.round(price / 10) * quantity
    const productId = await createStockedProduct(buyer.auth, price)
    await addToBasket(buyer, productId, quantity)
    await setBalance(buyer.userId, 0)
    await setBalance(bystander.userId, 80)
    const ordersBefore = await currentOrderIds()
    const pdfsBefore = orderPdfNames()

    const responses = await overlapReads(t, BasketModel, async () => {
      return await Promise.all([
        checkout(buyer, { paymentId: 'card', UserId: bystander.userId }),
        checkout(buyer, { paymentId: 'card', UserId: bystander.userId })
      ])
    })

    try {
      const placed = responses.filter((res) => res.status === 200 && typeof res.body?.orderConfirmation === 'string')
      const createdOrders = await ordersSince(ordersBefore)
      const createdPdfs = orderPdfNames().filter((name) => !pdfsBefore.includes(name))
      const buyerBalance = await balanceOf(buyer.userId)
      const bystanderBalance = await balanceOf(bystander.userId)

      assert.deepEqual({
        placed: placed.length,
        orders: createdOrders.length,
        pdfs: createdPdfs.length,
        buyerBalance,
        bystanderBalance
      }, {
        placed: 1,
        orders: 1,
        pdfs: 1,
        buyerBalance: bonus,
        bystanderBalance: 80
      })
      assert.equal(createdOrders.length, 1)
      assert.equal(createdOrders[0].paymentId, 'card')
      assert.equal(Number(createdOrders[0].totalPrice), price)
      assert.equal(Number(createdOrders[0].bonus), bonus)
      assert.equal(createdOrders[0].orderId, placed[0].body.orderConfirmation)
      assert.deepEqual(createdPdfs, [`order_${placed[0].body.orderConfirmation}.pdf`])
      assert.equal(buyerBalance, bonus)
      assert.equal(bystanderBalance, 80)
    } finally {
      removeNewPdfs(pdfsBefore)
    }
  }, { timeout: 30000 })

  void it('debits a wallet once when two deluxe upgrades overlap', async (t) => {
    const buyer = await registerCustomer('buyer-deluxe')
    const bystander = await registerCustomer('bystander-deluxe')
    const costRes = await request(app).get('/rest/deluxe-membership').set(buyer.auth)
    assert.equal(costRes.status, 200)
    const membershipCost = costRes.body.data.membershipCost
    await setBalance(buyer.userId, membershipCost)
    await setBalance(bystander.userId, 80)

    const responses = await overlapReads(t, WalletModel, async () => {
      return await Promise.all([
        upgrade(buyer, bystander.userId),
        upgrade(buyer, bystander.userId)
      ])
    })

    const successes = responses.filter((res) => res.status === 200)
    const buyerUser = await UserModel.findByPk(buyer.userId)
    const bystanderUser = await UserModel.findByPk(bystander.userId)
    assert.deepEqual({
      successes: successes.length,
      buyerBalance: await balanceOf(buyer.userId),
      bystanderBalance: await balanceOf(bystander.userId),
      buyerRole: buyerUser?.role,
      bystanderRole: bystanderUser?.role
    }, {
      successes: 1,
      buyerBalance: 0,
      bystanderBalance: 80,
      buyerRole: security.roles.deluxe,
      bystanderRole: security.roles.customer
    })
  }, { timeout: 30000 })
})

interface Customer {
  userId: number
  basketId: number
  auth: { Authorization: string, 'content-type': string }
}

async function registerCustomer (label: string): Promise<Customer> {
  const email = `${label}-${Date.now()}@example.test`
  const registered = await register(app, { email, password: placeholderPassword })
  const userId = registered.body.data.id
  await waitForWallet(userId)
  const { token, bid } = await login(app, { email, password: placeholderPassword })
  return {
    userId,
    basketId: bid,
    auth: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  }
}

async function waitForWallet (userId: number) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const wallet = await WalletModel.findOne({ where: { UserId: userId } })
    if (wallet != null) {
      return wallet
    }
    await new Promise((resolve) => { setTimeout(resolve, 20) })
  }
  throw new Error(`Wallet for user ${userId} was not created`)
}

async function setBalance (userId: number, balance: number) {
  const updated = await WalletModel.update({ balance }, { where: { UserId: userId } })
  assert.equal(updated[0], 1)
}

async function balanceOf (userId: number) {
  const wallet = await WalletModel.findOne({ where: { UserId: userId } })
  assert.ok(wallet != null)
  return Number(wallet.balance)
}

async function createStockedProduct (auth: Customer['auth'], price: number) {
  const res = await request(app)
    .post('/api/Products')
    .set(auth)
    .send({ name: `Race Juice ${Date.now()}`, description: 'Priced for a single wallet checkout', price })
  assert.equal(res.status, 201)
  const productId = res.body.data.id
  await QuantityModel.create({ ProductId: productId, quantity: 5 })
  const stored = await ProductModel.findByPk(productId)
  assert.equal(Number(stored?.price), price)
  return productId
}

async function addToBasket (customer: Customer, productId: number, quantity: number) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(customer.auth)
    .send({ BasketId: customer.basketId, ProductId: productId, quantity })
  assert.equal(res.status, 200)
}

function checkout (customer: Customer, orderDetails: { paymentId: string, UserId: number }) {
  return request(app)
    .post(`/rest/basket/${customer.basketId}/checkout`)
    .set(customer.auth)
    .send({
      orderDetails: { paymentId: orderDetails.paymentId },
      UserId: orderDetails.UserId
    })
}

function upgrade (customer: Customer, foreignUserId: number) {
  return request(app)
    .post('/rest/deluxe-membership')
    .set(customer.auth)
    .send({ paymentMode: 'wallet', UserId: foreignUserId })
}

async function currentOrderIds () {
  const docs: Array<{ orderId: string }> = await db.ordersCollection.find({})
  return new Set(docs.map((doc) => doc.orderId))
}

async function ordersSince (before: Set<string>) {
  const docs: Array<{ orderId: string, paymentId: string | null, totalPrice: number, bonus: number }> = await db.ordersCollection.find({})
  return docs.filter((doc) => !before.has(doc.orderId))
}

function orderPdfNames () {
  return fs.readdirSync(path.resolve('ftp')).filter((name) => name.startsWith('order_') && name.endsWith('.pdf')).sort()
}

function removeNewPdfs (before: string[]) {
  for (const name of orderPdfNames()) {
    if (!before.includes(name)) {
      fs.unlinkSync(path.resolve('ftp', name))
    }
  }
}

async function overlapReads <M extends Model, T> (
  t: TestContext,
  model: ModelStatic<M>,
  run: () => Promise<T>
): Promise<T> {
  const original = model.findOne.bind(model)
  let seenInPair = 0
  let releasePair = () => {}
  let pairArrived = new Promise<void>((resolve) => { releasePair = resolve })
  const mocked = t.mock.method(model, 'findOne', async (...args: unknown[]) => {
    const row = await original(...args as [never])
    seenInPair += 1
    if (seenInPair === 1) {
      const arrived = pairArrived
      const partnerArrived = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => { resolve(false) }, 3000)
        arrived.then(() => {
          clearTimeout(timer)
          resolve(true)
        }, () => {
          clearTimeout(timer)
          resolve(false)
        })
      })
      if (!partnerArrived) {
        seenInPair = 0
        pairArrived = new Promise<void>((resolve) => { releasePair = resolve })
      }
    } else if (seenInPair === 2) {
      releasePair()
      seenInPair = 0
      pairArrived = new Promise<void>((resolve) => { releasePair = resolve })
    }
    return row
  })
  try {
    return await run()
  } finally {
    mocked.mock.restore()
  }
}
