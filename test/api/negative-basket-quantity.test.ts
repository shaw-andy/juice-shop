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
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'

const placeholderPassword = 'placeholder-password'
const negativeQuantity = -10
const ftpDir = path.resolve('ftp')

let app: Express
let pdfsBefore: Set<string>

before(async () => {
  const result = await createTestApp()
  app = result.app
  pdfsBefore = new Set(orderPdfNames())
}, { timeout: 120000 })

after(() => {
  for (const name of orderPdfNames()) {
    if (!pdfsBefore.has(name)) {
      fs.unlinkSync(path.join(ftpDir, name))
    }
  }
})

void describe('negative basket quantity', () => {
  void it('POST /api/BasketItems rejects a negative quantity on a per-user limited product and does not store it', async () => {
    const customer = await registerCustomer('limited-negative@juice-sh.op')
    const product = await productByName('Apple Juice (1000ml)')
    const stock = await QuantityModel.findOne({ where: { ProductId: product.id } })
    assert.ok(stock != null)
    assert.equal(stock.limitPerUser, 5)
    assert.ok(stock.quantity >= 1)
    const stockBefore = Number(stock.quantity)

    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(customer.token))
      .send({ BasketId: customer.bid, ProductId: product.id, quantity: negativeQuantity })

    const stored = await BasketItemModel.findAll({ where: { BasketId: customer.bid, ProductId: product.id } })
    const stockAfter = await QuantityModel.findOne({ where: { ProductId: product.id } })
    assert.equal(res.status, 400, JSON.stringify(res.body))
    assert.equal(stored.length, 0)
    assert.equal(Number(stockAfter?.quantity), stockBefore)
  })

  void it('PUT /api/BasketItems/:id rejects a negative quantity on a product without a per-user limit and keeps the previous quantity', async () => {
    const customer = await registerCustomer('unlimited-negative@juice-sh.op')
    const product = await productByName('Orange Juice (1000ml)')
    const stock = await QuantityModel.findOne({ where: { ProductId: product.id } })
    assert.ok(stock != null)
    assert.equal(stock.limitPerUser, null)
    assert.ok(stock.quantity >= 1)
    const stockBefore = Number(stock.quantity)

    const created = await request(app)
      .post('/api/BasketItems')
      .set(authHeader(customer.token))
      .send({ BasketId: customer.bid, ProductId: product.id, quantity: 1 })
    assert.equal(created.status, 200, JSON.stringify(created.body))
    const itemId = created.body.data.id

    const res = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(authHeader(customer.token))
      .send({ quantity: negativeQuantity })

    const stored = await BasketItemModel.findByPk(itemId)
    const stockAfter = await QuantityModel.findOne({ where: { ProductId: product.id } })
    assert.equal(res.status, 400, JSON.stringify(res.body))
    assert.equal(stored?.quantity, 1)
    assert.equal(Number(stockAfter?.quantity), stockBefore)
  })

  void it('wallet checkout of a negative quantity does not credit a wallet, increase stock, write an order file, or insert an order, and a second checkout does not either', async () => {
    const customer = await registerCustomer('checkout-negative@juice-sh.op')
    const bystander = await registerCustomer('checkout-bystander@juice-sh.op')
    const product = await productByName('Apple Juice (1000ml)')
    const price = Number(product.price)
    const itemTotal = price * negativeQuantity
    const itemBonus = Math.round(price / 10) * negativeQuantity
    assert.ok(price > 0)
    assert.ok(itemTotal < 0)
    assert.ok((-itemTotal) + itemBonus > 0)

    const stock = await QuantityModel.findOne({ where: { ProductId: product.id } })
    assert.ok(stock != null)
    assert.ok(Number(stock.quantity) > 0)
    const stockBefore = Number(stock.quantity)
    const customerWallet = await walletFor(customer.userId)
    const bystanderWallet = await walletFor(bystander.userId)
    assert.equal(Number(customerWallet.balance), 0)
    assert.equal(Number(bystanderWallet.balance), 0)
    const balancesBefore = await walletBalances()

    const planted = await BasketItemModel.create({
      BasketId: customer.bid,
      ProductId: product.id,
      quantity: negativeQuantity
    })
    const basket = await request(app)
      .get('/rest/basket/' + customer.bid)
      .set(authHeader(customer.token))
    const plantedRow = basket.body.data.Products.find((entry: { id: number, BasketItem?: { quantity: number } }) => entry.id === product.id)
    assert.equal(plantedRow?.BasketItem?.quantity, negativeQuantity)

    const pdfsAtStart = new Set(orderPdfNames())
    const first = await checkout(customer, bystander.userId)
    const afterFirst = await BasketItemModel.findByPk(planted.id)
    if (afterFirst == null) {
      await BasketItemModel.create({
        BasketId: customer.bid,
        ProductId: product.id,
        quantity: negativeQuantity
      })
    }
    const second = await checkout(customer, bystander.userId)

    const balancesAfter = await walletBalances()
    const stockAfter = await QuantityModel.findOne({ where: { ProductId: product.id } })
    const surviving = await BasketItemModel.findByPk(planted.id)
    const orders = await db.ordersCollection.find({})
    const negativeOrders = orders.filter((order: { totalPrice: number }) => Number(order.totalPrice) < 0)
    const newPdfs = orderPdfNames().filter(name => !pdfsAtStart.has(name))
    const increased = [...balancesAfter.entries()].filter(([userId, balance]) => balance > (balancesBefore.get(userId) ?? 0))
    const report = JSON.stringify({
      firstStatus: first.status,
      firstBody: first.body,
      secondStatus: second.status,
      secondBody: second.body,
      customerBalance: balancesAfter.get(customer.userId),
      bystanderBalance: balancesAfter.get(bystander.userId),
      increased,
      stockBefore,
      stockAfter: Number(stockAfter?.quantity),
      originalItemQuantity: surviving?.quantity ?? null,
      negativeOrders: negativeOrders.map((order: { totalPrice: number, paymentId: string, bonus: number }) => ({
        totalPrice: order.totalPrice,
        paymentId: order.paymentId,
        bonus: order.bonus
      })),
      newPdfs
    })

    assert.deepEqual(increased, [], report)
    assert.equal(balancesAfter.get(customer.userId), 0, report)
    assert.equal(balancesAfter.get(bystander.userId), 0, report)
    assert.equal(Number(stockAfter?.quantity), stockBefore, report)
    assert.deepEqual(newPdfs, [], report)
    assert.equal(negativeOrders.length, 0, report)
    assert.equal(surviving?.quantity, negativeQuantity, report)
    assert.ok(first.status >= 400, report)
    assert.ok(second.status >= 400, report)
  })
})

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function registerCustomer (email: string) {
  const created = await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({
      email,
      password: placeholderPassword,
      passwordRepeat: placeholderPassword
    })
  assert.equal(created.status, 201, JSON.stringify(created.body))
  const loggedIn = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email, password: placeholderPassword })
  assert.equal(loggedIn.status, 200, JSON.stringify(loggedIn.body))
  return {
    token: loggedIn.body.authentication.token as string,
    bid: loggedIn.body.authentication.bid as number,
    userId: created.body.data.id as number
  }
}

async function productByName (name: string) {
  const product = await ProductModel.findOne({ where: { name } })
  assert.ok(product != null, name)
  return product
}

async function walletFor (userId: number) {
  for (let attempt = 0; attempt < 20; attempt++) {
    const wallet = await WalletModel.findOne({ where: { UserId: userId } })
    if (wallet != null) {
      return wallet
    }
    await new Promise(resolve => { setTimeout(resolve, 25) })
  }
  throw new Error('Wallet was not created for the new user')
}

async function walletBalances () {
  const rows = await WalletModel.findAll()
  return new Map(rows.map(row => [row.UserId, Number(row.balance)]))
}

function checkout (customer: { token: string, bid: number }, claimedUserId: number) {
  return request(app)
    .post('/rest/basket/' + customer.bid + '/checkout')
    .set(authHeader(customer.token))
    .send({
      UserId: claimedUserId,
      orderDetails: { paymentId: 'wallet' }
    })
}

function orderPdfNames () {
  return fs.readdirSync(ftpDir).filter(name => name.startsWith('order_') && name.endsWith('.pdf'))
}
