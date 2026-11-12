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
// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'

let app: Express

const password = 'placeholder'
const productId = 1

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function orderPdfNames () {
  return fs.readdirSync('ftp').filter((name) => name.startsWith('order_') && name.endsWith('.pdf')).sort()
}

function encodedCoupon (discountField: string) {
  const plain = utils.toMMMYY(new Date()) + '-' + discountField
  const encoded = z85.encode(plain)
  assert.equal(z85.decode(encoded).toString(), plain)
  return encoded as string
}

function discountWithinCap (discount: unknown) {
  return discount === undefined || (typeof discount === 'number' && discount >= 0 && discount <= 100)
}

async function walletBalance (userId: number) {
  const wallet = await WalletModel.findOne({ where: { UserId: userId } })
  assert.ok(wallet != null, `wallet for UserId ${userId} was not created`)
  return Number(wallet.balance)
}

async function openCustomer () {
  const email = `uncapped-coupon-${Date.now()}-${Math.random().toString(16).slice(2)}@juice-sh.op`
  const registered = await register(app, { email, password })
  const userId = registered.body.data.id as number
  const { token, bid } = await login(app, { email, password })
  const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  const product = await request(app).get('/api/Products/' + productId)
  assert.equal(product.status, 200)
  const price = Number(product.body.data.price)
  assert.ok(price > 0)
  const added = await request(app)
    .post('/api/BasketItems')
    .set(authHeader)
    .send({ BasketId: bid, ProductId: productId, quantity: 1 })
  assert.equal(added.status, 200, added.text)
  const quantityRow = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(quantityRow != null)
  const walletsBefore = new Map<number, number>()
  for (const wallet of await WalletModel.findAll()) {
    walletsBefore.set(wallet.UserId, Number(wallet.balance))
  }
  return {
    email,
    userId,
    bid,
    authHeader,
    price,
    startingBalance: await walletBalance(userId),
    quantityBefore: Number(quantityRow.quantity),
    allowedBonus: Math.round(price / 10),
    walletsBefore
  }
}

async function customerOrders (email: string) {
  const maskedEmail = email.replace(/[aeiou]/gi, '*')
  const orders = await db.ordersCollection.find({ email: maskedEmail })
  return orders as Array<{ totalPrice: number }>
}

async function expectCheckoutDoesNotCredit (customer: Awaited<ReturnType<typeof openCustomer>>, checkout: request.Response, extra: Record<string, unknown> = {}) {
  const balanceAfter = await walletBalance(customer.userId)
  const orders = await customerOrders(customer.email)
  const quantityRow = await QuantityModel.findOne({ where: { ProductId: productId } })
  const itemsAfter = await BasketItemModel.count({ where: { BasketId: customer.bid } })
  const report = JSON.stringify({
    balanceBefore: customer.startingBalance,
    balanceAfter,
    allowedBonus: customer.allowedBonus,
    price: customer.price,
    checkoutStatus: checkout.status,
    checkoutBody: checkout.body,
    totals: orders.map((order) => order.totalPrice),
    ...extra
  })
  assert.ok(balanceAfter <= customer.startingBalance + customer.allowedBonus + 1e-9, report)
  assert.ok(!orders.some((order) => Number(order.totalPrice) < 0), report)
  for (const wallet of await WalletModel.findAll()) {
    const before = customer.walletsBefore.get(wallet.UserId) ?? 0
    const cap = wallet.UserId === customer.userId ? before + customer.allowedBonus : before
    assert.ok(Number(wallet.balance) <= cap + 1e-9, `UserId ${wallet.UserId} balance ${before} -> ${wallet.balance}`)
  }
  const refused = checkout.status !== 200 || checkout.body?.orderConfirmation === undefined
  if (refused) {
    assert.equal(Number(quantityRow?.quantity), customer.quantityBefore, 'stock changed before refusal ' + report)
    assert.equal(itemsAfter, 1, 'basket item removed before refusal ' + report)
  }
}

async function withOrderFiles (run: (pdfsBefore: string[]) => Promise<void>) {
  const pdfsBefore = orderPdfNames()
  try {
    await run(pdfsBefore)
  } finally {
    for (const name of orderPdfNames()) {
      if (!pdfsBefore.includes(name)) {
        fs.unlinkSync(path.join('ftp', name))
      }
    }
  }
}

void describe('uncapped coupon percentage at checkout', () => {
  void it('does not turn a six-digit coupon into a wallet credit', async () => {
    await withOrderFiles(async (pdfsBefore) => {
      const customer = await openCustomer()
      const couponCode = encodedCoupon('999999')
      const coupon = await request(app)
        .put('/rest/basket/' + customer.bid + '/coupon/' + encodeURIComponent(couponCode))
        .set(customer.authHeader)
      const stored = await BasketModel.findByPk(customer.bid)
      const storedDiscount = stored?.coupon ? security.discountFromCoupon(stored.coupon) : undefined
      const checkout = await request(app)
        .post('/rest/basket/' + customer.bid + '/checkout')
        .set(customer.authHeader)
        .send({ orderDetails: { paymentId: 'wallet' } })
      await expectCheckoutDoesNotCredit(customer, checkout, {
        couponStatus: coupon.status,
        couponBody: coupon.body,
        storedDiscount
      })
      assert.ok(
        discountWithinCap(coupon.body?.discount),
        `coupon response ${coupon.status} ${JSON.stringify(coupon.body)}`
      )
      assert.ok(discountWithinCap(storedDiscount), `stored coupon decodes to ${String(storedDiscount)}`)
      if (checkout.status !== 200 || checkout.body?.orderConfirmation === undefined) {
        assert.deepEqual(orderPdfNames(), pdfsBefore, 'order file created before refusal')
      }
    })
  })

  void it('does not credit the wallet when the basket already holds a six-digit coupon', async () => {
    await withOrderFiles(async (pdfsBefore) => {
      const customer = await openCustomer()
      const couponCode = encodedCoupon('100001')
      await BasketModel.update({ coupon: couponCode }, { where: { id: customer.bid } })
      const checkout = await request(app)
        .post('/rest/basket/' + customer.bid + '/checkout')
        .set(customer.authHeader)
        .send({ orderDetails: { paymentId: 'wallet' } })
      await expectCheckoutDoesNotCredit(customer, checkout)
      if (checkout.status !== 200 || checkout.body?.orderConfirmation === undefined) {
        assert.deepEqual(orderPdfNames(), pdfsBefore, 'order file created before refusal')
      }
    })
  })
})
