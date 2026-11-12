/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { WalletModel } from '../../models/wallet'
import * as security from '../../lib/insecurity'

let app: Express

const password = 'placeholder-password'

interface CatalogProduct {
  id: number
  name: string
  price: number
}

interface DeliveryMethod {
  id: number
  name: string
  price: number
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('checkout wallet bonus', () => {
  void it('does not credit more than a wallet payment collects when a 99 percent coupon and delivery are applied', async () => {
    const customer = await registerCustomer()
    const product = await productByName('OWASP Juice Shop Hoodie')
    const delivery = await deliveryByName('One Day Delivery')
    const quote = quoteOrder(product.price, 99, delivery.price, 1)
    assert.ok(quote.bonus >= quote.charge + 1, `precondition failed: bonus ${quote.bonus} charge ${quote.charge}`)

    const before = await walletBalance(customer.token)
    const placed = await checkoutWithCoupon(customer, product.id, 99, {
      paymentId: 'wallet',
      deliveryMethodId: delivery.id
    })
    const after = await walletBalance(customer.token)
    const order = await placedOrder(customer.token, placed.orderConfirmation)

    assert.equal(placed.status, 200)
    assert.ok(order)
    assert.ok(Number(order.bonus) <= Number(order.totalPrice) && after <= before, `bonus ${order.bonus} totalPrice ${order.totalPrice} wallet ${before} -> ${after}`)
  })

  void it('does not credit more than a wallet payment collects when a 91 percent coupon is applied', async () => {
    const customer = await registerCustomer()
    const product = await productByName('OWASP Juice Shop Logo (3D-printed)')
    const delivery = await deliveryByName('Standard Delivery')
    const quote = quoteOrder(product.price, 91, delivery.price, 1)
    assert.ok(quote.bonus >= quote.charge + 1, `precondition failed: bonus ${quote.bonus} charge ${quote.charge}`)

    const before = await walletBalance(customer.token)
    const placed = await checkoutWithCoupon(customer, product.id, 91, {
      paymentId: 'wallet',
      deliveryMethodId: delivery.id
    })
    const after = await walletBalance(customer.token)
    const order = await placedOrder(customer.token, placed.orderConfirmation)

    assert.equal(placed.status, 200)
    assert.ok(order)
    assert.ok(Number(order.bonus) <= Number(order.totalPrice) && after <= before, `bonus ${order.bonus} totalPrice ${order.totalPrice} wallet ${before} -> ${after}`)
  })

  void it('does not credit the wallet when checkout payment id is a card id', async () => {
    const customer = await registerCustomer()
    const product = await productByName('OWASP Juice Shop Hoodie')
    const delivery = await deliveryByName('Standard Delivery')
    const quote = quoteOrder(product.price, 0, delivery.price, 1)
    assert.ok(quote.bonus >= 1)

    const before = await walletBalance(customer.token)
    const placed = await checkoutWithCoupon(customer, product.id, null, {
      paymentId: '1',
      deliveryMethodId: delivery.id
    })
    const after = await walletBalance(customer.token)
    const order = await placedOrder(customer.token, placed.orderConfirmation)

    assert.equal(placed.status, 200)
    assert.ok(order)
    assert.equal(after, before, `wallet changed from ${before} to ${after} for payment id ${String(order.paymentId)} and bonus ${order.bonus}`)
  })

  void it('does not credit the wallet when checkout has no wallet payment id', async () => {
    const customer = await registerCustomer()
    const product = await productByName('OWASP Juice Shop Hoodie')
    const delivery = await deliveryByName('Fast Delivery')
    const quote = quoteOrder(product.price, 0, delivery.price, 1)
    assert.ok(quote.bonus >= 1)

    const before = await walletBalance(customer.token)
    const placed = await checkoutWithCoupon(customer, product.id, null, {
      deliveryMethodId: delivery.id
    })
    const after = await walletBalance(customer.token)
    const order = await placedOrder(customer.token, placed.orderConfirmation)

    assert.equal(placed.status, 200)
    assert.ok(order)
    assert.notEqual(order.paymentId, 'wallet')
    assert.equal(after, before, `wallet changed from ${before} to ${after} with bonus ${order.bonus}`)
  })

  void it('does not credit the wallet when a campaign coupon is sent and payment id is not wallet', async () => {
    const customer = await registerCustomer()
    const product = await productByName('OWASP Juice Shop Hoodie')
    const delivery = await deliveryByName('Standard Delivery')
    const quote = quoteOrder(product.price, 75, delivery.price, 1)
    assert.ok(quote.bonus >= 1)

    const before = await walletBalance(customer.token)
    await addToBasket(customer, product.id, 1)
    const campaign = `WMNSDY2019-${new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()}`
    const placed = await request(app)
      .post(`/rest/basket/${customer.bid}/checkout`)
      .set(customer.header)
      .send({
        couponData: Buffer.from(campaign).toString('base64'),
        orderDetails: {
          paymentId: 'card',
          deliveryMethodId: delivery.id
        }
      })
    const after = await walletBalance(customer.token)
    const order = placed.status === 200 ? await placedOrder(customer.token, placed.body.orderConfirmation) : null

    assert.equal(placed.status, 200)
    assert.ok(order)
    assert.equal(Number(order.promotionalAmount) > 0, true)
    assert.equal(after, before, `wallet changed from ${before} to ${after} with bonus ${order.bonus}`)
  })

  void it('keeps the wallet from growing when the same discounted wallet checkout is repeated', async () => {
    const customer = await registerCustomer()
    const product = await productByName('OWASP Juice Shop Mug')
    const delivery = await deliveryByName('Standard Delivery')
    const quote = quoteOrder(product.price, 99, delivery.price, 1)
    assert.ok(quote.bonus >= quote.charge + 1, `precondition failed: bonus ${quote.bonus} charge ${quote.charge}`)

    let previous = await walletBalance(customer.token)
    for (let attempt = 0; attempt < 2; attempt++) {
      const placed = await checkoutWithCoupon(customer, product.id, 99, {
        paymentId: 'wallet',
        deliveryMethodId: delivery.id
      })
      const after = await walletBalance(customer.token)
      assert.equal(placed.status, 200)
      assert.ok(after <= previous, `wallet grew from ${previous} to ${after} on checkout ${attempt + 1}`)
      previous = after
    }
  })
})

function quoteOrder (price: number, discountPercent: number, delivery: number, quantity: number) {
  const catalog = price * quantity
  const bonus = Math.round(price / 10) * quantity
  const discountAmount = Number((catalog * (discountPercent / 100)).toFixed(2))
  const charge = Number((catalog - discountAmount + delivery).toFixed(2))
  return { bonus, charge, catalog }
}

async function registerCustomer () {
  const email = `wallet-bonus-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  const registered = await register(app, { email, password })
  const userId = registered.body.data.id as number
  const { token, bid } = await login(app, { email, password })
  await fundWallet(userId, 500)
  return {
    email,
    token,
    bid,
    userId,
    header: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  }
}

async function fundWallet (userId: number, balance: number) {
  let wallet = null
  for (let attempt = 0; attempt < 50 && wallet == null; attempt++) {
    wallet = await WalletModel.findOne({ where: { UserId: userId } })
    if (wallet == null) {
      await new Promise(resolve => setTimeout(resolve, 10))
    }
  }
  assert.ok(wallet)
  await wallet.update({ balance })
}

async function walletBalance (token: string) {
  const res = await request(app)
    .get('/rest/wallet/balance')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
  assert.equal(res.status, 200)
  return Number(res.body.data)
}

async function productByName (name: string): Promise<CatalogProduct> {
  const res = await request(app).get('/api/Products')
  assert.equal(res.status, 200)
  const product = (res.body.data as CatalogProduct[]).find(item => item.name === name)
  assert.ok(product)
  return { id: product.id, name: product.name, price: Number(product.price) }
}

async function deliveryByName (name: string): Promise<DeliveryMethod> {
  const res = await request(app).get('/api/Deliverys')
  assert.equal(res.status, 200)
  const method = (res.body.data as DeliveryMethod[]).find(item => item.name === name)
  assert.ok(method)
  return { id: method.id, name: method.name, price: Number(method.price) }
}

async function addToBasket (customer: { header: { Authorization: string, 'content-type': string }, bid: number }, productId: number, quantity: number) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(customer.header)
    .send({ ProductId: productId, BasketId: customer.bid, quantity })
  assert.equal(res.status, 200)
}

async function checkoutWithCoupon (
  customer: { header: { Authorization: string, 'content-type': string }, bid: number },
  productId: number,
  discount: number | null,
  orderDetails: { paymentId?: string, deliveryMethodId: number }
) {
  await addToBasket(customer, productId, 1)
  if (discount != null) {
    const coupon = security.generateCoupon(discount)
    const couponRes = await request(app)
      .put(`/rest/basket/${customer.bid}/coupon/${encodeURIComponent(coupon)}`)
      .set(customer.header)
    assert.equal(couponRes.status, 200)
    assert.equal(couponRes.body.discount, discount)
  }
  const res = await request(app)
    .post(`/rest/basket/${customer.bid}/checkout`)
    .set(customer.header)
    .send({ orderDetails })
  return { status: res.status, body: res.body, text: res.text, orderConfirmation: res.body?.orderConfirmation as string | undefined }
}

async function placedOrder (token: string, orderId: string | undefined) {
  const res = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
  assert.equal(res.status, 200)
  return (res.body.data as Array<{ orderId: string, bonus: number, totalPrice: number, paymentId: string | null, promotionalAmount: string }>).find(order => order.orderId === orderId)
}
