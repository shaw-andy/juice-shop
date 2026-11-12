/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketModel } from '../../models/basket'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

const placeholderPassword = 'placeholder-password'
const ownerDiscount = 10
const otherDiscount = 40

let app: Express
let productId: number

interface Customer {
  token: string
  bid: number
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const products = await ProductModel.findAll()
  const quantities = await QuantityModel.findAll()
  const product = products.find((candidate) => {
    const stock = quantities.find((row) => row.ProductId === candidate.id)
    return Number(candidate.price) >= 1 && stock != null && stock.quantity >= 5 && (stock.limitPerUser == null || stock.limitPerUser >= 1)
  })
  assert.ok(product, 'expected a stocked product to put in a basket')
  productId = product.id
}, { timeout: 60000 })

void describe('PUT /rest/basket/:id/coupon/:coupon authorization', { concurrency: 1 }, () => {
  void it('applies a valid coupon to the basket id from the caller session', async () => {
    const customer = await registerCustomer('owner-own')
    const coupon = security.generateCoupon(ownerDiscount)

    const res = await putCoupon(customer, customer.bid, coupon)

    assert.equal(res.status, 200)
    assert.equal(res.body.discount, ownerDiscount)
    assert.equal(await couponOf(customer.bid), coupon)
  })

  void it('does not replace another customer basket coupon when the caller is signed in', async () => {
    const owner = await registerCustomer('owner-replace')
    const other = await registerCustomer('other-replace')
    assert.notEqual(owner.bid, other.bid)
    const ownerCoupon = security.generateCoupon(ownerDiscount)
    const otherCoupon = security.generateCoupon(otherDiscount)
    assert.equal((await putCoupon(owner, owner.bid, ownerCoupon)).status, 200)

    const attack = await putCoupon(other, owner.bid, otherCoupon)

    assert.equal(await couponOf(owner.bid), ownerCoupon)
    assert.equal(await couponOf(other.bid), null)
    assert.ok(attack.status === 401 || attack.status === 403, `expected rejection, got ${attack.status}`)
    assert.notEqual(attack.body?.discount, otherDiscount)
  })

  void it('charges checkout from the coupon the basket owner stored, after another customer sends a different code', async () => {
    const owner = await registerCustomer('owner-charge')
    const other = await registerCustomer('other-charge')
    assert.notEqual(owner.bid, other.bid)
    await addOneProduct(owner)
    assert.equal((await putCoupon(owner, owner.bid, security.generateCoupon(ownerDiscount))).status, 200)
    const attack = await putCoupon(other, owner.bid, security.generateCoupon(otherDiscount))

    const order = await checkout(owner)
    const gross = lineItemGross(order)
    const delivery = Number(order.deliveryPrice)
    const charged = Number(order.totalPrice)
    const ownerTotal = totalAfterCoupon(gross, ownerDiscount) + delivery
    const otherTotal = totalAfterCoupon(gross, otherDiscount) + delivery

    assert.ok(gross > 0)
    assert.notEqual(ownerTotal, otherTotal)
    assert.equal(charged, ownerTotal)
    assert.equal(order.promotionalAmount, discountAmount(gross, ownerDiscount))
    assert.equal(await couponOf(other.bid), null)
    assert.ok(attack.status === 401 || attack.status === 403, `expected rejection, got ${attack.status}`)
  })
})

async function registerCustomer (label: string): Promise<Customer> {
  const email = `coupon-${label}-${crypto.randomBytes(8).toString('hex')}@example.test`
  await register(app, { email, password: placeholderPassword })
  const authentication = await login(app, { email, password: placeholderPassword })
  assert.equal(typeof authentication.bid, 'number')
  assert.equal(typeof authentication.token, 'string')
  return { token: authentication.token, bid: authentication.bid }
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function putCoupon (customer: Customer, basketId: number, coupon: string) {
  return await request(app)
    .put(`/rest/basket/${basketId}/coupon/${encodeURIComponent(coupon)}`)
    .set(bearer(customer.token))
    .send({})
}

async function couponOf (basketId: number) {
  const basket = await BasketModel.findByPk(basketId)
  assert.ok(basket)
  return basket.coupon ?? null
}

async function addOneProduct (customer: Customer) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(bearer(customer.token))
    .send({ BasketId: customer.bid, ProductId: productId, quantity: 1 })
  assert.equal(res.status, 200)
}

async function checkout (customer: Customer) {
  const res = await request(app)
    .post(`/rest/basket/${customer.bid}/checkout`)
    .set(bearer(customer.token))
    .send({})
  assert.equal(res.status, 200)
  const orders = await db.ordersCollection.find({ orderId: res.body.orderConfirmation })
  assert.equal(orders.length, 1)
  return orders[0]
}

function lineItemGross (order: { products: Array<{ total: number }> }) {
  return order.products.reduce((sum, product) => sum + Number(product.total), 0)
}

function discountAmount (gross: number, percent: number) {
  return (gross * (percent / 100)).toFixed(2)
}

function totalAfterCoupon (gross: number, percent: number) {
  return gross - parseFloat(discountAmount(gross, percent))
}
