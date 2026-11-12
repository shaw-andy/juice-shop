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
import config from 'config'
// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import * as utils from '../../lib/utils'

const placeholderPassword = 'placeholder-not-a-secret'
const itemQuantity = 1

let app: Express
let token: string
let userId: number
let productId: number

interface StoredOrder {
  orderId: string
  totalPrice: number
  promotionalAmount: number | string
  deliveryPrice?: number
  bonus: number
  products: Array<{ total: number, bonus: number }>
}

before(async () => {
  const created = await createTestApp()
  app = created.app
  const email = 'coupon-spec@' + config.get<string>('application.domain')
  await register(app, { email, password: placeholderPassword })
  const user = await UserModel.findOne({ where: { email } })
  if (user == null) {
    throw new Error('registered shopper was not stored')
  }
  userId = user.id
  await WalletModel.destroy({ where: { UserId: userId } })
  await WalletModel.create({ UserId: userId, balance: 0 })
  const authentication = await login(app, { email, password: placeholderPassword })
  token = authentication.token

  const quantities = await QuantityModel.findAll()
  const products = await ProductModel.findAll()
  const stocked = products
    .map(product => ({ product, stock: quantities.find(row => row.ProductId === product.id) }))
    .filter((row): row is { product: ProductModel, stock: QuantityModel } => row.stock != null && row.stock.quantity >= itemQuantity && Number(row.product.price) >= 5)
    .sort((a, b) => Number(b.product.price) - Number(a.product.price))
  const chosen = stocked[0]
  if (chosen == null) {
    throw new Error('no stocked product with a catalog price of at least 5')
  }
  productId = chosen.product.id
}, { timeout: 60000 })

void describe('client-encoded coupon discounts', () => {
  void it('PUT /rest/basket/:id/coupon/:coupon does not grant a client-encoded 99 percent discount', async () => {
    const basket = await createBasket()
    await assertCouponRejected(basket.id, '99')
  })

  void it('PUT /rest/basket/:id/coupon/:coupon does not grant a client-encoded single-digit discount', async () => {
    const basket = await createBasket()
    await assertCouponRejected(basket.id, '09')
  })

  void it('POST /rest/basket/:id/checkout does not charge 1 percent after the encoded coupon is applied', async () => {
    const basket = await createBasket()
    const encoded = clientEncodedDiscount('99')
    const applied = await request(app)
      .put('/rest/basket/' + basket.id + '/coupon/' + encodeURIComponent(encoded))
      .set(authHeader())
    assert.equal(applied.status < 500, true)
    await assertCheckoutChargesCatalogPrice(basket.id)
  })

  void it('POST /rest/basket/:id/checkout does not re-decode a stored 99 percent coupon', async () => {
    const basket = await createBasket()
    await BasketModel.update({ coupon: clientEncodedDiscount('99') }, { where: { id: basket.id } })
    await assertCheckoutChargesCatalogPrice(basket.id)
  })

  void it('POST /rest/basket/:id/checkout does not re-decode a stored single-digit coupon', async () => {
    const basket = await createBasket()
    await BasketModel.update({ coupon: clientEncodedDiscount('09') }, { where: { id: basket.id } })
    await assertCheckoutChargesCatalogPrice(basket.id)
  })
})

function clientEncodedDiscount (discount: string) {
  const plain = utils.toMMMYY(new Date()) + '-' + discount
  const encoded = z85.encode(plain)
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('encoder rejected a ' + String(plain.length) + ' character coupon plaintext')
  }
  return encoded
}

function authHeader () {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function createBasket () {
  const basket = await BasketModel.create({ UserId: userId })
  await BasketItemModel.create({ BasketId: basket.id, ProductId: productId, quantity: itemQuantity })
  return basket
}

async function assertCouponRejected (basketId: number, discount: string) {
  const encoded = clientEncodedDiscount(discount)
  const response = await request(app)
    .put('/rest/basket/' + basketId + '/coupon/' + encodeURIComponent(encoded))
    .set(authHeader())
  const reported = response.body != null && typeof response.body === 'object' ? Number(response.body.discount ?? 0) : 0
  const stored = await BasketModel.findByPk(basketId)
  assert.equal(reported, 0)
  assert.equal(stored?.coupon ?? null, null)
}

async function assertCheckoutChargesCatalogPrice (basketId: number) {
  const stockBefore = await stockOf(productId)
  const walletBefore = await walletBalance(userId)
  const pdfsBefore = orderPdfNames()
  const response = await request(app)
    .post('/rest/basket/' + basketId + '/checkout')
    .set(authHeader())
    .send({})
  const stockAfter = await stockOf(productId)
  const walletAfter = await walletBalance(userId)
  const createdPdfs = orderPdfNames().filter(name => !pdfsBefore.includes(name))
  try {
    if (response.status !== 200) {
      assert.equal(stockAfter, stockBefore)
      assert.equal(walletAfter, walletBefore)
      assert.deepEqual(createdPdfs, [])
      return
    }
    const order = await findOrder(String(response.body.orderConfirmation))
    const merchandise = order.products.reduce((sum, product) => sum + Number(product.total), 0)
    const delivery = Number(order.deliveryPrice ?? 0)
    const catalogTotal = merchandise + delivery
    assert.ok(
      Math.abs(Number(order.totalPrice) - catalogTotal) < 0.001 && Math.abs(Number(order.promotionalAmount)) < 0.001,
      'charged ' + String(order.totalPrice) + ' of catalog ' + String(catalogTotal) + ' promotionalAmount ' + String(order.promotionalAmount) + ' bonus ' + String(order.bonus) + ' walletDelta ' + String(walletAfter - walletBefore) + ' stockDelta ' + String(stockAfter - stockBefore)
    )
    assert.equal(stockAfter, stockBefore - itemQuantity)
    assert.equal(walletAfter - walletBefore, Number(order.bonus))
    assert.equal(createdPdfs.length, 1)
  } finally {
    for (const name of createdPdfs) {
      fs.unlinkSync(path.join('ftp', name))
    }
  }
}

async function findOrder (orderId: string) {
  const history = await request(app)
    .get('/rest/order-history')
    .set(authHeader())
  assert.equal(history.status, 200)
  const orders = (history.body.data ?? []) as StoredOrder[]
  const order = orders.find(row => row.orderId === orderId)
  if (order == null) {
    throw new Error('checkout confirmation was not stored on the order')
  }
  return order
}

async function stockOf (id: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: id } })
  if (row == null) {
    throw new Error('product has no stock row')
  }
  return row.quantity
}

async function walletBalance (id: number) {
  const rows = await WalletModel.findAll({ where: { UserId: id } })
  return rows.reduce((sum, row) => sum + Number(row.balance), 0)
}

function orderPdfNames () {
  return fs.readdirSync('ftp').filter(name => name.startsWith('order_') && name.endsWith('.pdf'))
}
