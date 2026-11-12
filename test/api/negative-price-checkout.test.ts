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
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import { UserModel } from '../../models/user'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { DeliveryModel } from '../../models/delivery'
import { ordersCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'password'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 120000 })

void describe('negative price must not mint wallet credit', { concurrency: 1 }, () => {
  void it('rejects a public product update that sets price below zero', async () => {
    const product = await createStockedProduct(4, 3)
    const res = await request(app)
      .put('/api/Products/' + product.id)
      .set(jsonHeader)
      .send({ price: -100000 })
    assert.ok(res.status >= 400)
    assert.ok(await storedPrice(product.id) >= 0)
  })

  void it('rejects a public product update that sets deluxe price below zero', async () => {
    const product = await createStockedProduct(4, 3)
    const res = await request(app)
      .put('/api/Products/' + product.id)
      .set(jsonHeader)
      .send({ deluxePrice: -100000 })
    assert.ok(res.status >= 400)
    assert.ok(await storedDeluxePrice(product.id) >= 0)
    assert.ok(await storedPrice(product.id) >= 0)
  })

  void it('still accepts a public product update that keeps both prices at or above zero', async () => {
    const product = await createStockedProduct(4, 3)
    const res = await request(app)
      .put('/api/Products/' + product.id)
      .set(jsonHeader)
      .send({ price: 2.5, deluxePrice: 1.5 })
    assert.equal(res.status, 200)
    assert.equal(await storedPrice(product.id), 2.5)
    assert.equal(await storedDeluxePrice(product.id), 1.5)
  })

  void it('rejects an authenticated product create with a price below zero', async () => {
    const name = uniqueName('create-price')
    const res = await request(app)
      .post('/api/Products')
      .set(authorizedHeader())
      .send({ name, description: 'fixture', price: -50, deluxePrice: 1, image: 'apple_juice.jpg' })
    assert.ok(res.status >= 400)
    assert.equal(await ProductModel.findOne({ where: { name } }), null)
  })

  void it('rejects an authenticated product create with a deluxe price below zero', async () => {
    const name = uniqueName('create-deluxe')
    const res = await request(app)
      .post('/api/Products')
      .set(authorizedHeader())
      .send({ name, description: 'fixture', price: 5, deluxePrice: -50, image: 'apple_juice.jpg' })
    assert.ok(res.status >= 400)
    assert.equal(await ProductModel.findOne({ where: { name } }), null)
  })

  void it('does not apply a negative price from the request body to a different product than the one in the URL', async () => {
    const target = await createStockedProduct(6, 5)
    const other = await createStockedProduct(7, 6)
    await request(app)
      .put('/api/Products/' + target.id)
      .set(jsonHeader)
      .send({
        id: other.id,
        name: 'hijacked',
        description: 'hijacked',
        price: -2500,
        deluxePrice: -2500,
        image: 'apple_juice.jpg'
      })
    assert.ok(await storedPrice(target.id) >= 0)
    assert.ok(await storedDeluxePrice(target.id) >= 0)
    assert.ok(await storedPrice(other.id) >= 0)
    assert.ok(await storedDeluxePrice(other.id) >= 0)
    assert.notEqual((await ProductModel.findByPk(other.id))?.name, 'hijacked')
  })

  void it('refuses wallet checkout of a negative regular price without crediting the wallet or changing stock', async () => {
    const customer = await registerCustomer(0)
    const product = await createStockedProduct(2, 2, 40)
    await ProductModel.update({ price: -100000 }, { where: { id: product.id } })
    const added = await addToBasket(customer, product.id, 3)
    assert.equal(added.status, 200)

    const outcome = await checkout(customer, { paymentId: 'wallet' })
    await assertNegativeOrderRefused(customer, product.id, 40, 0, outcome)
    await assertWalletCannotBuyAnything(customer)
  })

  void it('refuses wallet checkout of a negative deluxe price for a deluxe customer', async () => {
    const customer = await registerCustomer(0)
    await UserModel.update({
      role: security.roles.deluxe,
      deluxeToken: security.deluxeToken(customer.email)
    }, { where: { id: customer.userId } })
    const deluxe = await registerCustomer(0, customer.email)
    const product = await createStockedProduct(8, 8, 15)
    await ProductModel.update({ deluxePrice: -80000 }, { where: { id: product.id } })
    const added = await addToBasket(deluxe, product.id, 1)
    assert.equal(added.status, 200)

    const outcome = await checkout(deluxe, { paymentId: 'wallet' })
    await assertNegativeOrderRefused(deluxe, product.id, 15, 0, outcome)
  })

  void it('bills a non-deluxe customer the regular price when only the deluxe price is negative', async () => {
    const customer = await registerCustomer(100)
    const product = await createStockedProduct(5, 5, 15)
    await ProductModel.update({ deluxePrice: -80000 }, { where: { id: product.id } })
    const added = await addToBasket(customer, product.id, 1)
    assert.equal(added.status, 200)
    const beforePdfs = orderPdfNames()

    const outcome = await checkout(customer, { paymentId: 'wallet' })
    try {
      assert.equal(outcome.res.status, 200)
      assert.ok(outcome.balance <= 100)
      assert.ok(outcome.balance < 100)
      const orders = await ordersFor(customer.email)
      assert.ok(orders.every((order) => Number(order.totalPrice) >= 0))
    } finally {
      removeNewOrderPdfs(beforePdfs)
    }
  })

  void it('refuses wallet checkout when the price is changed to a negative value after the stock check', async () => {
    const customer = await registerCustomer(0)
    const product = await createStockedProduct(9, 9, 30)
    const added = await addToBasket(customer, product.id, 2)
    assert.equal(added.status, 200)
    await ProductModel.update({ price: -100000 }, { where: { id: product.id } })

    const outcome = await checkout(customer, { paymentId: 'wallet' })
    await assertNegativeOrderRefused(customer, product.id, 30, 0, outcome)
  })

  void it('refuses wallet checkout of a negative quantity without crediting the wallet or changing stock', async () => {
    const customer = await registerCustomer(0)
    const product = await createStockedProduct(12, 12, 25)
    const added = await addToBasket(customer, product.id, -4)
    assert.equal(added.status, 200)

    const outcome = await checkout(customer, { paymentId: 'wallet' })
    await assertNegativeOrderRefused(customer, product.id, 25, 0, outcome)
  })

  void it('refuses a non-wallet checkout whose total is below zero', async () => {
    const customer = await registerCustomer(40)
    const product = await createStockedProduct(6, 6, 18)
    await ProductModel.update({ price: -100000 }, { where: { id: product.id } })
    const added = await addToBasket(customer, product.id, 1)
    assert.equal(added.status, 200)

    const outcome = await checkout(customer, { paymentId: 'card' })
    await assertNegativeOrderRefused(customer, product.id, 18, 40, outcome)
  })

  void it('refuses wallet checkout when a negative delivery price makes the total negative', async () => {
    const customer = await registerCustomer(0)
    const product = await createStockedProduct(5, 5, 12)
    const delivery = await DeliveryModel.create({
      name: uniqueName('delivery'),
      price: -80,
      deluxePrice: 0,
      eta: 1,
      icon: 'fas fa-truck'
    })
    const added = await addToBasket(customer, product.id, 1)
    assert.equal(added.status, 200)

    const outcome = await checkout(customer, { paymentId: 'wallet', deliveryMethodId: delivery.id })
    await assertNegativeOrderRefused(customer, product.id, 12, 0, outcome)
  })

  void it('refuses wallet checkout of a basket that mixes a negative line with a positive line', async () => {
    const customer = await registerCustomer(0)
    const negative = await createStockedProduct(4, 4, 10)
    const positive = await createStockedProduct(3, 3, 10)
    await ProductModel.update({ price: -40 }, { where: { id: negative.id } })
    assert.equal((await addToBasket(customer, negative.id, 1)).status, 200)
    assert.equal((await addToBasket(customer, positive.id, 1)).status, 200)

    const beforePdfs = orderPdfNames()
    const res = await request(app)
      .post('/rest/basket/' + customer.bid + '/checkout')
      .set(authHeader(customer.token))
      .send({ orderDetails: { paymentId: 'wallet' } })
    const createdPdfs = orderPdfNames().filter((name) => !beforePdfs.includes(name))
    try {
      assert.ok(res.status >= 400)
      assert.equal(res.body?.orderConfirmation, undefined)
      assert.equal(await balanceOf(customer.userId), 0)
      assert.equal(await stockOf(negative.id), 10)
      assert.equal(await stockOf(positive.id), 10)
      assert.equal(createdPdfs.length, 0)
      assert.equal((await ordersFor(customer.email)).length, 0)
      const negativeItem = await BasketItemModel.findOne({ where: { BasketId: customer.bid, ProductId: negative.id } })
      const positiveItem = await BasketItemModel.findOne({ where: { BasketId: customer.bid, ProductId: positive.id } })
      assert.ok(negativeItem)
      assert.ok(positiveItem)
    } finally {
      for (const name of createdPdfs) fs.unlinkSync(path.join('ftp', name))
    }
  })

  void it('does not credit the wallet when the product price changes after checkout has loaded the line', async () => {
    const customer = await registerCustomer(100)
    const product = await createStockedProduct(20, 20, 20)
    assert.equal((await addToBasket(customer, product.id, 1)).status, 200)
    const beforePdfs = orderPdfNames()
    let armed = true
    const hookName = 'flip-price-after-basket-load-' + product.id
    BasketModel.addHook('afterFind', hookName, async () => {
      if (!armed) return
      armed = false
      await ProductModel.update({ price: -5000, deluxePrice: -5000 }, { where: { id: product.id }, hooks: false })
    })
    try {
      const res = await request(app)
        .post('/rest/basket/' + customer.bid + '/checkout')
        .set(authHeader(customer.token))
        .send({ orderDetails: { paymentId: 'wallet' } })
      const balance = await balanceOf(customer.userId)
      assert.equal(await storedPrice(product.id), -5000)
      assert.equal(await storedDeluxePrice(product.id), -5000)
      assert.ok(balance <= 100)
      const orders = await ordersFor(customer.email)
      if (res.status >= 400) {
        assert.equal(balance, 100)
        assert.equal(orders.length, 0)
      }
      assert.ok(orders.every((order) => Number(order.totalPrice) >= 0))
    } finally {
      BasketModel.removeHook('afterFind', hookName)
      removeNewOrderPdfs(beforePdfs)
    }
  })

  void it('follows the public price update into wallet checkout and a later purchase', async () => {
    const customer = await registerCustomer(0)
    const product = await createStockedProduct(1.5, 1, 20)
    const updated = await request(app)
      .put('/api/Products/' + product.id)
      .set(jsonHeader)
      .send({ price: -100000 })
    const price = await storedPrice(product.id)
    const added = await addToBasket(customer, product.id, 2)
    assert.equal(added.status, 200)
    const outcome = await checkout(customer, { paymentId: 'wallet' })
    if (price < 0) {
      await assertNegativeOrderRefused(customer, product.id, 20, 0, outcome)
    }
    assert.ok(updated.status >= 400)
    assert.ok(price >= 0)
    assert.equal(await balanceOf(customer.userId), 0)
    await assertWalletCannotBuyAnything(customer)
  })
})

interface Customer {
  email: string
  token: string
  bid: number
  userId: number
}

async function registerCustomer (openingBalance: number, email = uniqueName('buyer') + '@juice-sh.op'): Promise<Customer> {
  const existing = await UserModel.findOne({ where: { email } })
  if (existing == null) {
    await register(app, { email, password: placeholderPassword })
  }
  const auth = await login(app, { email, password: placeholderPassword })
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  let wallet = await WalletModel.findOne({ where: { UserId: user.id } })
  if (wallet == null) {
    wallet = await WalletModel.create({ UserId: user.id, balance: openingBalance })
  } else {
    await wallet.update({ balance: openingBalance })
  }
  return { email, token: auth.token, bid: auth.bid, userId: user.id }
}

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function authorizedHeader () {
  return { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
}

function uniqueName (prefix: string) {
  return prefix + '-' + Date.now().toString(36) + '-' + Math.random().toString(16).slice(2)
}

async function createStockedProduct (price: number, deluxePrice: number, stock = 20) {
  const product = await ProductModel.create({
    name: uniqueName('product'),
    description: 'fixture',
    price,
    deluxePrice,
    image: 'apple_juice.jpg'
  })
  await QuantityModel.create({ ProductId: product.id, quantity: stock, limitPerUser: null })
  return product
}

async function storedPrice (productId: number) {
  const product = await ProductModel.findByPk(productId)
  assert.ok(product)
  return Number(product.price)
}

async function storedDeluxePrice (productId: number) {
  const product = await ProductModel.findByPk(productId)
  assert.ok(product)
  return Number(product.deluxePrice)
}

async function addToBasket (customer: Customer, productId: number, quantity: number) {
  return await request(app)
    .post('/api/BasketItems')
    .set(authHeader(customer.token))
    .send({ ProductId: productId, BasketId: customer.bid, quantity })
}

async function balanceOf (userId: number) {
  const wallet = await WalletModel.findOne({ where: { UserId: userId } })
  assert.ok(wallet)
  return Number(wallet.balance)
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row)
  return Number(row.quantity)
}

async function ordersFor (email: string): Promise<Array<{ totalPrice: number }>> {
  const masked = email.replace(/[aeiou]/gi, '*')
  return await ordersCollection.find({ email: masked })
}

function orderPdfNames () {
  return fs.readdirSync('ftp').filter((name) => name.startsWith('order_') && name.endsWith('.pdf'))
}

function removeNewOrderPdfs (before: string[]) {
  for (const name of orderPdfNames()) {
    if (!before.includes(name)) fs.unlinkSync(path.join('ftp', name))
  }
}

interface CheckoutOutcome {
  res: request.Response
  balance: number
  createdPdfs: string[]
}

async function checkout (customer: Customer, orderDetails: { paymentId: string, deliveryMethodId?: number }): Promise<CheckoutOutcome> {
  const beforePdfs = orderPdfNames()
  const res = await request(app)
    .post('/rest/basket/' + customer.bid + '/checkout')
    .set(authHeader(customer.token))
    .send({ orderDetails })
  return {
    res,
    balance: await balanceOf(customer.userId),
    createdPdfs: orderPdfNames().filter((name) => !beforePdfs.includes(name))
  }
}

async function assertNegativeOrderRefused (customer: Customer, productId: number, stock: number, openingBalance: number, outcome: CheckoutOutcome) {
  try {
    assert.ok(outcome.res.status >= 400)
    assert.equal(outcome.res.body?.orderConfirmation, undefined)
    assert.equal(outcome.balance, openingBalance)
    assert.equal(await stockOf(productId), stock)
    assert.equal(outcome.createdPdfs.length, 0)
    assert.equal((await ordersFor(customer.email)).length, 0)
    const item = await BasketItemModel.findOne({ where: { BasketId: customer.bid, ProductId: productId } })
    assert.ok(item)
  } finally {
    for (const name of outcome.createdPdfs) fs.unlinkSync(path.join('ftp', name))
  }
}

async function assertWalletCannotBuyAnything (customer: Customer) {
  const product = await createStockedProduct(1, 1, 5)
  const added = await addToBasket(customer, product.id, 1)
  assert.equal(added.status, 200)
  const beforePdfs = orderPdfNames()
  const outcome = await checkout(customer, { paymentId: 'wallet' })
  try {
    assert.ok(outcome.res.status >= 400)
    assert.equal(outcome.res.body?.orderConfirmation, undefined)
    assert.equal(outcome.balance, 0)
  } finally {
    removeNewOrderPdfs(beforePdfs)
  }
}
