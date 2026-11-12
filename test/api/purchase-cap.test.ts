/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { BasketItemModel } from '../../models/basketitem'
import * as db from '../../data/mongodb'

let app: Express

const PLACEHOLDER_PASSWORD = 'placeholder-password'
const CAPPED_PRODUCT_NAME = 'Melon Bike (Comeback-Product 2018 Edition)'
const OTHER_PRODUCT_NAME = 'Apple Juice (1000ml)'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function customer () {
  const email = `cap-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const auth = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  return {
    email,
    bid: auth.bid as number,
    header: {
      Authorization: 'Bearer ' + auth.token,
      'content-type': 'application/json'
    }
  }
}

async function cappedProduct () {
  const product = await ProductModel.findOne({ where: { name: CAPPED_PRODUCT_NAME } })
  assert.ok(product)
  const row = await QuantityModel.findOne({ where: { ProductId: product.id } })
  assert.ok(row)
  assert.ok(row.limitPerUser != null && row.limitPerUser > 0)
  await row.update({ quantity: row.limitPerUser + 4 })
  return { productId: product.id, limit: row.limitPerUser }
}

async function linesFor (basketId: number, productId: number) {
  return await BasketItemModel.findAll({ where: { BasketId: basketId, ProductId: productId } })
}

function totalQuantity (lines: Array<{ quantity: number }>) {
  return lines.reduce((sum, line) => sum + line.quantity, 0)
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row)
  return row.quantity
}

function orderPdfs () {
  return fs.readdirSync('ftp').filter(name => name.startsWith('order_') && name.endsWith('.pdf'))
}

async function ordersFor (email: string) {
  const masked = email.replace(/[aeiou]/gi, '*')
  return await db.ordersCollection.find({ email: masked }) as Array<{ orderId: string, products: Array<{ id?: number, quantity: number }> }>
}

void describe('per-customer purchase cap', () => {
  void it('refuses a single add whose own quantity is already over the cap', async () => {
    const user = await customer()
    const { productId, limit } = await cappedProduct()

    const res = await request(app)
      .post('/api/BasketItems')
      .set(user.header)
      .send({ ProductId: productId, BasketId: user.bid, quantity: limit + 1 })

    assert.equal(res.status, 400)
    assert.equal(totalQuantity(await linesFor(user.bid, productId)), 0)
  })

  void it('does not order more than the cap when the same product is added once per unit', async () => {
    const user = await customer()
    const { productId, limit } = await cappedProduct()
    const stockBefore = await stockOf(productId)
    const pdfsBefore = new Set(orderPdfs())

    try {
      for (let i = 0; i < limit + 1; i++) {
        await request(app)
          .post('/api/BasketItems')
          .set(user.header)
          .send({ ProductId: productId, BasketId: user.bid, quantity: 1 })
      }

      const stored = await linesFor(user.bid, productId)
      assert.ok(totalQuantity(stored) <= limit)
      await assert.rejects(
        BasketItemModel.create({ ProductId: productId, BasketId: user.bid, quantity: 1 }),
        (error: unknown) => {
          const err = error as { name?: string, parent?: { message?: string } }
          assert.equal(err.name, 'SequelizeUniqueConstraintError')
          assert.match(err.parent?.message ?? '', /UNIQUE constraint failed: BasketItems\.ProductId, BasketItems\.BasketId/)
          return true
        }
      )

      const checkout = await request(app)
        .post('/rest/basket/' + user.bid + '/checkout')
        .set(user.header)
        .send({})
      const orders = await ordersFor(user.email)
      const ordered = orders.reduce((sum, order) => {
        return sum + order.products.filter(product => product.id === productId).reduce((inner, product) => inner + product.quantity, 0)
      }, 0)

      assert.equal(checkout.status, 200)
      assert.ok(ordered <= limit)
      assert.ok((stockBefore - await stockOf(productId)) <= limit)
    } finally {
      for (const name of orderPdfs()) {
        if (!pdfsBefore.has(name)) fs.unlinkSync(path.join('ftp', name))
      }
    }
  })

  void it('stores only a quantity that itself passed the cap check', async () => {
    const user = await customer()
    const { productId, limit } = await cappedProduct()
    const body = JSON.stringify({
      ProductId: productId,
      BasketId: user.bid,
      quantity: 1,
      extra: { quantity: limit + 2 }
    })

    const res = await request(app)
      .post('/api/BasketItems')
      .set(user.header)
      .send(body)
    const lines = await linesFor(user.bid, productId)

    assert.ok(totalQuantity(lines) <= limit, `stored ${totalQuantity(lines)} of product ${productId} after status ${res.status}`)
    for (const line of lines) {
      assert.ok(line.quantity <= limit)
    }
  })

  void it('stores the product whose cap was checked, not a different product from the same body', async () => {
    const user = await customer()
    const { productId, limit } = await cappedProduct()
    const other = await ProductModel.findOne({ where: { name: OTHER_PRODUCT_NAME } })
    assert.ok(other)
    const body = JSON.stringify({
      ProductId: other.id,
      BasketId: user.bid,
      quantity: 1,
      extra: { ProductId: productId, quantity: limit + 2 }
    })

    await request(app)
      .post('/api/BasketItems')
      .set(user.header)
      .send(body)

    assert.ok(totalQuantity(await linesFor(user.bid, productId)) <= limit)
  })

  void it('refuses to raise an existing line above the cap', async () => {
    const user = await customer()
    const { productId, limit } = await cappedProduct()
    const created = await request(app)
      .post('/api/BasketItems')
      .set(user.header)
      .send({ ProductId: productId, BasketId: user.bid, quantity: 1 })
    assert.equal(created.status, 200)

    const updated = await request(app)
      .put('/api/BasketItems/' + created.body.data.id)
      .set(user.header)
      .send({ quantity: limit + 1 })

    assert.equal(updated.status, 400)
    assert.ok(totalQuantity(await linesFor(user.bid, productId)) <= limit)
  })

  void it('refuses checkout of a basket already over the cap before stock, order, or file side effects', async () => {
    const user = await customer()
    const { productId, limit } = await cappedProduct()
    const stockBefore = await stockOf(productId)
    const pdfsBefore = new Set(orderPdfs())
    const ordersBefore = new Set((await ordersFor(user.email)).map(order => order.orderId))
    await BasketItemModel.create({ ProductId: productId, BasketId: user.bid, quantity: limit + 2 })
    const linesBefore = await linesFor(user.bid, productId)
    assert.ok(totalQuantity(linesBefore) > limit)

    try {
      const checkout = await request(app)
        .post('/rest/basket/' + user.bid + '/checkout')
        .set(user.header)
        .send({})
      const linesAfter = await linesFor(user.bid, productId)
      const newOrders = (await ordersFor(user.email)).filter(order => !ordersBefore.has(order.orderId))
      const newPdfs = orderPdfs().filter(name => !pdfsBefore.has(name))

      assert.ok(checkout.status >= 400)
      assert.equal(await stockOf(productId), stockBefore)
      assert.equal(newOrders.length, 0)
      assert.equal(newPdfs.length, 0)
      assert.equal(totalQuantity(linesAfter), totalQuantity(linesBefore))
    } finally {
      for (const name of orderPdfs()) {
        if (!pdfsBefore.has(name)) fs.unlinkSync(path.join('ftp', name))
      }
    }
  })
})
