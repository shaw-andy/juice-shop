/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { QueryTypes, type Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { ordersCollection } from '../../data/mongodb'

const ftpDir = path.resolve('ftp')
const placeholderPassword = 'placeholder-password'

interface ProductRow {
  id: number
  name: string
  deletedAt: string | null
  quantity: number | null
  limitPerUser: number | null
}

interface StoredOrder {
  _id?: unknown
  orderId?: string
  products?: Array<{ id?: number, name?: string }>
}

interface Customer {
  bid: number
  header: { Authorization: string, 'content-type': string }
}

let app: Express
let sequelize: Sequelize
let products: ProductRow[]
let deleted: ProductRow[]
let withdrawn: ProductRow[]
let forSale: ProductRow
const createdPdfs = new Set<string>()

function orderPdfs () {
  return fs.readdirSync(ftpDir).filter((name) => name.startsWith('order_') && name.endsWith('.pdf'))
}

function rememberNewPdfs (before: Set<string>) {
  for (const name of orderPdfs()) {
    if (!before.has(name)) createdPdfs.add(name)
  }
}

async function customer (): Promise<Customer> {
  const email = `withdrawn-buyer-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  await register(app, { email, password: placeholderPassword })
  const { token, bid } = await login(app, { email, password: placeholderPassword })
  return {
    bid,
    header: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  }
}

async function loadProducts () {
  return await sequelize.query<ProductRow>(
    `SELECT p.id, p.name, p.deletedAt, q.quantity, q.limitPerUser
     FROM Products p
     LEFT JOIN Quantities q ON q.ProductId = p.id`,
    { type: QueryTypes.SELECT }
  )
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row, `expected a stock row for product ${productId}`)
  return row.quantity
}

async function storedOrders (): Promise<StoredOrder[]> {
  return await ordersCollection.find() as StoredOrder[]
}

function orderKey (order: StoredOrder) {
  return String(order.orderId ?? order._id)
}

function productIdsOn (orders: StoredOrder[]) {
  return orders.flatMap((order) => (order.products ?? []).map((product) => product.id))
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
  products = await loadProducts()
  deleted = products.filter((product) => product.deletedAt != null)
  withdrawn = deleted.filter((product) => (product.quantity ?? 0) >= 1)
  const saleable = products.filter((product) => product.deletedAt == null && (product.quantity ?? 0) >= 5 && (product.limitPerUser == null || product.limitPerUser >= 5))
  assert.ok(saleable.length >= 2)
  forSale = saleable[0]
}, { timeout: 60000 })

after(() => {
  for (const name of createdPdfs) {
    fs.rmSync(path.join(ftpDir, name), { force: true })
  }
})

void describe('products withdrawn from the catalog', { concurrency: false }, () => {
  void it('are absent from the public catalog while stock rows remain', async () => {
    const christmas = products.find((product) => product.name.includes('Christmas Super-Surprise-Box'))
    const rippertuer = products.find((product) => product.name.includes('Rippertuer Special Juice'))
    assert.ok(christmas)
    assert.ok(rippertuer)
    assert.ok(christmas.deletedAt)
    assert.ok(rippertuer.deletedAt)
    assert.ok((christmas.quantity ?? 0) >= 1)
    assert.ok((rippertuer.quantity ?? 0) >= 1)

    const list = await request(app).get('/api/Products')
    assert.equal(list.status, 200)
    const listedIds = (list.body.data as Array<{ id: number }>).map((product) => product.id)
    for (const product of deleted) {
      assert.equal(listedIds.includes(product.id), false)

      const read = await request(app).get('/api/Products/' + product.id)
      assert.equal(read.status, 404)

      const search = await request(app).get('/rest/products/search').query({ q: product.name })
      assert.equal(search.status, 200)
      const foundIds = (search.body.data as Array<{ id: number }>).map((row) => row.id)
      assert.equal(foundIds.includes(product.id), false)
    }
  })

  void it('cannot be added to a basket by product id', async () => {
    const buyer = await customer()
    for (const product of withdrawn) {
      assert.ok((await stockOf(product.id)) >= 1)
      const res = await request(app)
        .post('/api/BasketItems')
        .set(buyer.header)
        .send({ BasketId: buyer.bid, ProductId: product.id, quantity: 1 })
      const lines = await BasketItemModel.findAll({ where: { BasketId: buyer.bid, ProductId: product.id } })
      assert.ok(res.status >= 400, `withdrawn product ${product.id} was accepted with status ${res.status}`)
      assert.equal(lines.length, 0)
    }
  })

  void it('cannot be added when the stock check is shown a different product id than the line that is saved', async () => {
    const buyer = await customer()
    const target = withdrawn[0]
    assert.ok(target)
    assert.ok((await stockOf(forSale.id)) >= 1)
    assert.ok((await stockOf(target.id)) >= 1)
    const raw = `{"ProductId":${forSale.id},"BasketId":${buyer.bid},"quantity":1,"note":{"ProductId":${target.id}}}`
    const parsed = JSON.parse(raw) as { ProductId: number, note: { ProductId: number } }
    assert.equal(parsed.ProductId, forSale.id)
    assert.equal(parsed.note.ProductId, target.id)
    assert.notEqual(parsed.ProductId, parsed.note.ProductId)

    const res = await request(app)
      .post('/api/BasketItems')
      .set(buyer.header)
      .send(raw)
    const lines = await BasketItemModel.findAll({ where: { BasketId: buyer.bid } })
    assert.equal(lines.some((line) => line.ProductId === target.id), false)
    assert.ok(res.status >= 400 || lines.every((line) => line.ProductId === forSale.id))
    if (res.status < 400) {
      assert.equal(lines.length, 1)
      assert.equal(lines[0].ProductId, forSale.id)
    }
  })

  void it('can still be added and checked out when the product is for sale', async () => {
    const buyer = await customer()
    const beforeStock = await stockOf(forSale.id)
    const beforePdfs = new Set(orderPdfs())
    const beforeOrders = new Set((await storedOrders()).map(orderKey))
    const added = await request(app)
      .post('/api/BasketItems')
      .set(buyer.header)
      .send({ BasketId: buyer.bid, ProductId: forSale.id, quantity: 1 })
    assert.equal(added.status, 200)
    assert.equal(added.body.data.ProductId, forSale.id)

    const res = await request(app)
      .post('/rest/basket/' + buyer.bid + '/checkout')
      .set(buyer.header)
      .send({})
    rememberNewPdfs(beforePdfs)
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.orderConfirmation, 'string')
    const created = (await storedOrders()).filter((order) => !beforeOrders.has(orderKey(order)))
    assert.equal(created.length, 1)
    assert.ok(productIdsOn(created).includes(forSale.id))
    assert.equal(await stockOf(forSale.id), beforeStock - 1)
  })

  void it('cannot have its basket quantity increased', async () => {
    const buyer = await customer()
    const product = withdrawn[0]
    const line = await BasketItemModel.create({ BasketId: buyer.bid, ProductId: product.id, quantity: 1 })
    const res = await request(app)
      .put('/api/BasketItems/' + line.id)
      .set(buyer.header)
      .send({ quantity: 2 })
    const saved = await BasketItemModel.findByPk(line.id)
    assert.ok(res.status >= 400)
    assert.ok(saved)
    assert.equal(saved.quantity, 1)
    assert.equal(saved.ProductId, product.id)
  })

  void it('cannot be purchased from a basket line, and checkout leaves no order, stock change, file, or deleted line', async () => {
    for (const product of deleted) {
      const buyer = await customer()
      const beforeStock = await stockOf(product.id)
      const line = await BasketItemModel.create({ BasketId: buyer.bid, ProductId: product.id, quantity: 1 })
      const beforePdfs = new Set(orderPdfs())
      const beforeOrders = new Set((await storedOrders()).map(orderKey))
      const res = await request(app)
        .post('/rest/basket/' + buyer.bid + '/checkout')
        .set(buyer.header)
        .send({})
      rememberNewPdfs(beforePdfs)
      const saved = await BasketItemModel.findByPk(line.id)
      const created = (await storedOrders()).filter((order) => !beforeOrders.has(orderKey(order)))
      const newPdfs = orderPdfs().filter((name) => !beforePdfs.has(name))
      assert.ok(res.status >= 400, `checkout of withdrawn product ${product.id} returned ${res.status}`)
      assert.equal(res.body?.orderConfirmation, undefined)
      assert.equal(created.length, 0)
      assert.equal(productIdsOn(created).includes(product.id), false)
      assert.equal(await stockOf(product.id), beforeStock)
      assert.deepEqual(newPdfs, [])
      assert.ok(saved)
      assert.equal(saved.ProductId, product.id)
      assert.equal(saved.quantity, 1)
    }
  })

  void it('cannot be purchased after it is soft-deleted from the catalog', async () => {
    const product = products.find((row) => row.deletedAt == null && row.id !== forSale.id && (row.quantity ?? 0) >= 1)
    assert.ok(product)
    await ProductModel.destroy({ where: { id: product.id } })
    const gone = await ProductModel.findByPk(product.id)
    assert.equal(gone, null)
    assert.ok((await stockOf(product.id)) >= 1)

    const buyer = await customer()
    const added = await request(app)
      .post('/api/BasketItems')
      .set(buyer.header)
      .send({ BasketId: buyer.bid, ProductId: product.id, quantity: 1 })
    const lines = await BasketItemModel.findAll({ where: { BasketId: buyer.bid, ProductId: product.id } })
    assert.ok(added.status >= 400)
    assert.equal(lines.length, 0)

    const beforeStock = await stockOf(product.id)
    const line = await BasketItemModel.create({ BasketId: buyer.bid, ProductId: product.id, quantity: 1 })
    const beforePdfs = new Set(orderPdfs())
    const beforeOrders = new Set((await storedOrders()).map(orderKey))
    const res = await request(app)
      .post('/rest/basket/' + buyer.bid + '/checkout')
      .set(buyer.header)
      .send({})
    rememberNewPdfs(beforePdfs)
    const created = (await storedOrders()).filter((order) => !beforeOrders.has(orderKey(order)))
    assert.ok(res.status >= 400)
    assert.equal(created.length, 0)
    assert.equal(await stockOf(product.id), beforeStock)
    assert.deepEqual(orderPdfs().filter((name) => !beforePdfs.has(name)), [])
    const saved = await BasketItemModel.findByPk(line.id)
    assert.ok(saved)
    assert.equal(saved.quantity, 1)
  })

  void it('are not returned as lines of a basket', async () => {
    const buyer = await customer()
    const product = withdrawn[0]
    await BasketItemModel.create({ BasketId: buyer.bid, ProductId: product.id, quantity: 1 })
    const res = await request(app)
      .get('/rest/basket/' + buyer.bid)
      .set(buyer.header)
    assert.equal(res.status, 200)
    const basketProducts = (res.body.data?.Products ?? []) as Array<{ id: number }>
    assert.equal(basketProducts.some((row) => row.id === product.id), false)
  })
})
