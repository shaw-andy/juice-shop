/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { copyFileSync, readdirSync, unlinkSync } from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { ProductModel } from '../../models/product'
import { UserModel } from '../../models/user'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { HintModel } from '../../models/hint'
import * as security from '../../lib/insecurity'
import * as db from '../../data/mongodb'

const brokenName = '{{/x}}'
const brokenDescription = '{{/y}}'
const brokenCreatedName = '{{/z}}'
const brokenHint = '{{/h}}'

const nameProductId = 1
const descriptionProductId = 2
const safeProductId = 3
const basketId = 1

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let createdProductId: number
let hintId: number
let otherHintText: string
let pdfsBefore: Set<string>

function detail (res: { status: number, text?: string }) {
  return `status ${res.status} ${(res.text ?? '').slice(0, 400)}`
}

function orderPdfs () {
  return readdirSync('ftp').filter(name => name.startsWith('order_') && name.endsWith('.pdf'))
}

function restoreLocales () {
  for (const name of readdirSync('data/static/i18n')) {
    if (!name.endsWith('.json')) continue
    copyFileSync(path.join('data/static/i18n', name), path.join('i18n', name))
  }
  for (const name of readdirSync('i18n')) {
    if (name.endsWith('.tmp') || name.endsWith('.invalid')) {
      unlinkSync(path.join('i18n', name))
    }
  }
}

function removeCreatedPdfs () {
  if (pdfsBefore === undefined) return
  for (const name of orderPdfs()) {
    if (!pdfsBefore.has(name)) unlinkSync(path.join('ftp', name))
  }
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row)
  return Number(row.quantity)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  pdfsBefore = new Set(orderPdfs())

  const baseline = await request(app).get('/rest/products/search?q=')
  if (baseline.status !== 200 || !Array.isArray(baseline.body?.data) || baseline.body.data.length < 3) {
    throw new Error('catalog is not readable before any product is changed: ' + detail(baseline))
  }

  const user = await UserModel.findByPk(1, { attributes: ['id', 'email', 'role'] })
  const basket = await BasketModel.findOne({ where: { UserId: user?.id } })
  assert.equal(basket?.id, basketId)
  const authenticatedUser = {
    data: { id: user?.id, email: user?.email, role: user?.role },
    bid: basket?.id
  }
  const token = security.authorize(authenticatedUser)
  security.authenticatedUsers.put(token, authenticatedUser)
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

  const hints = await HintModel.findAll({ order: [['id', 'ASC']] })
  assert.ok(hints.length >= 2)
  hintId = hints[0].id
  otherHintText = hints[1].text

  const nameUpdate = await request(app)
    .put('/api/Products/' + nameProductId)
    .set('content-type', 'application/json')
    .send({ name: brokenName })
  if (nameUpdate.status !== 200) throw new Error('could not store product name: ' + detail(nameUpdate))

  const descriptionUpdate = await request(app)
    .put('/api/Products/' + descriptionProductId)
    .set('content-type', 'application/json')
    .send({ description: brokenDescription })
  if (descriptionUpdate.status !== 200) throw new Error('could not store product description: ' + detail(descriptionUpdate))

  const created = await request(app)
    .post('/api/Products')
    .set(authHeader)
    .send({
      name: brokenCreatedName,
      description: 'ordinary description',
      price: 1.23,
      deluxePrice: 1.23,
      image: 'created.jpg'
    })
  if (created.status !== 200 && created.status !== 201) throw new Error('could not create product: ' + detail(created))
  createdProductId = created.body.data.id

  const hintUpdate = await request(app)
    .put('/api/Hints/' + hintId)
    .set('content-type', 'application/json')
    .send({ text: brokenHint })
  if (hintUpdate.status !== 200) throw new Error('could not store hint text: ' + detail(hintUpdate))
}, { timeout: 60000 })

after(() => {
  restoreLocales()
  removeCreatedPdfs()
})

void describe('catalog text stored by a customer', () => {
  void it('PUT /api/Products/:id stores a product name without a login', async () => {
    const res = await request(app)
      .put('/api/Products/' + nameProductId)
      .set('content-type', 'application/json')
      .send({ name: brokenName })
    assert.equal(res.status, 200, detail(res))
    assert.equal(res.body.data.name, brokenName)
    const stored = await ProductModel.findByPk(nameProductId)
    assert.equal(stored?.name, brokenName)
  })

  void it('PUT /api/Products/:id stores a product description without a login', async () => {
    const res = await request(app)
      .put('/api/Products/' + descriptionProductId)
      .set('content-type', 'application/json')
      .send({ description: brokenDescription })
    assert.equal(res.status, 200, detail(res))
    assert.equal(res.body.data.description, brokenDescription)
    const stored = await ProductModel.findByPk(descriptionProductId)
    assert.equal(stored?.description, brokenDescription)
  })

  void it('POST /api/Products stores a product name for any signed-in user', async () => {
    const res = await request(app)
      .post('/api/Products')
      .set(authHeader)
      .send({
        name: brokenCreatedName,
        description: 'ordinary description',
        price: 1.23,
        deluxePrice: 1.23,
        image: 'created.jpg'
      })
    assert.ok(res.status === 200 || res.status === 201, detail(res))
    createdProductId = res.body.data.id
    assert.equal(typeof createdProductId, 'number')
    assert.equal(res.body.data.name, brokenCreatedName)
    const stored = await ProductModel.findByPk(createdProductId)
    assert.equal(stored?.name, brokenCreatedName)
  })

  void it('PUT /api/Hints/:id stores hint text without a login', async () => {
    const res = await request(app)
      .put('/api/Hints/' + hintId)
      .set('content-type', 'application/json')
      .send({ text: brokenHint })
    assert.equal(res.status, 200, detail(res))
    assert.equal(res.body.data.text, brokenHint)
    const stored = await HintModel.findByPk(hintId)
    assert.equal(stored?.text, brokenHint)
  })
})

void describe('reading catalog text that was stored as an unopened Mustache section', () => {
  void it('GET /rest/products/search returns every product, including the stored name and description', async () => {
    const res = await request(app).get('/rest/products/search?q=')
    assert.equal(res.status, 200, detail(res))
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const products = res.body.data
    assert.ok(Array.isArray(products))
    assert.equal(products.find((product: { id: number }) => product.id === safeProductId) !== undefined, true)
    assert.equal(products.find((product: { id: number }) => product.id === nameProductId)?.name, brokenName)
    assert.equal(products.find((product: { id: number }) => product.id === descriptionProductId)?.description, brokenDescription)
    assert.equal(products.find((product: { id: number }) => product.id === createdProductId)?.name, brokenCreatedName)
  })

  void it('GET /api/Products returns every product, including the stored name and description', async () => {
    const res = await request(app).get('/api/Products')
    assert.equal(res.status, 200, detail(res))
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const products = res.body.data
    assert.ok(Array.isArray(products))
    assert.equal(products.find((product: { id: number }) => product.id === safeProductId) !== undefined, true)
    assert.equal(products.find((product: { id: number }) => product.id === nameProductId)?.name, brokenName)
    assert.equal(products.find((product: { id: number }) => product.id === descriptionProductId)?.description, brokenDescription)
    assert.equal(products.find((product: { id: number }) => product.id === createdProductId)?.name, brokenCreatedName)
  })

  void it('GET /api/Products/:id returns the stored name', async () => {
    const res = await request(app).get('/api/Products/' + nameProductId)
    assert.equal(res.status, 200, detail(res))
    assert.equal(res.body.data.name, brokenName)
  })

  void it('GET /api/Products/:id returns the stored description', async () => {
    const res = await request(app).get('/api/Products/' + descriptionProductId)
    assert.equal(res.status, 200, detail(res))
    assert.equal(res.body.data.description, brokenDescription)
  })

  void it('GET /api/Products/:id returns a name created by a signed-in user', async () => {
    const res = await request(app).get('/api/Products/' + createdProductId)
    assert.equal(res.status, 200, detail(res))
    assert.equal(res.body.data.name, brokenCreatedName)
  })

  void it('GET /rest/basket/:id returns the stored product name', async () => {
    const res = await request(app).get('/rest/basket/' + basketId).set(authHeader)
    assert.equal(res.status, 200, detail(res))
    const products = res.body.data.Products
    assert.ok(Array.isArray(products))
    assert.equal(products.find((product: { id: number }) => product.id === nameProductId)?.name, brokenName)
    assert.equal(products.find((product: { id: number }) => product.id === safeProductId) !== undefined, true)
  })

  void it('POST /rest/basket/:id/checkout finishes the order and does not change stock or write an order file when it fails', async () => {
    const items = await BasketItemModel.findAll({ where: { BasketId: basketId } })
    const stockBefore = new Map<number, number>()
    for (const item of items) {
      stockBefore.set(item.ProductId, await stockOf(item.ProductId))
    }
    const res = await request(app).post('/rest/basket/' + basketId + '/checkout').set(authHeader)
    const createdPdfs = orderPdfs().filter(name => !pdfsBefore.has(name))
    if (res.status !== 200) {
      const problems: string[] = []
      if (createdPdfs.length > 0) problems.push('order file created: ' + createdPdfs.join(','))
      for (const item of items) {
        const afterQty = await stockOf(item.ProductId)
        const beforeQty = stockBefore.get(item.ProductId)
        if (afterQty !== beforeQty) problems.push('stock for product ' + item.ProductId + ' changed from ' + beforeQty + ' to ' + afterQty)
      }
      assert.deepEqual(problems, [], detail(res))
    }
    assert.equal(res.status, 200, detail(res))
    assert.equal(typeof res.body.orderConfirmation, 'string')
    const order = await db.ordersCollection.findOne({ orderId: res.body.orderConfirmation })
    const names = (order?.products ?? []).map((product: { name: string }) => product.name)
    assert.ok(names.includes(brokenName))
    for (const item of items) {
      assert.equal(await stockOf(item.ProductId), (stockBefore.get(item.ProductId) ?? 0) - item.quantity)
    }
  })

  void it('GET /api/Hints returns the stored hint text and the other hints', async () => {
    const res = await request(app).get('/api/Hints')
    assert.equal(res.status, 200, detail(res))
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const hints = res.body.data
    assert.ok(Array.isArray(hints))
    assert.equal(hints.find((hint: { id: number }) => hint.id === hintId)?.text, brokenHint)
    assert.equal(hints.some((hint: { text: string }) => hint.text === otherHintText), true)
  })
})
