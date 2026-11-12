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
import { ProductModel } from '../../models/product'
import * as security from '../../lib/insecurity'

let app: Express
let customerHeader: Record<string, string>
let basketId: number

const jsonHeader = { 'content-type': 'application/json' }
const buyerEmail = 'buyer@example.test'
const placeholderPassword = 'placeholder-password'
const descriptionMarkup = '<iframe src="javascript:alert(`xss`)"></iframe><img src="x" onerror="window.__productDescriptionRan=1">'

before(async () => {
  const result = await createTestApp()
  app = result.app
  await register(app, { email: buyerEmail, password: placeholderPassword })
  const session = await login(app, { email: buyerEmail, password: placeholderPassword })
  customerHeader = { Authorization: 'Bearer ' + session.token, 'content-type': 'application/json' }
  basketId = session.bid
}, { timeout: 60000 })

async function readProduct (id: number) {
  const res = await request(app).get('/api/Products/' + id)
  assert.equal(res.status, 200)
  return res.body.data
}

async function restoreProduct (id: number, original: { name: string, description: string, price: number, deluxePrice: number, image: string }) {
  await ProductModel.update({
    name: original.name,
    description: original.description,
    price: original.price,
    deluxePrice: original.deluxePrice,
    image: original.image,
    deletedAt: null
  }, { where: { id }, paranoid: false })
}

function deluxeHeader () {
  const email = 'deluxe-buyer@example.test'
  const session = {
    data: {
      role: 'deluxe',
      email,
      id: 1,
      deluxeToken: security.deluxeToken(email)
    },
    bid: basketId
  }
  const token = security.authorize(session)
  security.authenticatedUsers.put(token, session as any)
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function checkoutProduct (productId: number, header: Record<string, string>) {
  const item = await request(app)
    .post('/api/BasketItems')
    .set(header)
    .send({ ProductId: productId, BasketId: basketId, quantity: 1 })
  assert.equal(item.status, 200, JSON.stringify(item.body))
  const checkout = await request(app)
    .post('/rest/basket/' + basketId + '/checkout')
    .set(header)
    .send({})
  assert.equal(checkout.status, 200, checkout.text)
  const tracked = await request(app).get('/rest/track-order/' + checkout.body.orderConfirmation)
  assert.equal(tracked.status, 200, tracked.text)
  return Number(tracked.body.data[0].totalPrice)
}

void describe('product updates require an administrator', { concurrency: false }, () => {
  void it('anonymous PUT cannot change the price checkout charges', async () => {
    const original = await readProduct(1)
    const put = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ price: 0, description: descriptionMarkup })
    let charged = Number.NaN
    try {
      charged = await checkoutProduct(1, customerHeader)
      const after = await readProduct(1)
      const search = await request(app).get('/rest/products/search').query({ q: 'Apple Juice' })
      const searched = search.body.data.find((product: { id: number }) => product.id === 1)
      assert.equal(charged.toFixed(2), Number(original.price).toFixed(2))
      assert.equal(Number(after.price).toFixed(2), Number(original.price).toFixed(2))
      assert.equal(searched.description, original.description)
      assert.equal(after.description, original.description)
      assert.equal(charged.toFixed(2), Number(original.price).toFixed(2))
      assert.ok(put.status === 401 || put.status === 403)
    } finally {
      await restoreProduct(1, original)
    }
  })

  void it('anonymous PUT cannot make checkout charge a negative product price', async () => {
    const original = await readProduct(2)
    const put = await request(app)
      .put('/api/Products/2')
      .set(jsonHeader)
      .send({ price: -5 })
    let charged = Number.NaN
    try {
      charged = await checkoutProduct(2, customerHeader)
      const after = await readProduct(2)
      assert.equal(charged.toFixed(2), Number(original.price).toFixed(2))
      assert.equal(Number(after.price).toFixed(2), Number(original.price).toFixed(2))
      assert.ok(charged >= 0)
      assert.ok(put.status === 401 || put.status === 403)
    } finally {
      await restoreProduct(2, original)
    }
  })

  void it('anonymous PUT cannot change the deluxe price checkout charges', async () => {
    const original = await readProduct(3)
    const put = await request(app)
      .put('/api/Products/3')
      .set(jsonHeader)
      .send({ deluxePrice: 0 })
    let charged = Number.NaN
    try {
      charged = await checkoutProduct(3, deluxeHeader())
      const after = await readProduct(3)
      assert.equal(charged.toFixed(2), Number(original.deluxePrice).toFixed(2))
      assert.equal(Number(after.deluxePrice).toFixed(2), Number(original.deluxePrice).toFixed(2))
      assert.ok(put.status === 401 || put.status === 403)
    } finally {
      await restoreProduct(3, original)
    }
  })

  void it('anonymous PUT cannot change product name or image', async () => {
    const original = await readProduct(4)
    const put = await request(app)
      .put('/api/Products/4')
      .set(jsonHeader)
      .send({ name: 'Renamed by anonymous', image: 'not-a-real-image.jpg' })
    try {
      const after = await readProduct(4)
      assert.deepEqual(
        { name: after.name, image: after.image },
        { name: original.name, image: original.image }
      )
      assert.ok(put.status === 401 || put.status === 403)
    } finally {
      await restoreProduct(4, original)
    }
  })

  void it('a customer token cannot change a product price', async () => {
    const original = await readProduct(5)
    const who = await request(app).get('/api/Users').set(customerHeader)
    const put = await request(app)
      .put('/api/Products/5')
      .set(customerHeader)
      .send({ price: 0, description: descriptionMarkup })
    try {
      const after = await readProduct(5)
      assert.equal(who.status, 200)
      assert.equal(Number(after.price).toFixed(2), Number(original.price).toFixed(2))
      assert.equal(after.description, original.description)
      assert.ok(put.status === 401 || put.status === 403)
    } finally {
      await restoreProduct(5, original)
    }
  })

  void it('a customer cannot store markup in a new product description', async () => {
    const res = await request(app)
      .post('/api/Products')
      .set(customerHeader)
      .send({
        name: 'Created by customer',
        description: descriptionMarkup,
        price: 1,
        image: 'created.jpg'
      })
    const createdId = res.body?.data?.id
    try {
      if (res.status === 200 || res.status === 201) {
        const stored = await readProduct(createdId)
        const search = await request(app).get('/rest/products/search').query({ q: 'Created by customer' })
        const searched = search.body.data.find((product: { id: number }) => product.id === createdId)
        assert.equal(stored.description.includes('<iframe'), false)
        assert.equal(stored.description.includes('onerror'), false)
        assert.equal(searched.description.includes('<iframe'), false)
        assert.equal(searched.description.includes('onerror'), false)
      } else {
        assert.ok(res.status === 401 || res.status === 403)
      }
    } finally {
      if (createdId) {
        await ProductModel.destroy({ where: { id: createdId }, force: true })
      }
    }
  })

  void it('anonymous PUT cannot soft-delete a product', async () => {
    const original = await readProduct(6)
    const put = await request(app)
      .put('/api/Products/6')
      .set(jsonHeader)
      .send({ deletedAt: new Date().toISOString() })
    try {
      const after = await request(app).get('/api/Products/6')
      assert.equal(after.status, 200)
      assert.equal(after.body.data.id, 6)
      assert.ok(put.status === 401 || put.status === 403)
    } finally {
      await restoreProduct(6, original)
    }
  })
})
