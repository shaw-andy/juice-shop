/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { QuantityModel } from '../../models/quantity'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/api/BasketItems', () => {
  void it('GET all basket items is forbidden via public API', async () => {
    const res = await request(app).get('/api/BasketItems')
    assert.equal(res.status, 401)
  })

  void it('POST new basket item is forbidden via public API', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .send({ BasketId: 2, ProductId: 1, quantity: 1 })
    assert.equal(res.status, 401)
  })

  void it('GET all basket items', async () => {
    const res = await request(app).get('/api/BasketItems').set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('POST new basket item', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 2, quantity: 1 })
    assert.equal(res.status, 200)
  })

  void it('POST new basket item with more than available quantity is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 2, quantity: 101 })
    assert.equal(res.status, 400)
  })

  void it('POST new basket item with more than allowed quantity is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 1, quantity: 6 })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You can order only up to 5 items of this product.')
  })

  void it('POST new basket item with invalid basket ID is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 42, ProductId: 1, quantity: 1 })
    assert.equal(res.status, 401)
    assert.equal(res.text, "{'error' : 'Invalid BasketId'}")
  })

  void it('POST new basket item with non-existent product ID is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 999, quantity: 1 })
    assert.equal(res.status, 500) // quantityCheck throws Error which is caught and passed to next(error)
  })

  void it('POST same product twice increments quantity of the existing basket item', async () => {
    const firstRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 5, quantity: 1 })
    assert.equal(firstRes.status, 200)

    const secondRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 5, quantity: '1' })
    assert.equal(secondRes.status, 200)
    assert.equal(secondRes.body.data.id, firstRes.body.data.id)
    assert.equal(secondRes.body.data.quantity, 2)

    const basketRes = await request(app).get('/rest/basket/2').set(authHeader)
    assert.equal(basketRes.status, 200)
    const lines = basketRes.body.data.Products.filter((product: { id: number }) => product.id === 5)
    assert.equal(lines.length, 1)
    assert.equal(lines[0].BasketItem.quantity, 2)
  })

  void it('basket total reflects aggregated quantities after repeated adds', async () => {
    const totalOf = (products: Array<{ price: number, BasketItem: { quantity: number } }>) =>
      products.reduce((total, product) => total + product.price * product.BasketItem.quantity, 0)

    await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 24, quantity: 1 })
    const before = await request(app).get('/rest/basket/2').set(authHeader)
    const unitPrice = before.body.data.Products.find((product: { id: number }) => product.id === 24).price

    const addRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 24, quantity: 1 })
    assert.equal(addRes.status, 200)

    const after = await request(app).get('/rest/basket/2').set(authHeader)
    assert.equal(after.body.data.Products.length, before.body.data.Products.length)
    assert.equal(totalOf(after.body.data.Products), totalOf(before.body.data.Products) + unitPrice)
  })

  void it('POST same product beyond limitPerUser through repeated adds is forbidden', async () => {
    const firstRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 7, quantity: 3 })
    assert.equal(firstRes.status, 200)

    const secondRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 7, quantity: 3 })
    assert.equal(secondRes.status, 400)
    assert.equal(secondRes.body.error, 'You can order only up to 5 items of this product.')

    const itemRes = await request(app).get('/api/BasketItems/' + firstRes.body.data.id).set(authHeader)
    assert.equal(itemRes.body.data.quantity, 3)
  })

  void it('POST same product beyond available stock through repeated adds is forbidden', async () => {
    const stock = await QuantityModel.findOne({ where: { ProductId: 11 } })
    assert.ok(stock)
    assert.equal(stock.limitPerUser, null)

    const firstRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 11, quantity: stock.quantity })
    assert.equal(firstRes.status, 200)

    const secondRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 11, quantity: 1 })
    assert.equal(secondRes.status, 400)
    assert.equal(secondRes.body.error, 'We are out of stock! Sorry for the inconvenience.')
  })
})

void describe('/api/BasketItems/:id', () => {
  void it('GET basket item by id is forbidden via public API', async () => {
    const res = await request(app).get('/api/BasketItems/1')
    assert.equal(res.status, 401)
  })

  void it('PUT update basket item is forbidden via public API', async () => {
    const res = await request(app)
      .put('/api/BasketItems/1')
      .set({ 'content-type': 'application/json' })
      .send({ quantity: 2 })
    assert.equal(res.status, 401)
  })

  void it('DELETE basket item is forbidden via public API', async () => {
    const res = await request(app).delete('/api/BasketItems/1')
    assert.equal(res.status, 401)
  })

  void it('GET newly created basket item by id', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 6, quantity: 3 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('PUT update newly created basket item', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 3, quantity: 3 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 20 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.quantity, 20)
  })

  void it('PUT update basket ID of basket item is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 8, quantity: 8 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ BasketId: 42 })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'null: `BasketId` cannot be updated due `noUpdate` constraint')
    assert.deepEqual(res.body.errors, [{ field: 'BasketId', message: '`BasketId` cannot be updated due `noUpdate` constraint' }])
  })

  void it('PUT update basket ID of basket item without basket ID', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 8, quantity: 8 })
    assert.equal(createRes.status, 200)
    assert.equal(createRes.body.data.BasketId, undefined)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ BasketId: 3 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.BasketId, 3)
  })

  void it('PUT update product ID of basket item is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 9, quantity: 9 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ ProductId: 42 })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'null: `ProductId` cannot be updated due `noUpdate` constraint')
    assert.deepEqual(res.body.errors, [{ field: 'ProductId', message: '`ProductId` cannot be updated due `noUpdate` constraint' }])
  })

  void it('PUT update newly created basket item with more than available quantity is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 12, quantity: 12 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 100 })
    assert.equal(res.status, 400)
  })

  void it('PUT update basket item with more than allowed quantity is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 1, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 6 })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You can order only up to 5 items of this product.')
  })

  void it('DELETE newly created basket item', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: 10 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .delete('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('PUT update basket item passes errors from quantity check to error handler', async (t) => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 13, quantity: 1 })
    assert.equal(createRes.status, 200)

    t.mock.method(QuantityModel, 'findOne', async () => { throw new Error('Quantity error') })
    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 2 })
    assert.equal(res.status, 500)
    assert.match(res.text, /Quantity error/)
  })

  void it('PUT update non-existent basket item', async () => {
    const res = await request(app)
      .put('/api/BasketItems/999')
      .set(authHeader)
      .send({ quantity: 1 })
    assert.equal(res.status, 500)
  })
})
