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
})

void describe('/api/BasketItems repeat adds of the same product', () => {
  let benderAuthHeader: { Authorization: string, 'content-type': string }
  const benderBasketId = 3

  before(async () => {
    const { token } = await login(app, {
      email: 'bender@juice-sh.op',
      password: 'OhG0dPlease1nsertLiquor!'
    })
    benderAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  })

  const getBasket = async () => {
    const res = await request(app).get('/rest/basket/' + benderBasketId).set(benderAuthHeader)
    assert.equal(res.status, 200)
    return res.body.data
  }

  void it('POST same product twice increments the existing basket item instead of creating a duplicate', async () => {
    const firstRes = await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 1, quantity: 1 })
    assert.equal(firstRes.status, 200)
    assert.equal(firstRes.body.data.quantity, 1)

    const secondRes = await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 1, quantity: 1 })
    assert.equal(secondRes.status, 200)
    assert.equal(secondRes.body.data.id, firstRes.body.data.id)
    assert.equal(secondRes.body.data.quantity, 2)

    const basket = await getBasket()
    const appleJuiceLines = basket.Products.filter((product: { id: number }) => product.id === 1)
    assert.equal(appleJuiceLines.length, 1)
    assert.equal(appleJuiceLines[0].BasketItem.quantity, 2)
  })

  void it('basket total equals the sum of quantity x price after repeat adds', async () => {
    await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 1, quantity: 2 })

    const basket = await getBasket()
    const appleJuice = basket.Products.find((product: { id: number }) => product.id === 1)
    assert.equal(appleJuice.BasketItem.quantity, 4)
    const total = basket.Products.reduce((sum: number, product: { price: number, BasketItem: { quantity: number } }) => sum + product.price * product.BasketItem.quantity, 0)
    const raspberryJuice = basket.Products.find((product: { id: number }) => product.id === 4)
    assert.equal(total, appleJuice.price * 4 + raspberryJuice.price * raspberryJuice.BasketItem.quantity)
  })

  void it('POST same product beyond limitPerUser through repeat adds is forbidden and leaves quantity unchanged', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 1, quantity: 2 })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You can order only up to 5 items of this product.')

    const basket = await getBasket()
    const appleJuice = basket.Products.find((product: { id: number }) => product.id === 1)
    assert.equal(appleJuice.BasketItem.quantity, 4)
  })

  void it('concurrent POSTs of a product not yet in the basket result in a single item with the combined quantity', async () => {
    const add = async () => await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 5, quantity: 1 })
    const responses = await Promise.all([add(), add(), add()])
    responses.forEach((res) => { assert.equal(res.status, 200) })

    const basket = await getBasket()
    const lines = basket.Products.filter((product: { id: number }) => product.id === 5)
    assert.equal(lines.length, 1)
    assert.equal(lines[0].BasketItem.quantity, 3)
  })

  void it('concurrent POSTs that would each reach limitPerUser do not exceed the limit', async () => {
    const add = async () => await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 7, quantity: 5 })
    const responses = await Promise.all([add(), add()])
    const statuses = responses.map((res) => res.status).sort()
    assert.deepEqual(statuses, [200, 400])
    const rejected = responses.find((res) => res.status === 400)
    assert.equal(rejected?.body.error, 'You can order only up to 5 items of this product.')

    const basket = await getBasket()
    const lines = basket.Products.filter((product: { id: number }) => product.id === 7)
    assert.equal(lines.length, 1)
    assert.equal(lines[0].BasketItem.quantity, 5)
  })

  void it('POST same product up to exactly limitPerUser through repeat adds is allowed', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(benderAuthHeader)
      .send({ BasketId: benderBasketId, ProductId: 1, quantity: 1 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.quantity, 5)
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

  void it('PUT update non-existent basket item', async () => {
    const res = await request(app)
      .put('/api/BasketItems/999')
      .set(authHeader)
      .send({ quantity: 1 })
    assert.equal(res.status, 500)
  })

  void it('PUT update basket item passes errors from the quantity check to the error handler', async (t) => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 11, quantity: 1 })
    assert.equal(createRes.status, 200)

    t.mock.method(QuantityModel, 'findOne', async () => { throw new Error('Quantity lookup failed') })
    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 2 })
    assert.equal(res.status, 500)
    assert.match(res.text, /Quantity lookup failed/)
  })
})
