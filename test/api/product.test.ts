/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import type { Product as ProductConfig } from '../../lib/config.schema'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'

const tamperingProductId = config.get<ProductConfig[]>('products').findIndex((product) => !!product.urlForProductTamperingChallenge) + 1

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Products', () => {
  void it('GET all products', async () => {
    const res = await request(app)
      .get('/api/Products')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    for (const product of res.body.data) {
      assert.equal(typeof product.id, 'number')
      assert.equal(typeof product.name, 'string')
      assert.equal(typeof product.description, 'string')
      assert.equal(typeof product.price, 'number')
      assert.equal(typeof product.deluxePrice, 'number')
      assert.equal(typeof product.image, 'string')
    }
  })

  void it('POST new product is forbidden via public API', async () => {
    const res = await request(app)
      .post('/api/Products')
      .send({
        name: 'Dirt Juice (1000ml)',
        description: 'Made from ugly dirt.',
        price: 0.99,
        image: 'dirt_juice.jpg'
      })
    assert.equal(res.status, 401)
  })

  if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
    void it('POST new product does not filter XSS attacks', async () => {
      const res = await request(app)
        .post('/api/Products')
        .set(authHeader)
        .send({
          name: 'XSS Juice (42ml)',
          description: '<iframe src="javascript:alert(`xss`)">',
          price: 9999.99,
          image: 'xss3juice.jpg'
        })
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.data.description, '<iframe src="javascript:alert(`xss`)">')
    })
  }
})

void describe('/api/Products/:id', () => {
  void it('GET existing product by id', async () => {
    const res = await request(app)
      .get('/api/Products/1')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.name, 'string')
    assert.equal(typeof res.body.data.description, 'string')
    assert.equal(typeof res.body.data.price, 'number')
    assert.equal(typeof res.body.data.deluxePrice, 'number')
    assert.equal(typeof res.body.data.image, 'string')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    assert.equal(res.body.data.id, 1)
  })

  void it('GET non-existing product by id', async () => {
    const res = await request(app)
      .get('/api/Products/4711')
    assert.equal(res.status, 404)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Not Found')
  })

  void it('PUT update existing product is possible due to Missing Function-Level Access Control vulnerability', async () => {
    const res = await request(app)
      .put('/api/Products/' + tamperingProductId)
      .set(jsonHeader)
      .send({
        description: '<a href="http://kimminich.de" target="_blank">More...</a>'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.description, '<a href="http://kimminich.de" target="_blank">More...</a>')
  })

  void it('GET all products still succeeds after a product description is cleared to null', async () => {
    const update = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ description: null })
    assert.equal(update.status, 200)

    const list = await request(app).get('/api/Products')
    assert.equal(list.status, 200)
    assert.ok(Array.isArray(list.body.data))
    assert.ok(list.body.data.length > 1)
    const cleared = list.body.data.find((product: { id: number }) => product.id === 1)
    assert.equal(cleared.description, '')

    const single = await request(app).get('/api/Products/1')
    assert.equal(single.status, 200)
    assert.equal(single.body.data.description, '')

    const search = await request(app).get('/rest/products/search').query({ q: 'Apple' })
    assert.equal(search.status, 200)
    assert.ok(Array.isArray(search.body.data))
  })

  void it('DELETE existing product is forbidden via public API', async () => {
    const res = await request(app)
      .delete('/api/Products/1')
    assert.equal(res.status, 401)
  })

  void it('DELETE existing product is forbidden via API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/Products/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
