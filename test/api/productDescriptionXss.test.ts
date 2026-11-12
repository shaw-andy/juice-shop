/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'

// Markup a shopper's browser will run if it is inserted with innerHTML.
// The iframe is the API-only XSS challenge string. The image runs when the
// element is parsed, which is the path innerHTML actually takes.
const activeDescription = '<img id="pd-xss" src="x" alt="pd-xss" onerror="window.__productDescriptionRan=1"><iframe id="pd-xss-frame" src="javascript:alert(`xss`)">'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

function hasExecutableMarkup (value: unknown): boolean {
  const html = String(value ?? '')
  return /<\s*\/?\s*(img|iframe|script|svg|math|object|embed)\b/i.test(html) ||
    /<[^>]*\s(?:on[a-z]+|srcdoc)\s*=/i.test(html) ||
    /javascript\s*:/i.test(html)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('product description HTML', () => {
  void it('refuses to persist executable description HTML from an anonymous product update', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.restfulXssChallenge), true)

    const updated = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ description: activeDescription })

    if (updated.status !== 401 && updated.status !== 403) {
      assert.equal(updated.status, 200)
      assert.equal(hasExecutableMarkup(updated.body?.data?.description), false)
    }

    const stored = await request(app).get('/api/Products/1')
    assert.equal(stored.status, 200)
    assert.equal(hasExecutableMarkup(stored.body?.data?.description), false)

    const search = await request(app).get('/rest/products/search').query({ q: 'Apple' })
    assert.equal(search.status, 200)
    const product = search.body.data.find((entry: { id: number }) => entry.id === 1)
    assert.ok(product)
    assert.equal(hasExecutableMarkup(product.description), false)
  })

  void it('refuses to persist executable description HTML when an authenticated client creates a product', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.restfulXssChallenge), true)

    const created = await request(app)
      .post('/api/Products')
      .set(authHeader)
      .send({
        name: 'Plain Juice',
        description: activeDescription,
        price: 1.23,
        image: 'apple_juice.jpg'
      })

    assert.equal(created.status, 201)
    assert.equal(hasExecutableMarkup(created.body?.data?.description), false)

    const id = created.body.data.id
    const stored = await request(app).get('/api/Products/' + id)
    assert.equal(stored.status, 200)
    assert.equal(hasExecutableMarkup(stored.body?.data?.description), false)
  })
})
