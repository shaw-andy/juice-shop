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

let app: Express
let customerAuthorization: string

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const customerEmail = 'review-operator-customer@juice-sh.op'

interface StoredReview {
  productId: number
  id: string
  author: string
  message: string
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  await register(app, { email: customerEmail, password: placeholderPassword })
  const { token } = await login(app, { email: customerEmail, password: placeholderPassword })
  customerAuthorization = 'Bearer ' + token
}, { timeout: 60000 })

async function storedReviews (): Promise<StoredReview[]> {
  const products = await request(app).get('/api/Products')
  assert.equal(products.status, 200)
  const reviews: StoredReview[] = []
  for (const product of products.body.data) {
    const res = await request(app).get(`/rest/products/${product.id}/reviews`)
    assert.equal(res.status, 200)
    for (const review of res.body.data) {
      reviews.push({
        productId: product.id,
        id: review._id,
        author: review.author,
        message: review.message
      })
    }
  }
  return reviews
}

async function patchReview (id: unknown, message: string) {
  return await request(app)
    .patch('/rest/products/reviews')
    .set({ Authorization: customerAuthorization, ...jsonHeader })
    .send({ id, message })
}

void describe('PATCH /rest/products/reviews query operator', () => {
  void it('a logged-in customer cannot replace every review message with a not-equal id', async () => {
    const before = await storedReviews()
    assert.ok(before.length > 1)
    assert.ok(new Set(before.map(review => review.productId)).size > 1)
    const otherAuthors = before.filter(review => review.author !== customerEmail)
    assert.ok(otherAuthors.length > 1)

    const replacement = 'operator-replacement-not-equal'
    const res = await patchReview({ $ne: -1 }, replacement)
    const after = await storedReviews()

    const replaced = after.filter(review => review.message === replacement)
    assert.deepEqual(after.map(review => [review.id, review.message]), before.map(review => [review.id, review.message]))
    assert.equal(replaced.length, 0)
    assert.equal(res.status, 400)
  })

  void it('a logged-in customer cannot replace every review message with an exists id', async () => {
    const before = await storedReviews()
    assert.ok(before.length > 1)

    const replacement = 'operator-replacement-exists'
    const res = await patchReview({ $exists: true }, replacement)
    const after = await storedReviews()

    assert.deepEqual(after.map(review => [review.id, review.message]), before.map(review => [review.id, review.message]))
    assert.equal(res.status, 400)
  })

  void it('a logged-in customer cannot replace every review message with a not-in id', async () => {
    const before = await storedReviews()
    assert.ok(before.length > 1)

    const replacement = 'operator-replacement-not-in'
    const res = await patchReview({ $nin: [-1] }, replacement)
    const after = await storedReviews()

    assert.deepEqual(after.map(review => [review.id, review.message]), before.map(review => [review.id, review.message]))
    assert.equal(res.status, 400)
  })

  void it('a logged-in customer cannot replace every review message with a form-encoded not-equal id', async () => {
    const before = await storedReviews()
    assert.ok(before.length > 1)

    const replacement = 'operator-replacement-form'
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: customerAuthorization, 'content-type': 'application/x-www-form-urlencoded' })
      .send('id[$ne]=-1&message=' + encodeURIComponent(replacement))
    const after = await storedReviews()

    assert.deepEqual(after.map(review => [review.id, review.message]), before.map(review => [review.id, review.message]))
    assert.equal(res.status, 400)
  })
})
