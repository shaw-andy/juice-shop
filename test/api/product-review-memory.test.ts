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
import { login } from './helpers/auth'
import { loadStaticUserData } from '../../data/staticData'
import { reviewsCollection } from '../../data/mongodb'

const MAX_MESSAGE_LENGTH = 2000
const MAX_AUTHOR_LENGTH = 320
const MAX_REVIEWS_PER_PRODUCT = 20
const MAX_CREATE_REQUESTS_PER_MINUTE = 100

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const jsonHeader = { 'content-type': 'application/json' }

interface StoredReview {
  product: unknown
  message?: unknown
  author?: unknown
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  const users = await loadStaticUserData()
  const customer = users.find((user) => user.key === 'jim' && user.customDomain !== true && (user.totpSecret === undefined || user.totpSecret === ''))
  assert.ok(customer)
  const email = `${customer.email}@${config.get<string>('application.domain')}`
  const { token } = await login(app, { email, password: customer.password })
  authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}, { timeout: 60000 })

async function storedReviews (): Promise<StoredReview[]> {
  return await reviewsCollection.find({}) as StoredReview[]
}

async function reviewsForProduct (productId: string): Promise<StoredReview[]> {
  const reviews = await storedReviews()
  return reviews.filter((review) => String(review.product) === productId)
}

function putReview (productId: string, message: unknown, author: unknown, authenticated = true) {
  const req = request(app)
    .put(`/rest/products/${productId}/reviews`)
    .set(authenticated ? authHeader : jsonHeader)
    .send({ message, author })
  return req
}

async function emptyProductIds (): Promise<string[]> {
  const res = await request(app).get('/api/Products')
  assert.equal(res.status, 200)
  const ids = (res.body.data as Array<{ id: number }>).map((product) => String(product.id))
  const empty: string[] = []
  for (const id of ids) {
    if ((await reviewsForProduct(id)).length === 0) empty.push(id)
  }
  assert.ok(empty.length >= 2)
  return empty
}

void describe('product review retention', () => {
  void it('does not retain reviews posted without a session', async () => {
    const productId = (await emptyProductIds())[0]
    const before = await storedReviews()
    const markers = ['anon-review-a', 'anon-review-b', 'anon-review-c']

    const statuses: number[] = []
    for (const message of markers) {
      const res = await putReview(productId, message, 'Anonymous', false)
      statuses.push(res.status)
    }

    const after = await storedReviews()
    const listed = await request(app).get(`/rest/products/${productId}/reviews`)
    assert.equal(after.length, before.length)
    assert.deepEqual(statuses, [401, 401, 401])
    assert.equal(listed.status, 200)
    const messages = JSON.stringify(listed.body)
    for (const message of markers) {
      assert.equal(messages.includes(message), false)
    }
  })

  void it('retains one review from a session when the text is within the cap', async () => {
    const productId = (await emptyProductIds())[0]
    const message = 'm'.repeat(MAX_MESSAGE_LENGTH)
    const author = 'a'.repeat(MAX_AUTHOR_LENGTH)
    const before = (await reviewsForProduct(productId)).length

    const res = await putReview(productId, message, author)
    assert.equal(res.status, 201)

    const stored = await reviewsForProduct(productId)
    assert.equal(stored.length, before + 1)
    assert.equal(stored.some((review) => review.message === message && review.author === author), true)

    const listed = await request(app).get(`/rest/products/${productId}/reviews`)
    assert.equal(listed.status, 200)
    assert.equal(listed.body.data.length, stored.length)
    assert.equal(listed.body.data.some((review: StoredReview) => review.message === message), true)
  })

  void it('does not retain a message longer than the cap', async () => {
    const productId = (await emptyProductIds())[0]
    const message = 'm'.repeat(MAX_MESSAGE_LENGTH + 1)
    const before = await storedReviews()

    const res = await putReview(productId, message, 'reader@example.test')
    const after = await storedReviews()
    const listed = await request(app).get(`/rest/products/${productId}/reviews`)
    assert.equal(after.length, before.length)
    assert.equal(JSON.stringify(after).includes(message), false)
    assert.equal(JSON.stringify(listed.body).includes(message), false)
    assert.equal(res.status, 400)
  })

  void it('does not retain an author longer than the cap', async () => {
    const productId = (await emptyProductIds())[0]
    const author = 'a'.repeat(MAX_AUTHOR_LENGTH + 1)
    const before = await storedReviews()

    const res = await putReview(productId, 'short review', author)
    const after = await storedReviews()
    assert.equal(after.length, before.length)
    assert.equal(JSON.stringify(after).includes(author), false)
    assert.equal(res.status, 400)
  })

  void it('does not retain a non-string message', async () => {
    const productId = (await emptyProductIds())[0]
    const before = await storedReviews()
    const message = { text: 'nested', pad: 'x'.repeat(1000) }

    const res = await putReview(productId, message, 'reader@example.test')
    const after = await storedReviews()
    assert.equal(after.length, before.length)
    assert.equal(JSON.stringify(after).includes('nested'), false)
    assert.equal(res.status, 400)
  })

  void it('does not retain reviews for a product that is not in the catalog', async () => {
    const before = await storedReviews()
    const unknownIds = ['1000001', 'not-a-product']

    const statuses: number[] = []
    for (const productId of unknownIds) {
      const res = await putReview(productId, `review-for-${productId}`, 'reader@example.test')
      statuses.push(res.status)
    }

    const after = await storedReviews()
    assert.equal(after.length, before.length)
    for (const productId of unknownIds) {
      assert.equal((await reviewsForProduct(productId)).length, 0)
      const listed = await request(app).get(`/rest/products/${productId}/reviews`)
      assert.equal(JSON.stringify(listed.body).includes(`review-for-${productId}`), false)
    }
    assert.deepEqual(statuses, [404, 404])
  })

  void it('does not keep more than the per-product cap when creates race', async () => {
    const productId = (await emptyProductIds())[0]
    const before = (await reviewsForProduct(productId)).length
    assert.equal(before, 0)
    const attempts = MAX_REVIEWS_PER_PRODUCT + 10

    const responses = await Promise.all(Array.from({ length: attempts }, async (_, index) => {
      return await putReview(productId, `capped-review-${index}`, 'reader@example.test')
    }))

    const stored = await reviewsForProduct(productId)
    const created = responses.filter((res) => res.status === 201)
    const listed = await request(app).get(`/rest/products/${productId}/reviews`)
    assert.equal(listed.status, 200)
    assert.equal(listed.body.data.length, stored.length)
    assert.ok(stored.length <= MAX_REVIEWS_PER_PRODUCT)
    assert.equal(stored.length, before + created.length)
    assert.ok(responses.some((res) => res.status === 400))
  })

  void it('rejects an oversized edit and leaves the stored message in place', async () => {
    const catalog = await request(app).get('/api/Products')
    assert.equal(catalog.status, 200)
    const withReviews: string[] = []
    for (const product of catalog.body.data as Array<{ id: number }>) {
      const reviews = await reviewsForProduct(String(product.id))
      if (reviews.length > 0) withReviews.push(String(product.id))
    }
    assert.ok(withReviews.length > 0)
    const productId = withReviews[0]
    const listed = await request(app).get(`/rest/products/${productId}/reviews`)
    assert.equal(listed.status, 200)
    const original = listed.body.data[0] as { _id: string, message: string }
    const replacement = 'e'.repeat(MAX_MESSAGE_LENGTH + 1)

    const rejected = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({ id: original._id, message: replacement })

    const afterReject = await request(app).get(`/rest/products/${productId}/reviews`)
    const unchanged = afterReject.body.data.find((review: { _id: string, message: string }) => review._id === original._id)
    const stored = await reviewsForProduct(productId)
    assert.equal(stored.some((review) => review.message === replacement), false)
    assert.equal(unchanged.message, original.message)
    assert.equal(rejected.status, 400)

    const acceptedText = 'e'.repeat(MAX_MESSAGE_LENGTH)
    const accepted = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({ id: original._id, message: acceptedText })
    assert.equal(accepted.status, 200)
    const afterAccept = await request(app).get(`/rest/products/${productId}/reviews`)
    const edited = afterAccept.body.data.find((review: { _id: string, message: string }) => review._id === original._id)
    assert.equal(edited.message, acceptedText)
  })

  void it('rate limits one client and does not retain the rejected creates', { timeout: 60000 }, async () => {
    const productId = (await emptyProductIds())[0]
    const before = (await reviewsForProduct(productId)).length
    const attempts = MAX_CREATE_REQUESTS_PER_MINUTE + 1

    const responses = await Promise.all(Array.from({ length: attempts }, async (_, index) => {
      return await putReview(productId, `rated-review-${index}`, 'reader@example.test')
    }))

    const stored = await reviewsForProduct(productId)
    const created = responses.filter((res) => res.status === 201)
    const listed = await request(app).get(`/rest/products/${productId}/reviews`)
    assert.equal(listed.status, 200)
    assert.equal(listed.body.data.length, stored.length)
    assert.ok(stored.length <= MAX_REVIEWS_PER_PRODUCT)
    assert.equal(stored.length, before + created.length)
    assert.ok(responses.some((res) => res.status === 429))
  })
})
