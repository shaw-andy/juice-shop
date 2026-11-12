/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const victimEmail = 'jim@' + config.get<string>('application.domain')

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface StoredReview {
  author?: string
  message?: string
  product?: number | string
}

async function listedReviews (productId: number): Promise<StoredReview[]> {
  const res = await request(app).get(`/rest/products/${productId}/reviews`)
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data as StoredReview[]
}

function reviewsMatching (reviews: StoredReview[], message: string): StoredReview[] {
  return reviews.filter((review) => review.message === message)
}

void describe('PUT /rest/products/:id/reviews author binding', () => {
  void it('rejects an anonymous review and does not store the caller-supplied author', async () => {
    const message = 'anonymous-forged-author-marker'
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set(jsonHeader)
      .send({ message, author: victimEmail })

    const stored = reviewsMatching(await listedReviews(1), message)
    assert.equal(stored.length, 0)
    assert.equal(res.status, 401)
  })

  void it('rejects an anonymous review submitted as form fields and does not store it', async () => {
    const message = 'anonymous-form-forged-author-marker'
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .type('form')
      .send({ message, author: victimEmail })

    const stored = reviewsMatching(await listedReviews(1), message)
    assert.equal(stored.length, 0)
    assert.equal(res.status, 401)
  })

  void it('rejects a bearer token that is not a logged-in session and does not store the review', async () => {
    const message = 'placeholder-token-forged-author-marker'
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: 'Bearer placeholder-token', ...jsonHeader })
      .send({ message, author: victimEmail })

    const stored = reviewsMatching(await listedReviews(1), message)
    assert.equal(stored.length, 0)
    assert.equal(res.status, 401)
  })

  void it('stores the session email when the body and X-User-Email name a different customer', async () => {
    const sessionEmail = `session-reviewer-${Date.now()}@example.test`
    const message = `session-bound-author-marker-${Date.now()}`
    await register(app, { email: sessionEmail, password: placeholderPassword })
    const { token } = await login(app, { email: sessionEmail, password: placeholderPassword })

    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({
        Authorization: `Bearer ${token}`,
        'X-User-Email': victimEmail,
        ...jsonHeader
      })
      .send({ message, author: victimEmail })

    assert.equal(res.status, 201)
    const stored = reviewsMatching(await listedReviews(1), message)
    assert.equal(stored.length, 1)
    assert.equal(stored[0].author, sessionEmail)
  })

  void it('stores the session email when the body omits author', async () => {
    const sessionEmail = `session-reviewer-omit-${Date.now()}@example.test`
    const message = `session-omitted-author-marker-${Date.now()}`
    await register(app, { email: sessionEmail, password: placeholderPassword })
    const { token } = await login(app, { email: sessionEmail, password: placeholderPassword })

    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${token}`, ...jsonHeader })
      .send({ message })

    assert.equal(res.status, 201)
    const stored = reviewsMatching(await listedReviews(1), message)
    assert.equal(stored.length, 1)
    assert.equal(stored[0].author, sessionEmail)
  })

  void it('binds the author to the authenticated user for every product id', async () => {
    const sessionEmail = `session-reviewer-product-${Date.now()}@example.test`
    const message = `other-product-author-marker-${Date.now()}`
    await register(app, { email: sessionEmail, password: placeholderPassword })
    const { token } = await login(app, { email: sessionEmail, password: placeholderPassword })

    const res = await request(app)
      .put('/rest/products/2/reviews')
      .set({ Authorization: `Bearer ${token}`, ...jsonHeader })
      .send({ message, author: victimEmail })

    assert.equal(res.status, 201)
    const stored = reviewsMatching(await listedReviews(2), message)
    assert.equal(stored.length, 1)
    assert.equal(stored[0].author, sessionEmail)
  })
})
