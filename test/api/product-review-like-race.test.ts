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

const placeholderPassword = 'placeholder-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface StoredReview {
  _id: string
  message: string
  likesCount: number
  likedBy: string[]
}

async function createReview (message: string): Promise<StoredReview> {
  const created = await request(app)
    .put('/rest/products/1/reviews')
    .send({ message, author: 'Anonymous' })
  assert.equal(created.status, 201)

  const listed = await request(app).get('/rest/products/1/reviews')
  assert.equal(listed.status, 200)
  const review = (listed.body.data as StoredReview[]).find(item => item.message === message)
  assert.ok(review, `review ${message} was not stored`)
  return review
}

async function readReview (message: string): Promise<StoredReview> {
  const listed = await request(app).get('/rest/products/1/reviews')
  assert.equal(listed.status, 200)
  const review = (listed.body.data as StoredReview[]).find(item => item.message === message)
  assert.ok(review, `review ${message} disappeared`)
  return review
}

async function likeReview (token: string, id: string) {
  return await request(app)
    .post('/rest/products/reviews')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({ id })
}

void describe('POST /rest/products/reviews one like per customer', () => {
  void it('overlapping likes from one customer count as a single vote on that review', async () => {
    const customerEmail = 'parallel-like@juice-sh.op'
    await register(app, { email: customerEmail, password: placeholderPassword })
    const { token } = await login(app, { email: customerEmail, password: placeholderPassword })

    const target = await createReview('parallel-like-target')
    const untouched = await createReview('parallel-like-untouched')
    assert.equal(target.likesCount, 0)
    assert.deepEqual(target.likedBy, [])

    const overlapped = await Promise.all([
      likeReview(token, target._id),
      likeReview(token, target._id),
      likeReview(token, target._id)
    ])
    const statuses = overlapped.map(res => res.status).sort((a, b) => a - b)

    const afterOverlap = await readReview(target.message)
    const votes = afterOverlap.likedBy.filter(email => email === customerEmail)
    assert.deepEqual(
      { likesCount: afterOverlap.likesCount, votes: votes.length, statuses },
      { likesCount: 1, votes: 1, statuses: [200, 403, 403] }
    )
    assert.deepEqual(afterOverlap.likedBy, [customerEmail])

    const repeat = await likeReview(token, target._id)
    assert.equal(repeat.status, 403)
    const afterRepeat = await readReview(target.message)
    assert.equal(afterRepeat.likesCount, 1)
    assert.deepEqual(afterRepeat.likedBy, [customerEmail])

    const control = await readReview(untouched.message)
    assert.equal(control.likesCount, untouched.likesCount)
    assert.deepEqual(control.likedBy, untouched.likedBy)
  })

  void it('a second customer can still like the same review once', async () => {
    const customerEmail = 'parallel-like-first@juice-sh.op'
    const otherCustomerEmail = 'parallel-like-other@juice-sh.op'
    await register(app, { email: customerEmail, password: placeholderPassword })
    await register(app, { email: otherCustomerEmail, password: placeholderPassword })
    const first = await login(app, { email: customerEmail, password: placeholderPassword })
    const second = await login(app, { email: otherCustomerEmail, password: placeholderPassword })

    const review = await createReview('parallel-like-two-customers')
    const firstLike = await likeReview(first.token, review._id)
    assert.equal(firstLike.status, 200)

    const overlapped = await Promise.all([
      likeReview(second.token, review._id),
      likeReview(second.token, review._id),
      likeReview(second.token, review._id)
    ])
    const statuses = overlapped.map(res => res.status).sort((a, b) => a - b)
    const stored = await readReview(review.message)
    const firstVotes = stored.likedBy.filter(email => email === customerEmail)
    const secondVotes = stored.likedBy.filter(email => email === otherCustomerEmail)
    assert.deepEqual(
      {
        likesCount: stored.likesCount,
        firstVotes: firstVotes.length,
        secondVotes: secondVotes.length,
        statuses
      },
      { likesCount: 2, firstVotes: 1, secondVotes: 1, statuses: [200, 403, 403] }
    )
  })
})
