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
import { reviewsCollection } from '../../data/mongodb'

interface StoredReview {
  _id: string
  message: string
  author: string
  product: number | string
}

const attackerEmail = 'review-edit-attacker@example.test'
const placeholderPassword = 'placeholder-password'
const ownMessage = 'review written by the caller'
const otherMessage = 'review written by another customer'
const overwritten = 'text substituted by a different customer'

let app: Express
let attackerToken = ''
let ownReviewId = ''
let laterOtherReviewId = ''
let seededOtherReviewId = ''

const jsonHeader = { 'content-type': 'application/json' }

async function storedReviews (): Promise<StoredReview[]> {
  return await reviewsCollection.find({})
}

function foreignReviews (reviews: StoredReview[]): StoredReview[] {
  return reviews
    .filter((review) => review.author !== attackerEmail)
    .map((review) => ({ _id: review._id, author: review.author, message: review.message, product: review.product }))
    .sort((a, b) => a._id < b._id ? -1 : a._id > b._id ? 1 : 0)
}

async function productReviews (productId: number): Promise<StoredReview[]> {
  const res = await request(app).get(`/rest/products/${productId}/reviews`)
  assert.equal(res.status, 200)
  return res.body.data as StoredReview[]
}

/**
 * Records review writes that land before the handler responds.
 * A later revert of the same document still counts: the first write already published the substitute text.
 */
function watchReviewWrites () {
  const writes: Array<{ updated: StoredReview, original: StoredReview }> = []
  const listener = (updated: StoredReview, original: StoredReview) => {
    writes.push({ updated, original })
  }
  reviewsCollection.on('update', listener)
  return {
    writes,
    stop () {
      reviewsCollection.removeListener('update', listener)
    }
  }
}

function foreignOverwriteIds (writes: Array<{ updated: StoredReview, original: StoredReview }>, forbiddenMessage: string) {
  return writes
    .filter((write) => write.original?.author !== attackerEmail && write.updated?.message === forbiddenMessage)
    .map((write) => write.original._id)
}

async function patchReview (body: { id: unknown, message: string }, token?: string) {
  const req = request(app)
    .patch('/rest/products/reviews')
    .set(jsonHeader)
  if (token !== undefined) {
    req.set('Authorization', `Bearer ${token}`)
  }
  return await req.send(body)
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  await register(app, { email: attackerEmail, password: placeholderPassword })
  const authentication = await login(app, { email: attackerEmail, password: placeholderPassword })
  attackerToken = authentication.token

  const createdOwn = await request(app)
    .put('/rest/products/1/reviews')
    .set(jsonHeader)
    .send({ message: ownMessage, author: attackerEmail })
  assert.equal(createdOwn.status, 201)

  const listed = await productReviews(1)
  const seeded = listed.find((review) => review.author !== attackerEmail)
  assert.ok(seeded)
  seededOtherReviewId = seeded._id

  const createdOther = await request(app)
    .put('/rest/products/1/reviews')
    .set(jsonHeader)
    .send({ message: otherMessage, author: seeded.author })
  assert.equal(createdOther.status, 201)

  const afterCreate = await productReviews(1)
  const own = afterCreate.find((review) => review.author === attackerEmail && review.message === ownMessage)
  const other = afterCreate.find((review) => review.author === seeded.author && review.message === otherMessage)
  assert.ok(own)
  assert.ok(other)
  ownReviewId = own._id
  laterOtherReviewId = other._id
}, { timeout: 60000 })

void describe('PATCH /rest/products/reviews', () => {
  void it('updates a review the caller authored and leaves every other review unchanged', async () => {
    const beforeForeign = foreignReviews(await storedReviews())
    const message = 'review text replaced by its author'
    const writes = watchReviewWrites()
    try {
      const res = await patchReview({ id: ownReviewId, message }, attackerToken)
      assert.equal(res.status, 200)
      const shown = await productReviews(1)
      const own = shown.find((review) => review._id === ownReviewId)
      assert.ok(own)
      assert.equal(own.message, message)
      assert.equal(own.author, attackerEmail)
      assert.ok(writes.writes.some((write) => write.updated?._id === ownReviewId && write.updated.message === message))
      assert.deepEqual(foreignReviews(await storedReviews()), beforeForeign)
      assert.deepEqual(foreignOverwriteIds(writes.writes, message), [])
    } finally {
      writes.stop()
    }
  })

  void it('does not change another customer review selected by id', async () => {
    const beforeForeign = foreignReviews(await storedReviews())
    const message = `${overwritten} by id`
    const writes = watchReviewWrites()
    try {
      await patchReview({ id: seededOtherReviewId, message }, attackerToken)
      const shown = await productReviews(1)
      const review = shown.find((item) => item._id === seededOtherReviewId)
      assert.ok(review)
      assert.notEqual(review.message, message)
      assert.equal(review.author, beforeForeign.find((item) => item._id === seededOtherReviewId)?.author)
      assert.deepEqual(foreignReviews(await storedReviews()), beforeForeign)
      assert.deepEqual(foreignOverwriteIds(writes.writes, message), [])
    } finally {
      writes.stop()
    }
  })

  void it('does not change another customer review when the id matches the caller review and that review', async () => {
    const beforeForeign = foreignReviews(await storedReviews())
    const message = `${overwritten} by operator`
    const writes = watchReviewWrites()
    try {
      // The caller's id is first. A check that authorizes only that first match
      // still fails when the update applies the same operator to the other review.
      await patchReview({
        id: { $in: [ownReviewId, laterOtherReviewId] },
        message
      }, attackerToken)
      const shown = await productReviews(1)
      const other = shown.find((review) => review._id === laterOtherReviewId)
      assert.ok(other)
      assert.equal(other.message, otherMessage)
      assert.notEqual(other.author, attackerEmail)
      assert.deepEqual(foreignReviews(await storedReviews()), beforeForeign)
      assert.deepEqual(foreignOverwriteIds(writes.writes, message), [])
    } finally {
      writes.stop()
    }
  })

  void it('does not change reviews the caller did not author when the id is a query operator', async () => {
    const beforeForeign = foreignReviews(await storedReviews())
    const message = `${overwritten} by inequality`
    const writes = watchReviewWrites()
    try {
      await patchReview({ id: { $ne: -1 }, message }, attackerToken)
      assert.deepEqual(foreignReviews(await storedReviews()), beforeForeign)
      assert.deepEqual(foreignOverwriteIds(writes.writes, message), [])
      const shown = await productReviews(1)
      const other = shown.find((review) => review._id === seededOtherReviewId)
      assert.ok(other)
      assert.notEqual(other.message, message)
    } finally {
      writes.stop()
    }
  })

  void it('does not change a review when the caller is not authenticated', async () => {
    const beforeForeign = foreignReviews(await storedReviews())
    const message = `${overwritten} without authentication`
    const writes = watchReviewWrites()
    try {
      const res = await patchReview({ id: seededOtherReviewId, message })
      assert.equal(res.status, 401)
      assert.deepEqual(foreignReviews(await storedReviews()), beforeForeign)
      assert.deepEqual(foreignOverwriteIds(writes.writes, message), [])
    } finally {
      writes.stop()
    }
  })
})
