/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }

interface FeedbackRow {
  id: number
  comment: string
  rating: unknown
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function listFeedbacks (): Promise<FeedbackRow[]> {
  const res = await request(app).get('/api/Feedbacks')
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

async function postAnonymousFeedback (rating: unknown, comment: string) {
  const captchaRes = await request(app).get('/rest/captcha')
  assert.equal(captchaRes.status, 200)
  assert.equal(typeof captchaRes.body.captchaId, 'number')
  assert.equal(typeof captchaRes.body.answer, 'string')

  return await request(app)
    .post('/api/Feedbacks')
    .set(jsonHeader)
    .send({
      comment,
      rating,
      captchaId: captchaRes.body.captchaId,
      captcha: captchaRes.body.answer
    })
}

async function assertRatingRejected (rating: unknown, comment: string) {
  const before = await listFeedbacks()
  const maxBefore = before.reduce((max, row) => Math.max(max, row.id), 0)
  const res = await postAnonymousFeedback(rating, comment)
  assert.equal(res.status, 400)
  const after = await listFeedbacks()
  assert.equal(after.length, before.length)
  assert.equal(after.some(row => row.comment === comment), false)
  const accepted = await postAnonymousFeedback(1, `${comment}-kept`)
  assert.equal(accepted.status, 201)
  assert.equal(accepted.body.data.id, maxBefore + 1)
  assert.equal(accepted.body.data.rating, 1)
}

void describe('feedback rating bounds', () => {
  void it('still accepts a rating of 0', async () => {
    const comment = 'bounds-zero'
    const res = await postAnonymousFeedback(0, comment)
    assert.equal(res.status, 201)
    assert.equal(res.body.data.rating, 0)
    const stored = (await listFeedbacks()).find(row => row.comment === comment)
    assert.equal(stored?.rating, 0)
  })

  void it('still accepts a rating of 5', async () => {
    const comment = 'bounds-five'
    const res = await postAnonymousFeedback(5, comment)
    assert.equal(res.status, 201)
    assert.equal(res.body.data.rating, 5)
    const stored = (await listFeedbacks()).find(row => row.comment === comment)
    assert.equal(stored?.rating, 5)
  })

  void it('rejects a negative rating before saving it', async () => {
    await assertRatingRejected(-1, 'bounds-negative')
  })

  void it('rejects a rating above 5 before saving it', async () => {
    await assertRatingRejected(6, 'bounds-six')
  })

  void it('rejects a non-integer rating before saving it', async () => {
    await assertRatingRejected(1.5, 'bounds-fraction')
  })

  void it('rejects a very large rating before saving it', async () => {
    await assertRatingRejected(1000000000, 'bounds-huge')
  })

  void it('rejects a numeric string rating outside 0 through 5 before saving it', async () => {
    await assertRatingRejected('-1', 'bounds-negative-string')
    await assertRatingRejected('1000000000', 'bounds-huge-string')
  })

  void it('rejects a non-numeric rating before saving it', async () => {
    await assertRatingRejected('nope', 'bounds-not-a-number')
  })
})
