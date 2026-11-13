/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { Op } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { FeedbackModel } from '../../models/feedback'
import * as security from '../../lib/insecurity'

const maxCommentLength = 500
const maxListPage = 10
const maxCreatesInBurst = 5
const burstSize = 8

let app: Express
let sequelize: Sequelize

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

void describe('feedback storage bounds', { concurrency: 1 }, () => {
  void it('stores a short comment with a rating from 0 to 5', async () => {
    for (const rating of [0, 5]) {
      const marker = `short-ok-${rating}`
      const before = await feedbackSequence()
      const res = await postFeedback({ comment: marker, rating })
      assert.equal(res.status, 201)
      assert.equal(res.body.data.comment, marker)
      assert.equal(res.body.data.rating, rating)
      assert.equal(await feedbackSequence(), before + 1)
      assert.equal(await storedComment(marker), marker)
    }
  })

  void it('rejects an overlong comment without saving it', async () => {
    const failures = []
    failures.push(await attempt(() => assertRejectedWithoutInsert({ comment: overlongComment('json-anon', 20000), rating: 1 })))
    failures.push(await attempt(() => assertRejectedWithoutInsert({ comment: overlongComment('form-anon'), rating: 3 }, 'form')))
    failures.push(await attempt(() => assertRejectedWithoutInsert({ comment: overlongComment('json-auth'), rating: 4 }, 'json', true)))
    assert.deepEqual(failures.filter(Boolean), [])
  })

  void it('rejects a rating outside 0 to 5 without saving it', async () => {
    const failures = []
    for (const rating of [6, -1, 99]) {
      failures.push(await attempt(() => assertRejectedWithoutInsert({ comment: `bad-rating-${rating}`, rating })))
    }
    assert.deepEqual(failures.filter(Boolean), [])
  })

  void it('does not persist every rapid anonymous feedback create', async () => {
    const markers: string[] = []
    let successes = 0
    const before = await feedbackSequence()
    for (let i = 0; i < burstSize; i++) {
      const marker = `burst-${i}-${before}`
      markers.push(marker)
      const res = await postFeedback({ comment: marker, rating: 2 })
      if (res.status >= 200 && res.status < 300) successes++
    }
    let stored = 0
    for (const marker of markers) {
      if (await storedComment(marker) != null) stored++
    }
    const created = await feedbackSequence() - before
    assert.ok(stored <= maxCreatesInBurst, `stored ${stored} of ${burstSize} rapid creates`)
    assert.ok(successes < burstSize, `all ${burstSize} rapid creates were accepted`)
    assert.equal(stored, successes, `accepted ${successes} but left ${stored} rows`)
    assert.equal(created, stored, `sequence advanced by ${created} while ${stored} rows remain`)
  })

  void it('does not return every feedback row from the public list', async () => {
    const before = await FeedbackModel.count()
    for (let i = 0; i < maxListPage + 20; i++) {
      await FeedbackModel.create({ comment: `page-probe-${before}-${i}`, rating: 1 })
    }
    const total = await FeedbackModel.count()
    assert.ok(total > maxListPage, `expected more than ${maxListPage} stored feedback rows, found ${total}`)

    const failures = []
    for (const url of ['/api/Feedbacks/', '/api/Feedbacks']) {
      failures.push(await attempt(async () => {
        const listed = await listedFeedback(url)
        assert.ok(listed.length <= maxListPage, `${url} returned ${listed.length} of ${total} rows`)
        assert.ok(listed.length < total, `${url} returned every stored row (${listed.length})`)
      }))
      failures.push(await attempt(async () => {
        const unlimited = await listedFeedback(url, { count: 100000, limit: 100000, offset: 0 })
        assert.ok(unlimited.length <= maxListPage, `${url} with a huge page size returned ${unlimited.length} of ${total} rows`)
        assert.ok(unlimited.length < total, `${url} with a huge page size returned every stored row (${unlimited.length})`)
      }))
    }
    assert.deepEqual(failures.filter(Boolean), [])
  })
})

async function attempt (run: () => Promise<void>) {
  try {
    await run()
    return null
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}

function overlongComment (label: string, length = maxCommentLength) {
  return `${label}-${'A'.repeat(length)}`
}

async function postFeedback (fields: { comment: string, rating: number }, encoding: 'json' | 'form' = 'json', authorized = false) {
  const captchaRes = await request(app).get('/rest/captcha')
  assert.equal(captchaRes.status, 200)
  assert.equal(typeof captchaRes.body.answer, 'string')
  assert.ok(captchaRes.body.answer.length > 0)
  const payload = {
    comment: fields.comment,
    rating: fields.rating,
    captchaId: captchaRes.body.captchaId,
    captcha: captchaRes.body.answer
  }
  const req = request(app).post('/api/Feedbacks')
  if (authorized) {
    req.set('Authorization', 'Bearer ' + security.authorize())
  }
  if (encoding === 'form') {
    return await req.type('form').send(payload)
  }
  return await req.set('content-type', 'application/json').send(payload)
}

async function assertRejectedWithoutInsert (fields: { comment: string, rating: number }, encoding: 'json' | 'form' = 'json', authorized = false) {
  const before = await feedbackSequence()
  const res = await postFeedback(fields, encoding, authorized)
  const stored = await storedComment(fields.comment)
  const after = await feedbackSequence()
  const detail = `status ${res.status} storedLength ${stored?.length ?? 0} sequence ${before}->${after}`
  assert.ok(res.status >= 400 && res.status < 500, `expected a 4xx rejection, ${detail}`)
  assert.equal(stored, null, detail)
  assert.equal(after, before, `a rejected feedback create advanced the row sequence (${detail})`)
}

async function storedComment (marker: string) {
  const row = await FeedbackModel.findOne({ where: { comment: { [Op.like]: `%${marker}%` } } })
  return row?.comment ?? null
}

async function feedbackSequence () {
  const [rows] = await sequelize.query("SELECT seq AS seq FROM sqlite_sequence WHERE name = 'Feedbacks'")
  const list = rows as Array<{ seq: number }>
  if (!list.length) return 0
  return Number(list[0].seq)
}

async function listedFeedback (url: string, query?: Record<string, number>) {
  const req = request(app).get(url)
  const res = query ? await req.query(query) : await req
  assert.equal(res.status, 200, `${url} responded ${res.status}`)
  assert.ok(Array.isArray(res.body?.data), `${url} did not return a data array`)
  return res.body.data as any[]
}
