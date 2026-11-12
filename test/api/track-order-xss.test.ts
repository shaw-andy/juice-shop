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
import * as utils from '../../lib/utils'

let app: Express

const markupWithinLimit = '<img src=x onerror=document.title=localStorage.token>'
const challengeMarkup = '<iframe src="javascript:alert(`xss`)">'
const markupPastLimit = markupWithinLimit + '<!--' + 'x'.repeat(20) + '-->'

before(async () => {
  const result = await createTestApp()
  app = result.app
  challenges.reflectedXssChallenge.disabledEnv = null
  assert.equal(utils.isChallengeEnabled(challenges.reflectedXssChallenge), true)
  assert.ok(markupWithinLimit.length <= 60)
  assert.ok(challengeMarkup.length <= 60)
  assert.ok(markupPastLimit.length > 60)
}, { timeout: 60000 })

async function track (id: string) {
  return await request(app).get('/rest/track-order/' + encodeURIComponent(id))
}

void describe('/rest/track-order/:id reflected markup', () => {
  void it('returns a word-only order id when the tracking id is a script-bearing tag', async () => {
    const res = await track(markupWithinLimit)
    assert.equal(res.status, 200)
    const orderId = res.body.data[0].orderId
    assert.equal(typeof orderId, 'string')
    assert.equal(orderId.includes('<'), false)
    assert.equal(orderId.includes('>'), false)
    assert.equal(orderId.includes('onerror'), false)
    assert.equal(orderId, markupWithinLimit.replace(/[^\w-]+/g, ''))
  })

  void it('returns a word-only order id for the reflected XSS challenge payload', async () => {
    const res = await track(challengeMarkup)
    assert.equal(res.status, 200)
    const orderId = res.body.data[0].orderId
    assert.equal(orderId.includes('<'), false)
    assert.equal(orderId.includes('javascript'), false)
    assert.equal(orderId, challengeMarkup.replace(/[^\w-]+/g, ''))
  })

  void it('returns a word-only order id when the tracking id is longer than the truncation limit', async () => {
    const res = await track(markupPastLimit)
    assert.equal(res.status, 200)
    const orderId = res.body.data[0].orderId
    assert.equal(orderId.includes('<'), false)
    assert.equal(orderId.includes('>'), false)
    assert.equal(orderId.includes('...'), false)
    assert.equal(orderId, markupPastLimit.replace(/[^\w-]+/g, ''))
  })

  void it('still returns an ordinary tracking id unchanged', async () => {
    const benign = 'order-safe-1'
    const res = await track(benign)
    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].orderId, benign)
  })
})
