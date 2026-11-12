/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { CaptchaModel } from '../../models/captcha'
import { FeedbackModel } from '../../models/feedback'

const jsonHeader = { 'content-type': 'application/json' }
const floodSize = 20
const maxStoredRows = 5
const maxAgeMs = 15 * 60 * 1000
const impossibleAnswer = '100000'

let app: Express
let sequelize: Sequelize

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

function loggedStatements (logged: string[]): string[] {
  return logged.map((entry) => entry.replace(/^Executing \([^)]+\): /, ''))
}

async function explainPlan (sql: string): Promise<string> {
  const [rows] = await sequelize.query(`EXPLAIN QUERY PLAN ${sql}`)
  return (rows as Array<{ detail: string }>).map((row) => row.detail).join('\n')
}

void describe('GET /rest/captcha persistence', { concurrency: false }, () => {
  void it('does not keep a permanent Captchas row for every anonymous request', async () => {
    assert.equal(CaptchaModel.sequelize, sequelize)
    assert.equal(FeedbackModel.sequelize, sequelize)

    const before = await CaptchaModel.count()
    let accepted = 0
    let stored = before
    for (let i = 0; i < floodSize; i++) {
      const res = await request(app).get('/rest/captcha')
      const nextStored = await CaptchaModel.count()
      if (res.status === 429) {
        assert.equal(nextStored, stored, 'a refused captcha request still inserted a row')
      } else {
        assert.equal(res.status, 200, `unexpected status ${res.status}`)
        accepted++
      }
      stored = nextStored
    }

    assert.ok(accepted >= 1, 'anonymous callers can no longer obtain a captcha')
    assert.ok(
      stored - before <= maxStoredRows,
      `anonymous GET /rest/captcha stored ${stored - before} rows`
    )
  })

  void it('drops a captcha after a correct feedback check and still accepts the feedback', async () => {
    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    const captchaId = captchaRes.body.captchaId as number

    const created = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Captcha storage check.',
        rating: 1,
        captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(created.status, 201)
    assert.equal(await CaptchaModel.count({ where: { captchaId } }), 0)
  })

  void it('drops a captcha after an incorrect feedback check', async () => {
    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    const captchaId = captchaRes.body.captchaId as number

    const rejected = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Captcha storage check.',
        rating: 1,
        captchaId,
        captcha: impossibleAnswer
      })
    assert.equal(rejected.status, 401)
    assert.equal(await CaptchaModel.count({ where: { captchaId } }), 0)
  })

  void it('removes an unused captcha once it is older than fifteen minutes', async () => {
    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    const captchaId = captchaRes.body.captchaId as number
    const stored = await CaptchaModel.findAll({ where: { captchaId } })
    if (stored.length === 0) {
      return
    }

    const stale = new Date(Date.now() - maxAgeMs - 1000)
    const [updated] = await CaptchaModel.update(
      { createdAt: stale } as { createdAt: Date },
      { where: { captchaId }, silent: true }
    )
    assert.equal(updated, stored.length)
    const aged = await CaptchaModel.findOne({ where: { captchaId } })
    const createdAt = new Date(String(aged?.get('createdAt')))
    assert.ok(createdAt.getTime() <= Date.now() - maxAgeMs)

    const follow = await request(app).get('/rest/captcha')
    assert.equal(follow.status, 200)
    assert.equal(await CaptchaModel.count({ where: { captchaId } }), 0)
  })

  void it('does not look up captchaId with a full table scan', async () => {
    const logged: string[] = []
    const previous = sequelize.options.logging
    sequelize.options.logging = (sql: string) => {
      logged.push(sql)
    }
    try {
      const captchaRes = await request(app).get('/rest/captcha')
      assert.equal(captchaRes.status, 200)
      logged.length = 0
      const created = await request(app)
        .post('/api/Feedbacks')
        .set(jsonHeader)
        .send({
          comment: 'Captcha lookup check.',
          rating: 1,
          captchaId: captchaRes.body.captchaId,
          captcha: captchaRes.body.answer
        })
      assert.equal(created.status, 201)
    } finally {
      sequelize.options.logging = previous
    }

    const lookups = loggedStatements(logged).filter((sql) => /from `Captchas`/i.test(sql) && /captchaId/i.test(sql))
    for (const sql of lookups) {
      const plan = await explainPlan(sql)
      assert.match(plan, /USING INDEX/i, plan)
    }
  })
})
