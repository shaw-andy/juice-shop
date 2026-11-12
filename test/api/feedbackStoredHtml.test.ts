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
import { FeedbackModel } from '../../models/feedback'

let app: Express
let sequelize: Sequelize
const jsonHeader = { 'content-type': 'application/json' }

const nestedComment = '<<script>Foo</script>iframe src="javascript:alert(`xss`)">'

function assertCommentIsInert (comment: unknown, where: string) {
  const stored = comment == null ? '' : String(comment)
  assert.equal(
    /<iframe\b/i.test(stored),
    false,
    `${where} must not persist an iframe tag`
  )
  assert.equal(
    /javascript\s*:/i.test(stored),
    false,
    `${where} must not persist a javascript URL`
  )
}

async function postFeedback (comment: string) {
  const captchaRes = await request(app).get('/rest/captcha')
  assert.equal(captchaRes.status, 200)
  assert.equal(typeof captchaRes.body.captchaId, 'number')
  assert.equal(typeof captchaRes.body.answer, 'string')

  return await request(app)
    .post('/api/Feedbacks')
    .set(jsonHeader)
    .send({
      comment,
      rating: 1,
      captchaId: captchaRes.body.captchaId,
      captcha: captchaRes.body.answer
    })
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

void describe('Feedback comment HTML', () => {
  void it('does not store a nested-tag bypass as an iframe with a javascript URL', async () => {
    const created = await postFeedback(nestedComment)
    assert.equal(created.status, 201)
    assertCommentIsInert(created.body.data.comment, 'POST /api/Feedbacks')

    const listed = await request(app).get('/api/Feedbacks')
    assert.equal(listed.status, 200)
    const saved = listed.body.data.find((row: { id: number }) => row.id === created.body.data.id)
    assert.ok(saved)
    assertCommentIsInert(saved.comment, 'GET /api/Feedbacks')

    const [rows] = await sequelize.query(
      'SELECT comment FROM Feedbacks WHERE id = ?',
      { replacements: [created.body.data.id] }
    )
    assertCommentIsInert((rows as Array<{ comment: string }>)[0].comment, 'Feedbacks.comment column')
  })

  void it('does not store a nested-tag bypass when the comment is updated on the model', async () => {
    const created = await FeedbackModel.create({ comment: 'ordinary comment', rating: 1 })
    await created.update({ comment: nestedComment })
    await created.reload()
    assertCommentIsInert(created.comment, 'Feedback model update')
  })

  void it('does not store a nested-tag bypass from anonymous feedback creation', async () => {
    const created = await FeedbackModel.create({
      UserId: null,
      comment: nestedComment,
      rating: 2
    })
    assertCommentIsInert(created.comment, 'Feedback model create')
  })
})
