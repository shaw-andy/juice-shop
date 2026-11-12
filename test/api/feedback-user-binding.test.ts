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
import { FeedbackModel } from '../../models/feedback'
import { UserModel } from '../../models/user'

let app: Express
let callerToken = ''
const jsonHeader = { 'content-type': 'application/json' }
const callerEmail = 'feedback-binding@example.test'
const callerPassword = 'placeholder-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
  await register(app, { email: callerEmail, password: callerPassword })
  const authentication = await login(app, { email: callerEmail, password: callerPassword })
  callerToken = authentication.token
  assert.equal(typeof callerToken, 'string')
  assert.ok(callerToken.length > 0)
}, { timeout: 60000 })

async function solvedCaptcha () {
  const captchaRes = await request(app).get('/rest/captcha')
  assert.equal(captchaRes.status, 200)
  assert.equal(typeof captchaRes.body.captchaId, 'number')
  assert.ok(captchaRes.body.answer !== undefined && captchaRes.body.answer !== null)
  return {
    captchaId: captchaRes.body.captchaId as number,
    captcha: captchaRes.body.answer as string
  }
}

async function firstAdministrator () {
  const admin = await UserModel.findOne({ where: { role: 'admin' }, order: [['id', 'ASC']] })
  assert.ok(admin)
  assert.equal(typeof admin.id, 'number')
  return admin
}

async function registeredCaller () {
  const caller = await UserModel.findOne({ where: { email: callerEmail } })
  assert.ok(caller)
  const admin = await firstAdministrator()
  assert.notEqual(caller.id, admin.id)
  return { caller, admin, token: callerToken }
}

async function publicFeedbacks () {
  const res = await request(app).get('/api/Feedbacks')
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data as Array<{ comment?: string, UserId?: number | null }>
}

void describe('feedback user binding', () => {
  void it('stores a null user id when an anonymous comment names another account', async () => {
    const admin = await firstAdministrator()
    const comment = 'Anonymous numeric user binding probe'
    const captcha = await solvedCaptcha()

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment,
        rating: 1,
        UserId: admin.id,
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })

    assert.equal(res.status, 201)
    assert.equal(res.body.data.comment, comment)
    assert.equal(res.body.data.UserId, null)

    const stored = await FeedbackModel.findOne({ where: { comment } })
    assert.ok(stored)
    assert.equal(stored.UserId, null)

    const listed = (await publicFeedbacks()).find((row) => row.comment === comment)
    assert.ok(listed)
    assert.equal(listed.UserId, undefined)
  })

  void it('stores a null user id when an anonymous comment names another account as a string', async () => {
    const admin = await firstAdministrator()
    const comment = 'Anonymous string user binding probe'
    const captcha = await solvedCaptcha()

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment,
        rating: 2,
        UserId: String(admin.id),
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })

    assert.equal(res.status, 201)
    const stored = await FeedbackModel.findOne({ where: { comment } })
    assert.ok(stored)
    assert.equal(stored.UserId, null)

    const listed = (await publicFeedbacks()).find((row) => row.comment === comment)
    assert.ok(listed)
    assert.equal(listed.UserId, undefined)
  })

  void it('stores the signed-in user id and ignores a different user id in the body', async () => {
    const { caller, admin, token } = await registeredCaller()
    const comment = 'Signed-in numeric user binding probe'
    const captcha = await solvedCaptcha()

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment,
        rating: 3,
        UserId: admin.id,
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })

    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, caller.id)
    assert.notEqual(res.body.data.UserId, admin.id)

    const stored = await FeedbackModel.findOne({ where: { comment: res.body.data.comment } })
    assert.ok(stored)
    assert.equal(stored.UserId, caller.id)
    assert.notEqual(stored.UserId, admin.id)

    const listed = (await publicFeedbacks()).find((row) => row.comment === res.body.data.comment)
    assert.ok(listed)
    assert.equal(listed.UserId, undefined)
  })

  void it('stores the signed-in user id when the body user id is a string', async () => {
    const { caller, admin, token } = await registeredCaller()
    const comment = 'Signed-in string user binding probe'
    const captcha = await solvedCaptcha()

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment,
        rating: 4,
        UserId: String(admin.id),
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })

    assert.equal(res.status, 201)
    const stored = await FeedbackModel.findOne({ where: { comment: res.body.data.comment } })
    assert.ok(stored)
    assert.equal(stored.UserId, caller.id)
    assert.notEqual(Number(stored.UserId), admin.id)
  })

  void it('stores the signed-in user id when the body omits the user id', async () => {
    const { caller, token } = await registeredCaller()
    const comment = 'Signed-in omitted user binding probe'
    const captcha = await solvedCaptcha()

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment,
        rating: 1,
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })

    assert.equal(res.status, 201)
    const stored = await FeedbackModel.findOne({ where: { comment: res.body.data.comment } })
    assert.ok(stored)
    assert.equal(stored.UserId, caller.id)
  })

  void it('omits UserId from every row of the unauthenticated feedback list', async () => {
    const rows = await publicFeedbacks()
    assert.ok(rows.length > 0)
    for (const row of rows) {
      assert.equal(row.UserId, undefined)
    }
  })

  void it('does not store a comment when the captcha answer is wrong', async () => {
    const admin = await firstAdministrator()
    const comment = 'Rejected captcha user binding probe'
    const captcha = await solvedCaptcha()

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment,
        rating: 1,
        UserId: admin.id,
        captchaId: captcha.captchaId,
        captcha: String(captcha.captcha) + '9'
      })

    assert.equal(res.status, 401)
    const stored = await FeedbackModel.findOne({ where: { comment } })
    assert.equal(stored, null)
  })
})
