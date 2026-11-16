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
import { UserModel } from '../../models/user'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
const customerEmail = 'privacy.customer.alpha@example.test'
const placeholderPassword = 'placeholder-password'
const review = 'Fresh apples'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function exposedEmailTail (email: string): string | undefined {
  const at = email.indexOf('@')
  if (at <= 3) return undefined
  return email.slice(3)
}

async function captchaAnswer () {
  const captchaRes = await request(app).get('/rest/captcha')
  assert.equal(captchaRes.status, 200)
  return { captchaId: captchaRes.body.captchaId, captcha: captchaRes.body.answer }
}

void describe('public feedback author privacy', { concurrency: 1 }, () => {
  void it('anonymous GET does not reveal seeded author email tails', async () => {
    const users = await UserModel.findAll({ attributes: ['id', 'email'], paranoid: false })
    const res = await request(app).get('/api/Feedbacks')
    assert.equal(res.status, 200)
    const published = JSON.stringify(res.body)
    for (const user of users) {
      const tail = user.email ? exposedEmailTail(user.email) : undefined
      if (tail === undefined) continue
      assert.equal(published.includes(tail), false, `public feedback exposes the tail of user ${user.id}'s email`)
    }
  })

  void it('anonymous GET does not reveal the email tail the contact form appends', async () => {
    const tail = exposedEmailTail(customerEmail)
    assert.ok(tail)

    await register(app, { email: customerEmail, password: placeholderPassword })
    const { token } = await login(app, { email: customerEmail, password: placeholderPassword })

    const who = await request(app)
      .get('/rest/user/whoami?fields=id,email')
      .set({ Cookie: `token=${token}` })
    assert.equal(who.status, 200)
    assert.equal(who.body.user.email, customerEmail)

    const captcha = await captchaAnswer()
    const author = `***${customerEmail.slice(3)}`
    const posted = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, ...jsonHeader })
      .send({
        comment: `${review} (${author})`,
        rating: 2,
        UserId: who.body.user.id,
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })
    assert.equal(posted.status, 201)

    const res = await request(app).get('/api/Feedbacks')
    assert.equal(res.status, 200)
    const published = JSON.stringify(res.body)
    assert.equal(published.includes(review), true)
    assert.equal(published.includes(tail), false)
    assert.equal(published.includes(customerEmail), false)
  })

  void it('anonymous GET does not reveal an email a client puts in the comment', async () => {
    const tail = exposedEmailTail(customerEmail)
    assert.ok(tail)
    const captcha = await captchaAnswer()
    const posted = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: `Second review (${customerEmail})`,
        rating: 1,
        captchaId: captcha.captchaId,
        captcha: captcha.captcha
      })
    assert.equal(posted.status, 201)

    const res = await request(app).get('/api/Feedbacks')
    assert.equal(res.status, 200)
    const published = JSON.stringify(res.body)
    assert.equal(published.includes('Second review'), true)
    assert.equal(published.includes(tail), false)
    assert.equal(published.includes(customerEmail), false)
  })
})
