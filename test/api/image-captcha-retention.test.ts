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
import { ImageCaptchaModel } from '../../models/imageCaptcha'
import * as security from '../../lib/insecurity'

const placeholderPassword = 'placeholder-password'
const verificationWindowMs = 300000

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function openAccount () {
  const email = `image-captcha-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`
  await register(app, { email, password: placeholderPassword })
  const authentication = await login(app, { email, password: placeholderPassword })
  const user = security.authenticatedUsers.get(authentication.token)
  assert.ok(user?.data?.id)
  return {
    userId: user.data.id,
    authHeader: {
      Authorization: 'Bearer ' + authentication.token,
      'content-type': 'application/json'
    }
  }
}

async function captchasFor (userId: number) {
  return await ImageCaptchaModel.findAll({ where: { UserId: userId }, order: [['id', 'ASC']] })
}

function retainedResponses (rows: Array<{ image: string }>, images: string[]) {
  return images.filter(image => rows.some(row => row.image === image))
}

void describe('image captcha retention', { concurrency: 1 }, () => {
  void it('an anonymous image-captcha request stores nothing', async () => {
    const before = await ImageCaptchaModel.count()

    const res = await request(app).get('/rest/image-captcha')

    assert.equal(res.status, 401)
    assert.equal(await ImageCaptchaModel.count(), before)
  })

  void it('repeated image-captcha requests keep at most one stored SVG per user', async () => {
    const account = await openAccount()
    const images: string[] = []

    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .get('/rest/image-captcha')
        .set(account.authHeader)
      assert.equal(res.status, 200)
      assert.match(String(res.body.image), /<svg[\s>]/)
      images.push(res.body.image)
    }

    const rows = await captchasFor(account.userId)
    const retained = retainedResponses(rows, images)
    assert.ok(
      rows.length <= 1 && retained.length <= 1,
      `expected at most one stored image captcha, found ${rows.length} rows retaining ${retained.length} of ${images.length} SVGs (stored image lengths ${rows.map(row => row.image.length).join(',')})`
    )
  })

  void it('a captcha older than the verification window is not kept beside a newer one', async () => {
    const account = await openAccount()
    const first = await request(app)
      .get('/rest/image-captcha')
      .set(account.authHeader)
    assert.equal(first.status, 200)

    const [aged] = await ImageCaptchaModel.update(
      { createdAt: new Date(Date.now() - verificationWindowMs - 60000) },
      { where: { UserId: account.userId }, silent: true }
    )
    assert.equal(aged, 1)

    const second = await request(app)
      .get('/rest/image-captcha')
      .set(account.authHeader)
    assert.equal(second.status, 200)
    assert.match(String(second.body.image), /<svg[\s>]/)

    const rows = await captchasFor(account.userId)
    const retained = retainedResponses(rows, [first.body.image, second.body.image])
    assert.ok(
      rows.length <= 1 && retained.length <= 1,
      `expected the expired captcha to be replaced, found ${rows.length} rows retaining ${retained.length} SVGs`
    )
  })

  void it('a rejected captcha answer does not leave every generated SVG in place', async () => {
    const account = await openAccount()
    const images: string[] = []

    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .get('/rest/image-captcha')
        .set(account.authHeader)
      assert.equal(res.status, 200)
      images.push(res.body.image)
    }

    const rejected = await request(app)
      .post('/rest/user/data-export')
      .set(account.authHeader)
      .send({ answer: 'placeholder-wrong-answer', format: 1 })

    assert.equal(rejected.status, 401)
    const rows = await captchasFor(account.userId)
    const retained = retainedResponses(rows, images)
    assert.ok(
      rows.length <= 1 && retained.length <= 1,
      `expected no captcha history after a rejected check, found ${rows.length} rows retaining ${retained.length} SVGs`
    )
  })

  void it('a successful captcha check deletes that user\'s stored captcha and leaves other users alone', async () => {
    const account = await openAccount()
    const other = await openAccount()

    const otherCaptcha = await request(app)
      .get('/rest/image-captcha')
      .set(other.authHeader)
    assert.equal(otherCaptcha.status, 200)
    const otherBefore = (await captchasFor(other.userId)).map(row => row.id)

    let ownCaptcha = await request(app)
      .get('/rest/image-captcha')
      .set(account.authHeader)
    assert.equal(ownCaptcha.status, 200)
    let attempts = 0
    while (ownCaptcha.body.answer === otherCaptcha.body.answer && attempts < 5) {
      ownCaptcha = await request(app)
        .get('/rest/image-captcha')
        .set(account.authHeader)
      assert.equal(ownCaptcha.status, 200)
      attempts++
    }
    assert.notEqual(ownCaptcha.body.answer, otherCaptcha.body.answer)
    assert.equal(typeof ownCaptcha.body.answer, 'string')

    const wrongUser = await request(app)
      .post('/rest/user/data-export')
      .set(account.authHeader)
      .send({ answer: otherCaptcha.body.answer, format: 1 })
    assert.equal(wrongUser.status, 401)
    assert.deepEqual((await captchasFor(other.userId)).map(row => row.id), otherBefore)

    const accepted = await request(app)
      .post('/rest/user/data-export')
      .set(account.authHeader)
      .send({ answer: ownCaptcha.body.answer, format: 1 })
    assert.equal(accepted.status, 200)
    assert.equal(await ImageCaptchaModel.count({ where: { UserId: account.userId } }), 0)
    assert.deepEqual((await captchasFor(other.userId)).map(row => row.id), otherBefore)
  })
})
