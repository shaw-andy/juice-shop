/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import './helpers/enable-safety-mode'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'

function nestedClosingDivs (layers: number) {
  return '<p>' + '<'.repeat(layers) + '/div>'.repeat(layers) + 'x</p>'
}

const STALL_LAYERS = 8000
const STACK_LAYERS = 14000
const HEADER_LAYERS = 2500
const BODY_BUDGET_MS = 500
const HEADER_BUDGET_MS = 150
const jsonHeader = { 'content-type': 'application/json' }

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
  assert.equal(utils.isChallengeEnabled(challenges.restfulXssChallenge), false)
  assert.equal(utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge), false)
  assert.equal(utils.isChallengeEnabled(challenges.persistedXssUserChallenge), false)
  assert.equal(utils.isChallengeEnabled(challenges.httpHeaderXssChallenge), false)
}, { timeout: 60000 })

function assertNoStackOverflow (body: unknown) {
  assert.equal(JSON.stringify(body ?? '').includes('Maximum call stack size exceeded'), false)
}

void describe('recursive HTML cleaner bound', () => {
  void it('still accepts a stable product description', async () => {
    const res = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ description: '<p>hello</p>' })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.description, '<p>hello</p>')
  })

  void it('does not let a nested product description block other requests', async () => {
    const started = Date.now()
    const [update, other] = await Promise.all([
      request(app).put('/api/Products/1').set(jsonHeader).send({ description: nestedClosingDivs(STALL_LAYERS) }),
      request(app).get('/api/Products/1')
    ])
    const elapsed = Date.now() - started
    assert.ok(elapsed < BODY_BUDGET_MS, `product update blocked the event loop for ${elapsed}ms`)
    assertNoStackOverflow(update.body)
    assert.equal(other.status, 200)
  })

  void it('does not overflow the stack on a product description nested to the call-stack limit', async () => {
    const started = Date.now()
    const res = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ description: nestedClosingDivs(STACK_LAYERS) })
    const elapsed = Date.now() - started
    assert.ok(elapsed < BODY_BUDGET_MS, `product update blocked the event loop for ${elapsed}ms`)
    assertNoStackOverflow(res.body)
    const after = await request(app).get('/api/Products/2')
    assert.equal(after.status, 200)
  })

  void it('does not let a nested feedback comment block the shop', async () => {
    const captcha = await request(app).get('/rest/captcha')
    assert.equal(captcha.status, 200)
    const started = Date.now()
    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: nestedClosingDivs(STALL_LAYERS),
        rating: 1,
        captchaId: captcha.body.captchaId,
        captcha: captcha.body.answer
      })
    const elapsed = Date.now() - started
    assert.ok(elapsed < BODY_BUDGET_MS, `feedback create blocked the event loop for ${elapsed}ms`)
    assertNoStackOverflow(res.body)
  })

  void it('does not let a nested registration email block the shop', async () => {
    const started = Date.now()
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: nestedClosingDivs(STALL_LAYERS),
        password: 'placeholder-password',
        passwordRepeat: 'placeholder-password'
      })
    const elapsed = Date.now() - started
    assert.ok(elapsed < BODY_BUDGET_MS, `user registration blocked the event loop for ${elapsed}ms`)
    assertNoStackOverflow(res.body)
  })

  void it('does not let a nested registration username block the shop', async () => {
    const started = Date.now()
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'nested-username@example.com',
        username: nestedClosingDivs(STALL_LAYERS),
        password: 'placeholder-password',
        passwordRepeat: 'placeholder-password'
      })
    const elapsed = Date.now() - started
    assert.ok(elapsed < BODY_BUDGET_MS, `user registration blocked the event loop for ${elapsed}ms`)
    assertNoStackOverflow(res.body)
  })

  void it('does not let a nested True-Client-IP header block the shop', async () => {
    const registered = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'login-ip@example.com',
        password: 'placeholder-password',
        passwordRepeat: 'placeholder-password'
      })
    assert.equal(registered.status, 201)
    const login = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: 'login-ip@example.com', password: 'placeholder-password' })
    assert.equal(login.status, 200)

    const started = Date.now()
    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + login.body.authentication.token,
        'true-client-ip': nestedClosingDivs(HEADER_LAYERS)
      })
    const elapsed = Date.now() - started
    assert.ok(elapsed < HEADER_BUDGET_MS, `saveLoginIp blocked the event loop for ${elapsed}ms`)
    assertNoStackOverflow(res.body)
    assert.notEqual(res.status, 431)
  })
})
