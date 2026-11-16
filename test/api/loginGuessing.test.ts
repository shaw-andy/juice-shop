/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomUUID } from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { generateSecret } from 'otplib'
import { createTestApp } from './helpers/setup'
import { register } from './helpers/auth'

const PLACEHOLDER_PASSWORD = 'PLACEHOLDER-password-1'
const PLACEHOLDER_WRONG = 'PLACEHOLDER_WRONG'
const PLACEHOLDER_ANSWER = 'PLACEHOLDER_ANSWER'
const SHORT_PASSWORD = 'x'.repeat(7)
const FAILURE_BUDGET = 5
const jsonHeader = { 'content-type': 'application/json' }

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function emailFor (label: string) {
  return `${label}-${randomUUID()}@example.test`
}

function postLogin (email: string, password: string, forwardedFor?: string) {
  const req = request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
  if (forwardedFor !== undefined) {
    req.set('X-Forwarded-For', forwardedFor)
  }
  return req.send({ email, password })
}

function isGuessingBlocked (res: Response) {
  if (res.body?.authentication?.token !== undefined) {
    return false
  }
  if (res.body?.status === 'totp_token_required' || res.body?.data?.tmpToken !== undefined) {
    return false
  }
  if (res.status === 429 || res.status === 423 || res.status === 403) {
    return true
  }
  const text = `${res.text} ${JSON.stringify(res.body ?? {})}`.toLowerCase()
  return res.status === 401 && (text.includes('captcha') || text.includes('locked') || text.includes('too many'))
}

async function registerUser (email: string, password: string) {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email,
      password,
      passwordRepeat: password
    })
  return res
}

void describe('password guessing on POST /rest/user/login', { concurrency: 1 }, () => {
  void it('blocks further guesses for an account after a few failures, including a correct password from a new forwarded address', async () => {
    const email = emailFor('guess-target')
    const otherEmail = emailFor('guess-other')
    const created = await registerUser(email, PLACEHOLDER_PASSWORD)
    assert.equal(created.status, 201)
    const other = await registerUser(otherEmail, PLACEHOLDER_PASSWORD)
    assert.equal(other.status, 201)

    const first = await postLogin(email, PLACEHOLDER_WRONG)
    assert.equal(first.status, 401)

    for (let i = 1; i < FAILURE_BUDGET; i++) {
      await postLogin(email, `${PLACEHOLDER_WRONG}-${i}`)
    }

    const extraWrong = await postLogin(email, PLACEHOLDER_WRONG, '203.0.113.50')
    const correct = await postLogin(email, PLACEHOLDER_PASSWORD, '203.0.113.51')
    const tokenIssued = correct.body?.authentication?.token !== undefined
    assert.ok(
      isGuessingBlocked(extraWrong) && isGuessingBlocked(correct),
      `after ${FAILURE_BUDGET} failures the next wrong guess was ${extraWrong.status} and the correct password was ${correct.status} with authentication ${tokenIssued ? 'issued' : 'absent'}`
    )

    const otherLogin = await postLogin(otherEmail, PLACEHOLDER_PASSWORD)
    assert.equal(otherLogin.status, 200)
    assert.equal(typeof otherLogin.body.authentication.token, 'string')
    assert.equal(otherLogin.body.authentication.umail, otherEmail)
  })

  void it('does not confirm a correct password on a two-factor account with a distinct response', async () => {
    const email = emailFor('two-factor')
    const totpSecret = generateSecret()
    await register(app, { email, password: PLACEHOLDER_PASSWORD, totpSecret })

    const wrong = await postLogin(email, PLACEHOLDER_WRONG)
    const right = await postLogin(email, PLACEHOLDER_PASSWORD)

    assert.equal(right.status, wrong.status)
    assert.equal(right.body?.status ?? null, wrong.body?.status ?? null)
    assert.equal(right.body?.data?.tmpToken !== undefined, wrong.body?.data?.tmpToken !== undefined)
    assert.equal(right.body?.authentication ?? null, wrong.body?.authentication ?? null)
  })
})

void describe('server-side password strength', { concurrency: 1 }, () => {
  void it('rejects a short password when a user registers', async () => {
    const email = emailFor('weak-register')
    const res = await registerUser(email, SHORT_PASSWORD)

    assert.ok(
      res.status === 400 || res.status === 422,
      `expected a short password to be rejected at registration, got ${res.status}`
    )

    const loginRes = await postLogin(email, SHORT_PASSWORD)
    assert.notEqual(loginRes.status, 200)
    assert.equal(loginRes.body?.authentication, undefined)
  })

  void it('rejects a short replacement password on the change-password route', async () => {
    const email = emailFor('weak-change')
    const created = await registerUser(email, PLACEHOLDER_PASSWORD)
    assert.equal(created.status, 201)

    const loginRes = await postLogin(email, PLACEHOLDER_PASSWORD)
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token

    const changed = await request(app)
      .get('/rest/user/change-password')
      .query({ current: PLACEHOLDER_PASSWORD, new: SHORT_PASSWORD, repeat: SHORT_PASSWORD })
      .set({ Authorization: 'Bearer ' + token })

    assert.ok(
      changed.status === 400 || changed.status === 422,
      `expected a short replacement password to be rejected, got ${changed.status}`
    )

    const stillOriginal = await postLogin(email, PLACEHOLDER_PASSWORD)
    assert.equal(stillOriginal.status, 200)
    const withShort = await postLogin(email, SHORT_PASSWORD)
    assert.notEqual(withShort.status, 200)
    assert.equal(withShort.body?.authentication, undefined)
  })

  void it('rejects a short password on the reset-password route', async () => {
    const email = emailFor('weak-reset')
    const created = await registerUser(email, PLACEHOLDER_PASSWORD)
    assert.equal(created.status, 201)
    const userId = created.body.data.id

    const answer = await request(app)
      .post('/api/SecurityAnswers/')
      .set(jsonHeader)
      .send({
        UserId: userId,
        SecurityQuestionId: 1,
        answer: PLACEHOLDER_ANSWER
      })
    assert.ok(answer.status === 200 || answer.status === 201, `failed to store a security answer: ${answer.status}`)

    const reset = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email,
        answer: PLACEHOLDER_ANSWER,
        new: SHORT_PASSWORD,
        repeat: SHORT_PASSWORD
      })

    assert.ok(
      reset.status === 400 || reset.status === 422,
      `expected a short reset password to be rejected, got ${reset.status}`
    )

    const stillOriginal = await postLogin(email, PLACEHOLDER_PASSWORD)
    assert.equal(stillOriginal.status, 200)
    const withShort = await postLogin(email, SHORT_PASSWORD)
    assert.notEqual(withShort.status, 200)
    assert.equal(withShort.body?.authentication, undefined)
  })
})
