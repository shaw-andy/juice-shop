/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import jws from 'jws'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const placeholderNewPassword = 'placeholder-new-password'
const placeholderAnswer = 'placeholder-answer'
const sixHoursMs = 6 * 60 * 60 * 1000
const pastLifetimeMs = sixHoursMs + (2 * 60 * 1000)

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function sessionTokens (): string[] {
  return Object.keys(security.authenticatedUsers.tokenMap)
}

async function atTime<T> (nowMs: number, fn: () => Promise<T>): Promise<T> {
  const originalNow = Date.now
  Date.now = () => nowMs
  try {
    return await fn()
  } finally {
    Date.now = originalNow
  }
}

async function issuedPasswordProof (email: string, password: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })

  assert.equal(res.status, 401)
  assert.equal(res.body.status, 'totp_token_required')
  const tmpToken = res.body.data.tmpToken as string
  const payload = security.decode(tmpToken) as { userId: number, type: string }
  assert.equal(payload.type, 'password_valid_needs_second_factor_token')
  assert.equal(typeof payload.userId, 'number')
  return { tmpToken, userId: payload.userId }
}

async function postVerify (tmpToken: string, totpSecret: string) {
  const before = new Set(sessionTokens())
  const res = await request(app)
    .post('/rest/2fa/verify')
    .set(jsonHeader)
    .send({
      tmpToken,
      totpToken: generateSync({ secret: totpSecret })
    })
  const createdSessions = sessionTokens().filter((token) => !before.has(token))
  return { res, createdSessions }
}

function assertNoSession (res: request.Response, createdSessions: string[]) {
  assert.equal(res.status, 401)
  assert.equal(Object.hasOwn(res.body ?? {}, 'authentication'), false)
  assert.equal(createdSessions.length, 0)
}

void describe('password-proof token for /rest/2fa/verify', { concurrency: 1 }, () => {
  void it('still accepts a fresh password-proof token from login', async () => {
    const email = 'fresh-proof@example.test'
    const totpSecret = generateSecret()
    await register(app, { email, password: placeholderPassword, totpSecret })
    const { tmpToken } = await issuedPasswordProof(email, placeholderPassword)

    const { res, createdSessions } = await postVerify(tmpToken, totpSecret)

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication?.bid, 'number')
    assert.equal(createdSessions.length, 1)
  })

  void it('rejects the login password-proof token after six hours', async () => {
    const email = 'expired-proof@example.test'
    const totpSecret = generateSecret()
    await register(app, { email, password: placeholderPassword, totpSecret })
    const { tmpToken } = await issuedPasswordProof(email, placeholderPassword)
    const later = Date.now() + pastLifetimeMs

    const { res, createdSessions } = await atTime(later, async () => {
      return await postVerify(tmpToken, totpSecret)
    })

    assertNoSession(res, createdSessions)
  })

  void it('rejects a password-proof token after it has already completed login', async () => {
    const email = 'replay-proof@example.test'
    const totpSecret = generateSecret()
    await register(app, { email, password: placeholderPassword, totpSecret })
    const { tmpToken } = await issuedPasswordProof(email, placeholderPassword)

    const first = await postVerify(tmpToken, totpSecret)
    assert.equal(first.res.status, 200)

    const second = await postVerify(tmpToken, totpSecret)
    assertNoSession(second.res, second.createdSessions)
  })

  void it('rejects a password-proof token after the account password changes', async () => {
    const email = 'password-change-proof@example.test'
    const totpSecret = generateSecret()
    await register(app, { email, password: placeholderPassword, totpSecret })
    const session = await login(app, { email, password: placeholderPassword, totpSecret })
    const { tmpToken } = await issuedPasswordProof(email, placeholderPassword)

    const change = await request(app)
      .get('/rest/user/change-password')
      .query({
        current: placeholderPassword,
        new: placeholderNewPassword,
        repeat: placeholderNewPassword
      })
      .set({ Authorization: 'Bearer ' + session.token })

    assert.equal(change.status, 200)

    const { res, createdSessions } = await postVerify(tmpToken, totpSecret)
    assertNoSession(res, createdSessions)
  })

  void it('rejects a password-proof token after a password reset', async () => {
    const email = 'password-reset-proof@example.test'
    const totpSecret = generateSecret()
    const registered = await register(app, { email, password: placeholderPassword, totpSecret })
    const userId = registered.body.data?.id ?? registered.body.id
    assert.equal(typeof userId, 'number')

    const answer = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
      .send({
        UserId: userId,
        SecurityQuestionId: 1,
        answer: placeholderAnswer
      })
    assert.equal(answer.status, 201)

    const { tmpToken } = await issuedPasswordProof(email, placeholderPassword)

    const reset = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email,
        answer: placeholderAnswer,
        new: placeholderNewPassword,
        repeat: placeholderNewPassword
      })
    assert.equal(reset.status, 200)

    const { res, createdSessions } = await postVerify(tmpToken, totpSecret)
    assertNoSession(res, createdSessions)
  })

  void it('rejects a password-proof token whose algorithm is none', async () => {
    const email = 'alg-none-proof@example.test'
    const totpSecret = generateSecret()
    await register(app, { email, password: placeholderPassword, totpSecret })
    const { userId } = await issuedPasswordProof(email, placeholderPassword)
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      userId,
      type: 'password_valid_needs_second_factor_token'
    })).toString('base64url')

    const { res, createdSessions } = await postVerify(`${header}.${payload}.`, totpSecret)
    assertNoSession(res, createdSessions)
  })

  void it('rejects a password-proof token signed as HMAC with the public key', async () => {
    const email = 'alg-hmac-proof@example.test'
    const totpSecret = generateSecret()
    await register(app, { email, password: placeholderPassword, totpSecret })
    const { userId } = await issuedPasswordProof(email, placeholderPassword)
    const publicKey = fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
    const tmpToken = jws.sign({
      header: { alg: 'HS256', typ: 'JWT' },
      payload: {
        userId,
        type: 'password_valid_needs_second_factor_token'
      },
      secret: publicKey
    })

    const { res, createdSessions } = await postVerify(tmpToken, totpSecret)
    assertNoSession(res, createdSessions)
  })
})

void describe('setup token for /rest/2fa/setup', { concurrency: 1 }, () => {
  void it('rejects a setup token once six hours have passed and does not enable 2FA', async () => {
    const email = 'setup-lifetime@example.test'
    await register(app, { email, password: placeholderPassword })
    const { token } = await login(app, { email, password: placeholderPassword })
    const status = await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(status.status, 200)
    assert.equal(status.body.setup, false)

    const later = Date.now() + pastLifetimeMs
    const setup = await atTime(later, async () => {
      return await request(app)
        .post('/rest/2fa/setup')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
        .send({
          password: placeholderPassword,
          setupToken: status.body.setupToken,
          initialToken: generateSync({ secret: status.body.secret })
        })
    })

    assert.equal(setup.status, 401)

    const statusAfter = await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    assert.equal(statusAfter.status, 200)
    assert.equal(statusAfter.body.setup, false)
  })
})
