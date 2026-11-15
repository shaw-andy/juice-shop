/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import request from 'supertest'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { BasketModel } from '../../models/basket'
import { UserModel } from '../../models/user'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const periodSeconds = 30

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function sessionsFor (userId: number) {
  return Object.entries(security.authenticatedUsers.tokenMap).filter(([, entry]) => {
    return entry?.data?.id === userId
  })
}

async function stabilizeTotpWindow () {
  const remainder = Math.floor(Date.now() / 1000) % periodSeconds
  const remaining = periodSeconds - remainder
  if (remaining < 20) {
    await delay((remaining + 1) * 1000)
  }
}

function codesAt (secret: string, epoch: number) {
  return {
    past: generateSync({ secret, epoch: epoch - periodSeconds }),
    current: generateSync({ secret, epoch }),
    future: generateSync({ secret, epoch: epoch + periodSeconds })
  }
}

async function registerUser () {
  const email = `otp-replay-${crypto.randomBytes(8).toString('hex')}@example.test`
  const password = crypto.randomBytes(18).toString('base64url')
  await register(app, { email, password })
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  return { email, password, userId: user.id }
}

async function enableTwoFactor (email: string, password: string, totpSecret: string, initialToken: string) {
  const { token } = await login(app, { email, password })
  const setupRes = await request(app)
    .post('/rest/2fa/setup')
    .set({
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    })
    .send({
      password,
      setupToken: security.authorize({
        secret: totpSecret,
        type: 'totp_setup_secret'
      }),
      initialToken
    })
  assert.equal(setupRes.status, 200)
}

async function beginTwoFactorLogin (email: string, password: string) {
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  assert.equal(loginRes.status, 401)
  assert.equal(loginRes.body.status, 'totp_token_required')
  assert.equal(typeof loginRes.body.data.tmpToken, 'string')
  return loginRes.body.data.tmpToken as string
}

function postVerify (body: { tmpToken: string, totpToken: string }) {
  return request(app)
    .post('/rest/2fa/verify')
    .set(jsonHeader)
    .send(body)
}

async function acceptSession (token: string, userId: number, email: string) {
  const statusRes = await request(app)
    .get('/rest/2fa/status')
    .set({
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    })
  assert.equal(statusRes.status, 200)
  assert.equal(statusRes.body.setup, true)
  const stored = security.authenticatedUsers.get(token)
  assert.equal(stored?.data?.id, userId)
  assert.equal(stored?.data?.email, email)
}

void describe('two-factor authenticator code replay', () => {
  void it('does not issue a second session when the same verify request is submitted again', async () => {
    await stabilizeTotpWindow()
    const epoch = Math.floor(Date.now() / 1000)
    const totpSecret = generateSecret()
    const codes = codesAt(totpSecret, epoch)
    assert.notEqual(codes.current, codes.future)
    assert.notEqual(codes.current, codes.past)

    const { email, password, userId } = await registerUser()
    await enableTwoFactor(email, password, totpSecret, codes.future)

    const body = {
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.current
    }
    const before = sessionsFor(userId).length
    const first = await postVerify(body)
    assert.equal(first.status, 200)
    assert.equal(typeof first.body?.authentication?.token, 'string')
    const firstToken = first.body.authentication.token as string
    await acceptSession(firstToken, userId, email)
    assert.equal(sessionsFor(userId).length, before + 1)

    await delay(1100)
    const replay = await postVerify(body)
    assert.equal(replay.status, 401)
    assert.equal(replay.body?.authentication, undefined)
    assert.equal(sessionsFor(userId).length, before + 1)
    await acceptSession(firstToken, userId, email)

    const freshBody = {
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.current
    }
    const reusedWithNewLogin = await postVerify(freshBody)
    assert.equal(reusedWithNewLogin.status, 401)
    assert.equal(reusedWithNewLogin.body?.authentication, undefined)
    assert.equal(sessionsFor(userId).length, before + 1)

    const otherStep = await postVerify({
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.past
    })
    assert.equal(otherStep.status, 200)
    assert.equal(typeof otherStep.body?.authentication?.token, 'string')
    await acceptSession(otherStep.body.authentication.token as string, userId, email)
    assert.equal(sessionsFor(userId).length, before + 2)

    const otherReplay = await postVerify({
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.past
    })
    assert.equal(otherReplay.status, 401)
    assert.equal(sessionsFor(userId).length, before + 2)
  }, { timeout: 60000 })

  void it('issues only one session when two verify requests overlap between the code check and the session', async (t) => {
    await stabilizeTotpWindow()
    const epoch = Math.floor(Date.now() / 1000)
    const totpSecret = generateSecret()
    const codes = codesAt(totpSecret, epoch)
    const { email, password, userId } = await registerUser()
    await enableTwoFactor(email, password, totpSecret, codes.future)
    const user = await UserModel.findByPk(userId)
    assert.ok(user)

    const body = {
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.current
    }
    // Hold the basket lookup open so both requests are inside the handler
    // after the authenticator check and before a session is stored.
    t.mock.method(UserModel, 'findByPk', async () => user)
    t.mock.method(BasketModel, 'findOrCreate', async () => {
      await delay(50)
      return [{ id: userId }, false]
    })

    const before = sessionsFor(userId).length
    const responses = await Promise.all([postVerify(body), postVerify(body)])
    const accepted = responses.filter((res) => res.status === 200)
    const rejected = responses.filter((res) => res.status === 401)
    assert.equal(accepted.length, 1)
    assert.equal(rejected.length, 1)
    assert.equal(sessionsFor(userId).length, before + 1)
    const token = accepted[0].body?.authentication?.token
    assert.equal(typeof token, 'string')
    await acceptSession(token as string, userId, email)
  }, { timeout: 60000 })

  void it('does not issue a session for the time step already used to enable two-factor authentication', async () => {
    await stabilizeTotpWindow()
    const epoch = Math.floor(Date.now() / 1000)
    const totpSecret = generateSecret()
    const codes = codesAt(totpSecret, epoch)
    const { email, password, userId } = await registerUser()
    const before = sessionsFor(userId).length
    await enableTwoFactor(email, password, totpSecret, codes.future)

    const replayedSetupCode = await postVerify({
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.future
    })
    assert.equal(replayedSetupCode.status, 401)
    assert.equal(replayedSetupCode.body?.authentication, undefined)
    assert.equal(sessionsFor(userId).length, before + 1)

    const currentStep = await postVerify({
      tmpToken: await beginTwoFactorLogin(email, password),
      totpToken: codes.current
    })
    assert.equal(currentStep.status, 200)
    await acceptSession(currentStep.body.authentication.token as string, userId, email)
  }, { timeout: 60000 })
})
