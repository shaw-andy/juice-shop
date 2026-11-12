/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { generateSecret, generateSync } from 'otplib'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const currentPassword = 'placeholder-current'
const replacementPassword = 'placeholder-reset'
const securityAnswer = 'placeholder-answer'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function collectKeys (value: unknown, found: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, found)
    return found
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      found.push(key)
      collectKeys(child, found)
    }
  }
  return found
}

function collectStrings (value: unknown, found: string[] = []): string[] {
  if (typeof value === 'string') {
    found.push(value)
    return found
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, found)
    return found
  }
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value as Record<string, unknown>)) {
      collectStrings(child, found)
    }
  }
  return found
}

function assertSecretFieldsAbsent (body: unknown) {
  const keys = collectKeys(body)
  assert.equal(keys.includes('totpSecret'), false, 'response includes the second-factor field')
  assert.equal(keys.includes('password'), false, 'response includes the password field')
}

function assertTextOmits (body: unknown, secret: string, message: string) {
  assert.equal(JSON.stringify(body).includes(secret), false, message)
}

async function enroll (email: string, role?: string) {
  const totpSecret = generateSecret()
  const created = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password: currentPassword, role })
  assert.equal(created.status, 201)
  const userId = created.body.data.id as number

  const answer = await request(app)
    .post('/api/SecurityAnswers')
    .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
    .send({ UserId: userId, SecurityQuestionId: 1, answer: securityAnswer })
  assert.equal(answer.status, 201)

  const { token } = await login(app, { email, password: currentPassword })
  const setup = await request(app)
    .post('/rest/2fa/setup')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({
      password: currentPassword,
      setupToken: security.authorize({ secret: totpSecret, type: 'totp_setup_secret' }),
      initialToken: generateSync({ secret: totpSecret })
    })
  assert.equal(setup.status, 200)
  return { totpSecret, userId }
}

async function resetPassword (email: string) {
  return await request(app)
    .post('/rest/user/reset-password')
    .set(jsonHeader)
    .send({
      email,
      answer: securityAnswer,
      new: replacementPassword,
      repeat: replacementPassword
    })
}

async function expectSecondFactorChallenge (email: string, password: string) {
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  assert.equal(loginRes.status, 401)
  assert.equal(loginRes.body?.status, 'totp_token_required')
  assert.equal(loginRes.body?.authentication, undefined)
  assert.equal(typeof loginRes.body?.data?.tmpToken, 'string')
  return loginRes.body.data.tmpToken as string
}

async function verifyFactor (tmpToken: string, secret: string) {
  return await request(app)
    .post('/rest/2fa/verify')
    .set(jsonHeader)
    .send({ tmpToken, totpToken: generateSync({ secret }) })
}

async function responseMaterialVerifies (tmpToken: string, body: unknown) {
  for (const candidate of collectStrings(body)) {
    let code: string
    try {
      code = generateSync({ secret: candidate })
    } catch {
      continue
    }
    const verified = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({ tmpToken, totpToken: code })
    if (verified.status === 200 && verified.body?.authentication?.token) return true
  }
  return false
}

function decodedPayload (token: string): unknown {
  const decoded = security.decode(token)
  return typeof decoded === 'string' ? JSON.parse(decoded) : decoded
}

void describe('password reset must not defeat two-factor login', () => {
  void it('does not return the second factor or the password hash for an administrator', async () => {
    const email = 'placeholder-admin-reset@example.test'
    const { totpSecret } = await enroll(email, 'admin')
    const reset = await resetPassword(email)

    assert.equal(reset.status, 200)
    assertSecretFieldsAbsent(reset.body)
    assertTextOmits(reset.body, totpSecret, 'reset response includes the enrolled second factor')
    assertTextOmits(reset.body, security.hash(replacementPassword), 'reset response includes the new password hash')
  })

  void it('keeps the second-factor challenge and rejects the factor enrolled before the reset', async () => {
    const email = 'placeholder-admin-rotate@example.test'
    const { totpSecret } = await enroll(email, 'admin')
    const reset = await resetPassword(email)
    assert.equal(reset.status, 200)

    const tmpToken = await expectSecondFactorChallenge(email, replacementPassword)
    const previous = await verifyFactor(tmpToken, totpSecret)
    assert.equal(previous.status, 401)
    assert.equal(previous.body?.authentication, undefined)
  })

  void it('rejects a second factor derived from any value in the reset response', async () => {
    const email = 'placeholder-admin-response@example.test'
    await enroll(email, 'admin')
    const reset = await resetPassword(email)
    assert.equal(reset.status, 200)

    const tmpToken = await expectSecondFactorChallenge(email, replacementPassword)
    assert.equal(await responseMaterialVerifies(tmpToken, reset.body), false)
  })

  void it('does not change another account when the security answer matches one account', async () => {
    const victim = 'placeholder-admin-victim@example.test'
    const bystander = 'placeholder-bystander@example.test'
    await enroll(victim, 'admin')
    const bystanderFactor = await enroll(bystander)

    const reset = await resetPassword(victim)
    assert.equal(reset.status, 200)

    const bystanderLogin = await login(app, {
      email: bystander,
      password: currentPassword,
      totpSecret: bystanderFactor.totpSecret
    })
    assert.equal(typeof bystanderLogin.token, 'string')
    assert.equal(await expectSecondFactorChallenge(victim, replacementPassword).then(() => true), true)
  })

  void it('does not return the user when the security answer does not match', async () => {
    const email = 'placeholder-wrong-answer@example.test'
    const { totpSecret } = await enroll(email, 'admin')
    const reset = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email,
        answer: 'placeholder-wrong-answer',
        new: replacementPassword,
        repeat: replacementPassword
      })

    assert.equal(reset.status, 401)
    assertSecretFieldsAbsent(reset.body)
    assertTextOmits(reset.body, totpSecret, 'rejected reset includes the enrolled second factor')
    const tmpToken = await expectSecondFactorChallenge(email, currentPassword)
    const stillEnrolled = await verifyFactor(tmpToken, totpSecret)
    assert.equal(stillEnrolled.status, 200)
    assert.equal(typeof stillEnrolled.body?.authentication?.token, 'string')
  })
})

void describe('other user serializations must omit the second factor and password hash', () => {
  void it('password change does not return them or a usable second factor', async () => {
    const email = 'placeholder-change@example.test'
    const { totpSecret } = await enroll(email)
    const { token } = await login(app, { email, password: currentPassword, totpSecret })
    const changed = await request(app)
      .get('/rest/user/change-password')
      .query({ current: currentPassword, new: replacementPassword, repeat: replacementPassword })
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(changed.status, 200)
    assertSecretFieldsAbsent(changed.body)
    assertTextOmits(changed.body, totpSecret, 'password change response includes the enrolled second factor')
    assertTextOmits(changed.body, security.hash(replacementPassword), 'password change response includes the new password hash')

    const tmpToken = await expectSecondFactorChallenge(email, replacementPassword)
    assert.equal(await responseMaterialVerifies(tmpToken, changed.body), false)
  })

  void it('login IP update does not return them', async () => {
    const email = 'placeholder-login-ip@example.test'
    const { totpSecret } = await enroll(email)
    const { token } = await login(app, { email, password: currentPassword, totpSecret })
    const saved = await request(app)
      .get('/rest/saveLoginIp')
      .set({ Authorization: 'Bearer ' + token, 'true-client-ip': '203.0.113.10' })

    assert.equal(saved.status, 200)
    assert.equal(saved.body?.lastLoginIp, '203.0.113.10')
    assertSecretFieldsAbsent(saved.body)
    assertTextOmits(saved.body, totpSecret, 'login IP response includes the enrolled second factor')
    assertTextOmits(saved.body, security.hash(currentPassword), 'login IP response includes the password hash')
  })

  void it('public memories do not include them', async () => {
    const email = 'placeholder-memory@example.test'
    const { totpSecret } = await enroll(email)
    const memories = await request(app).get('/rest/memories')

    assert.equal(memories.status, 200)
    assertSecretFieldsAbsent(memories.body)
    assertTextOmits(memories.body, totpSecret, 'memories include the enrolled second factor')
    assertTextOmits(memories.body, security.hash(currentPassword), 'memories include the password hash')
  })

  void it('the session token from the second factor does not carry them', async () => {
    const email = 'placeholder-session@example.test'
    const { totpSecret } = await enroll(email)
    const { token } = await login(app, { email, password: currentPassword, totpSecret })
    const payload = decodedPayload(token)

    assertSecretFieldsAbsent(payload)
    assertTextOmits(payload, totpSecret, 'session token includes the enrolled second factor')
    assertTextOmits(payload, security.hash(currentPassword), 'session token includes the password hash')
  })

  void it('the session token from login does not carry the password hash', async () => {
    const email = 'placeholder-login-token@example.test'
    const created = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: currentPassword })
    assert.equal(created.status, 201)

    const { token } = await login(app, { email, password: currentPassword })
    const payload = decodedPayload(token)
    assertSecretFieldsAbsent(payload)
    assertTextOmits(payload, security.hash(currentPassword), 'login token includes the password hash')
  })
})
