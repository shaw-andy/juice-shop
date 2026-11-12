/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { generateSecret } from 'otplib'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const jsonHeader = { 'content-type': 'application/json' }
const password = 'PLACEHOLDER_PASSWORD'
const replacementPassword = 'PLACEHOLDER_NEW_PASSWORD'
const securityAnswer = 'PLACEHOLDER_ANSWER'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function hasKey (value: unknown, key: string): boolean {
  if (Array.isArray(value)) {
    return value.some(item => hasKey(item, key))
  }
  if (typeof value === 'object' && value !== null) {
    for (const [name, nested] of Object.entries(value)) {
      if (name === key || hasKey(nested, key)) return true
    }
  }
  return false
}

function exposes (value: unknown, secret: string): boolean {
  const serialized = JSON.stringify(value)
  return serialized != null && serialized.includes(secret)
}

function assertResponseOmitsSecrets (body: unknown, totpSecret: string, hashes: string[]) {
  for (const hash of hashes) {
    assert.equal(exposes(body, hash), false, 'response exposes password hash')
  }
  assert.equal(exposes(body, totpSecret), false, 'response exposes totp secret')
  assert.equal(hasKey(body, 'password'), false, 'response includes password')
  assert.equal(hasKey(body, 'totpSecret'), false, 'response includes totpSecret')
}

void describe('signed-in user responses omit password hash and totp secret', () => {
  void it('GET /rest/saveLoginIp returns the updated address without the user secrets', async () => {
    const totpSecret = generateSecret()
    const email = 'save-login-ip@te.st'
    const otherEmail = 'save-login-ip-other@te.st'
    const loginIp = '203.0.113.10'
    const created = await register(app, { email, password, totpSecret })
    const other = await register(app, { email: otherEmail, password, totpSecret: generateSecret() })
    const { token } = await login(app, { email, password, totpSecret })
    const otherId = other.body.data.id

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .query({ id: otherId, UserId: otherId })
      .set({
        Authorization: 'Bearer ' + token,
        'true-client-ip': loginIp
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, loginIp)
    assertResponseOmitsSecrets(res.body, totpSecret, [security.hash(password)])

    const signedIn = await UserModel.findOne({ where: { email } })
    const neighbor = await UserModel.findByPk(otherId)
    assert.equal(signedIn?.id, created.body.data.id)
    assert.equal(signedIn?.lastLoginIp, loginIp)
    assert.equal(neighbor?.lastLoginIp, '0.0.0.0')
  })

  void it('GET /rest/saveLoginIp without a session does not write a login address', async () => {
    const totpSecret = generateSecret()
    const email = 'save-login-ip-anonymous@te.st'
    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })
    const keptIp = '203.0.113.20'

    const saved = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + token,
        'true-client-ip': keptIp
      })
    assert.equal(saved.status, 200)

    const anonymous = await request(app)
      .get('/rest/saveLoginIp')
      .set({ 'true-client-ip': '198.51.100.30' })

    assert.equal(anonymous.status, 401)
    const stored = await UserModel.findOne({ where: { email } })
    assert.equal(stored?.lastLoginIp, keptIp)
  })

  void it('GET /rest/user/change-password does not return the user secrets', async () => {
    const totpSecret = generateSecret()
    const email = 'change-password-secrets@te.st'
    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })

    const res = await request(app)
      .get('/rest/user/change-password')
      .query({
        current: password,
        new: replacementPassword,
        repeat: replacementPassword
      })
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
    assertResponseOmitsSecrets(res.body, totpSecret, [
      security.hash(password),
      security.hash(replacementPassword)
    ])

    const auth = await login(app, { email, password: replacementPassword, totpSecret })
    assert.equal(typeof auth.token, 'string')
  })

  void it('POST /rest/user/reset-password does not return the user secrets', async () => {
    const totpSecret = generateSecret()
    const email = 'reset-password-secrets@te.st'
    const created = await register(app, { email, password, totpSecret })

    const answer = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: 'Bearer ' + security.authorize(), ...jsonHeader })
      .send({
        UserId: created.body.data.id,
        SecurityQuestionId: 1,
        answer: securityAnswer
      })
    assert.equal(answer.status, 201)

    const res = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email,
        answer: securityAnswer,
        new: replacementPassword,
        repeat: replacementPassword
      })

    assert.equal(res.status, 200)
    assertResponseOmitsSecrets(res.body, totpSecret, [
      security.hash(password),
      security.hash(replacementPassword)
    ])

    const auth = await login(app, { email, password: replacementPassword, totpSecret })
    assert.equal(typeof auth.token, 'string')
  })
})
