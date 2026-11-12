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
import * as security from '../../lib/insecurity'

let app: Express

const currentPassword = 'placeholder-current'
const nextPassword = 'placeholder-next'
const securityAnswer = 'placeholder-answer'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function stringField (node: unknown, name: string): string | undefined {
  if (node === null || typeof node !== 'object') return undefined
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = stringField(item, name)
      if (found !== undefined) return found
    }
    return undefined
  }
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (key === name && typeof value === 'string' && value.length > 0) return value
    const nested = stringField(value, name)
    if (nested !== undefined) return nested
  }
  return undefined
}

function exposureLabels (body: unknown, raw: string, totpSecret: string, passwordHash: string): string[] {
  const labels: string[] = []
  if (stringField(body, 'totpSecret') !== undefined) labels.push('totpSecret')
  if (stringField(body, 'password') !== undefined) labels.push('password')
  if (totpSecret.length > 0 && raw.includes(totpSecret)) labels.push('totp secret value')
  if (passwordHash.length > 0 && raw.includes(passwordHash)) labels.push('password hash value')
  return labels
}

async function registerWithSecondFactor (email: string) {
  const totpSecret = generateSecret()
  const created = await register(app, { email, password: currentPassword, totpSecret })
  const userId = created.body?.data?.id
  assert.equal(typeof userId, 'number')
  const { token } = await login(app, { email, password: currentPassword, totpSecret })
  assert.equal(typeof token, 'string')
  return { totpSecret, token, userId: userId as number }
}

async function assertSessionFromReturnedSecret (email: string, password: string, body: unknown) {
  const returnedSecret = stringField(body, 'totpSecret')
  if (returnedSecret !== undefined) {
    const session = await login(app, { email, password, totpSecret: returnedSecret })
    assert.equal(typeof session?.token, 'string')
  }
  const returnedPassword = stringField(body, 'password')
  if (returnedPassword !== undefined) {
    assert.ok(returnedPassword === security.hash(password), 'password field is not the hash of the password just set')
  }
}

void describe('user row serialization keeps password hash and totp secret private', () => {
  void it('GET /rest/user/change-password does not return them to the bearer token', async () => {
    const email = `change-password-secret-${Date.now()}@example.test`
    const { totpSecret, token } = await registerWithSecondFactor(email)

    const res = await request(app)
      .get('/rest/user/change-password')
      .query({ new: nextPassword, repeat: nextPassword })
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
    await assertSessionFromReturnedSecret(email, nextPassword, res.body)
    assert.deepEqual(exposureLabels(res.body, res.text, totpSecret, security.hash(nextPassword)), [])

    const session = await login(app, { email, password: nextPassword, totpSecret })
    assert.equal(typeof session?.token, 'string')
  })

  void it('GET /rest/user/change-password does not return them when the current password is supplied', async () => {
    const email = `change-password-current-${Date.now()}@example.test`
    const { totpSecret, token } = await registerWithSecondFactor(email)
    const replacement = 'placeholder-replacement'

    const res = await request(app)
      .get('/rest/user/change-password')
      .query({ current: currentPassword, new: replacement, repeat: replacement })
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
    await assertSessionFromReturnedSecret(email, replacement, res.body)
    assert.deepEqual(exposureLabels(res.body, res.text, totpSecret, security.hash(replacement)), [])
  })

  void it('POST /rest/user/reset-password does not return them after a security-answer reset', async () => {
    const email = `reset-password-secret-${Date.now()}@example.test`
    const { totpSecret, userId } = await registerWithSecondFactor(email)
    const replacement = 'placeholder-reset'

    const answer = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
      .send({
        UserId: userId,
        SecurityQuestionId: 1,
        answer: securityAnswer
      })
    assert.equal(answer.status, 201)

    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email,
        answer: securityAnswer,
        new: replacement,
        repeat: replacement
      })

    assert.equal(res.status, 200)
    await assertSessionFromReturnedSecret(email, replacement, res.body)
    assert.deepEqual(exposureLabels(res.body, res.text, totpSecret, security.hash(replacement)), [])

    const session = await login(app, { email, password: replacement, totpSecret })
    assert.equal(typeof session?.token, 'string')
  })

  void it('GET /rest/saveLoginIp does not return them for the signed-in user', async () => {
    const email = `save-login-ip-secret-${Date.now()}@example.test`
    const { totpSecret, token } = await registerWithSecondFactor(email)

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({ Authorization: 'Bearer ' + token, 'True-Client-IP': '203.0.113.50' })

    assert.equal(res.status, 200)
    const returnedSecret = stringField(res.body, 'totpSecret')
    if (returnedSecret !== undefined) {
      assert.ok(returnedSecret === totpSecret, 'returned totpSecret does not match the secret that signs in')
      const session = await login(app, { email, password: currentPassword, totpSecret: returnedSecret })
      assert.equal(typeof session?.token, 'string')
    }
    const returnedPassword = stringField(res.body, 'password')
    if (returnedPassword !== undefined) {
      assert.ok(returnedPassword === security.hash(currentPassword), 'password field is not the stored password hash')
    }
    assert.deepEqual(exposureLabels(res.body, res.text, totpSecret, security.hash(currentPassword)), [])
  })
})
