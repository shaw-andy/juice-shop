/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { generateSecret } from 'otplib'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'

const allowedFields = ['id', 'email', 'lastLoginIp', 'profileImage']

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function assertWhoAmIContract (res: Response, secrets: string[]) {
  assert.equal(res.status, 200)
  const contentType = String(res.headers['content-type'] ?? '')
  assert.equal(contentType.includes('application/json'), true)
  assert.equal(contentType.includes('javascript'), false)
  assert.equal(res.text.includes('typeof '), false)

  const user = res.body?.user
  assert.equal(typeof user, 'object')
  assert.notEqual(user, null)
  for (const key of Object.keys(user)) {
    assert.ok(allowedFields.includes(key), key)
  }
  for (const secret of secrets) {
    assert.equal(secret.length > 0, true)
    assert.equal(res.text.includes(secret), false)
  }
}

void describe('GET /rest/user/whoami field allow-list', () => {
  const email = 'whoami-allowlist@juice-sh.op'
  const password = 'placeholder-password'
  const totpEmail = 'whoami-allowlist-2fa@juice-sh.op'
  let passwordHash = ''
  let token = ''
  let totpSecret = ''
  let totpToken = ''

  before(async () => {
    passwordHash = security.hash(password)
    totpSecret = generateSecret()
    await register(app, { email, password })
    const authentication = await login(app, { email, password })
    token = authentication.token
    await register(app, { email: totpEmail, password, totpSecret })
    const totpAuthentication = await login(app, { email: totpEmail, password, totpSecret })
    totpToken = totpAuthentication.token
  }, { timeout: 30000 })

  void it('returns id and email when those fields are requested', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'id,email' })
      .set({ Cookie: `token=${token}` })

    assertWhoAmIContract(res, [passwordHash])
    assert.equal(typeof res.body.user.id, 'number')
    assert.equal(res.body.user.email, email)
  })

  void it('omits the password hash and totp secret requested from the login session', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'password,totpSecret' })
      .set({ Cookie: `token=${token}` })

    assertWhoAmIContract(res, [passwordHash])
  })

  void it('omits sensitive fields when the requested names are padded or mixed with profile fields', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: ' id , email , password , totpSecret , role , deluxeToken ' })
      .set({ Cookie: `token=${token}` })

    assertWhoAmIContract(res, [passwordHash])
    assert.equal(res.body.user.email, email)
  })

  void it('omits the login row when a model container property is requested', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'dataValues,_previousDataValues' })
      .set({ Cookie: `token=${token}` })

    assertWhoAmIContract(res, [passwordHash])
  })

  void it('keeps the response as JSON and omits the password hash when callback is set', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'password,totpSecret', callback: 'leak' })
      .set({ Cookie: `token=${token}` })

    assertWhoAmIContract(res, [passwordHash])
  })

  void it('ignores a callback when no fields are requested', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ callback: 'leak' })
      .set({ Cookie: `token=${token}` })

    assertWhoAmIContract(res, [passwordHash])
    assert.equal(res.body.user.email, email)
  })

  void it('omits the password hash and totp secret from a session opened by 2FA verification', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'password,totpSecret,dataValues,_previousDataValues' })
      .set({ Cookie: `token=${totpToken}` })

    assertWhoAmIContract(res, [passwordHash, totpSecret])
  })

  void it('does not disclose the login row for a token that is not the session cookie', async () => {
    const res = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'password,totpSecret', callback: 'leak' })
      .set({ Authorization: `Bearer ${token}` })

    assertWhoAmIContract(res, [passwordHash])
    assert.equal(res.body.user.email, undefined)
  })
})
