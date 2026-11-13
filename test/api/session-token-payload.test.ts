/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

const jsonHeader = { 'content-type': 'application/json' }
const PLACEHOLDER_PASSWORD = 'placeholder-password'
const allowedPayloadKeys = new Set(['id', 'role', 'bid', 'iat', 'exp'])

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function decodeBase64Url (encoded: string): string {
  const remainder = encoded.length % 4
  const padded = remainder === 0 ? encoded : encoded + '='.repeat(4 - remainder)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(base64, 'base64').toString('utf8')
}

function payloadFromToken (token: string): Record<string, unknown> {
  const parts = token.split('.')
  assert.equal(parts.length, 3)
  const payloadJson = decodeBase64Url(parts[1])
  const tampered = `${parts[0]}.${parts[1]}.not-the-signature`
  const tamperedJson = decodeBase64Url(tampered.split('.')[1])
  assert.equal(
    crypto.createHash('sha256').update(payloadJson).digest('hex'),
    crypto.createHash('sha256').update(tamperedJson).digest('hex')
  )
  return JSON.parse(payloadJson) as Record<string, unknown>
}

function payloadKeys (value: unknown, keys: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) payloadKeys(item, keys)
    return keys
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      keys.push(key)
      payloadKeys(child, keys)
    }
  }
  return keys
}

function assertSessionPayload (token: string, expected: {
  userId: number
  role: string
  bid: number
  passwordHash: string
  totpSecret?: string
}) {
  const payload = payloadFromToken(token)
  const serialized = JSON.stringify(payload)
  const problems: string[] = []
  if (serialized.includes(expected.passwordHash)) problems.push('password hash')
  if (serialized.includes(PLACEHOLDER_PASSWORD)) problems.push('password')
  if (expected.totpSecret !== undefined && expected.totpSecret !== '' && serialized.includes(expected.totpSecret)) {
    problems.push('authenticator secret')
  }
  const unexpected = payloadKeys(payload).filter(key => !allowedPayloadKeys.has(key))
  if (unexpected.length > 0) problems.push('fields ' + unexpected.join(', '))
  assert.equal(problems.length, 0, 'session token payload contains ' + problems.join('; '))
  assert.equal(payload.id, expected.userId)
  assert.equal(payload.role, expected.role)
  assert.equal(payload.bid, expected.bid)
}

function tokenFromSetCookie (res: Response): string {
  const raw = res.headers['set-cookie']
  const headers = Array.isArray(raw) ? raw : (raw !== undefined ? [raw] : [])
  let token: string | undefined
  for (const header of headers) {
    const match = /(?:^|;)\s*token=([^;]*)/.exec(header)
    if (match !== null) token = decodeURIComponent(match[1])
  }
  assert.equal(typeof token, 'string')
  return token as string
}

async function registerUser (email: string, role: string) {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email,
      password: PLACEHOLDER_PASSWORD,
      passwordRepeat: PLACEHOLDER_PASSWORD,
      role
    })
  assert.equal(res.status, 201)
  assert.equal(typeof res.body.data.id, 'number')
  assert.equal(res.body.data.role, role)
  return res.body.data.id as number
}

async function loginForToken (email: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password: PLACEHOLDER_PASSWORD })
  assert.equal(res.status, 200)
  assert.equal(typeof res.body.authentication.token, 'string')
  assert.equal(typeof res.body.authentication.bid, 'number')
  return res.body.authentication as { token: string, bid: number }
}

async function enableTwoFactor (email: string) {
  const { token } = await loginForToken(email)
  const statusRes = await request(app)
    .get('/rest/2fa/status')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
  assert.equal(statusRes.status, 200)
  assert.equal(statusRes.body.setup, false)
  assert.equal(typeof statusRes.body.secret, 'string')
  assert.equal(typeof statusRes.body.setupToken, 'string')

  const setupRes = await request(app)
    .post('/rest/2fa/setup')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({
      password: PLACEHOLDER_PASSWORD,
      setupToken: statusRes.body.setupToken,
      initialToken: generateSync({ secret: statusRes.body.secret })
    })
  assert.equal(setupRes.status, 200)
  return statusRes.body.secret as string
}

async function finishTwoFactorLogin (email: string, totpSecret: string) {
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password: PLACEHOLDER_PASSWORD })
  assert.equal(loginRes.status, 401)
  assert.equal(loginRes.body.status, 'totp_token_required')
  assert.equal(typeof loginRes.body.data.tmpToken, 'string')

  const interim = payloadFromToken(loginRes.body.data.tmpToken)
  const interimJson = JSON.stringify(interim)
  const passwordHash = security.hash(PLACEHOLDER_PASSWORD)
  assert.equal(interimJson.includes(passwordHash), false)
  assert.equal(interimJson.includes(totpSecret), false)

  const verifyRes = await request(app)
    .post('/rest/2fa/verify')
    .set(jsonHeader)
    .send({
      tmpToken: loginRes.body.data.tmpToken,
      totpToken: generateSync({ secret: totpSecret })
    })
  assert.equal(verifyRes.status, 200)
  assert.equal(typeof verifyRes.body.authentication.token, 'string')
  assert.equal(typeof verifyRes.body.authentication.bid, 'number')
  return verifyRes.body.authentication as { token: string, bid: number }
}

async function assertWhoami (token: string, userId: number) {
  const res = await request(app)
    .get('/rest/user/whoami')
    .set('Cookie', `token=${token}`)
  assert.equal(res.status, 200)
  assert.equal(res.body.user.id, userId)
}

void describe('session token payload', () => {
  void it('POST /rest/2fa/verify keeps the authenticator secret and password hash out of a customer session token', async () => {
    const email = 'customer-2fa@example.test'
    const userId = await registerUser(email, 'customer')
    const totpSecret = await enableTwoFactor(email)
    const authentication = await finishTwoFactorLogin(email, totpSecret)
    await assertWhoami(authentication.token, userId)
    assertSessionPayload(authentication.token, {
      userId,
      role: 'customer',
      bid: authentication.bid,
      passwordHash: security.hash(PLACEHOLDER_PASSWORD),
      totpSecret
    })
  })

  void it('POST /rest/2fa/verify keeps the authenticator secret and password hash out of an administrator session token', async () => {
    const email = 'admin-2fa@example.test'
    const userId = await registerUser(email, 'admin')
    const totpSecret = await enableTwoFactor(email)
    const authentication = await finishTwoFactorLogin(email, totpSecret)
    await assertWhoami(authentication.token, userId)
    assertSessionPayload(authentication.token, {
      userId,
      role: 'admin',
      bid: authentication.bid,
      passwordHash: security.hash(PLACEHOLDER_PASSWORD),
      totpSecret
    })
  })

  void it('POST /rest/user/login keeps the password hash out of a session token when the account has no second factor', async () => {
    const email = 'customer-password@example.test'
    const userId = await registerUser(email, 'customer')
    const authentication = await loginForToken(email)
    await assertWhoami(authentication.token, userId)
    assertSessionPayload(authentication.token, {
      userId,
      role: 'customer',
      bid: authentication.bid,
      passwordHash: security.hash(PLACEHOLDER_PASSWORD)
    })
  })

  void it('POST /profile keeps the authenticator secret and password hash out of the reissued session cookie', async () => {
    const email = 'customer-profile@example.test'
    const userId = await registerUser(email, 'customer')
    const totpSecret = await enableTwoFactor(email)
    const authentication = await finishTwoFactorLogin(email, totpSecret)
    const res = await request(app)
      .post('/profile')
      .set('Cookie', `token=${authentication.token}`)
      .type('form')
      .send({ username: 'updated-name' })
      .redirects(0)
    assert.equal(res.status, 302)
    const reissued = tokenFromSetCookie(res)
    await assertWhoami(reissued, userId)
    assertSessionPayload(reissued, {
      userId,
      role: 'customer',
      bid: authentication.bid,
      passwordHash: security.hash(PLACEHOLDER_PASSWORD),
      totpSecret
    })
  })

  void it('POST /rest/deluxe-membership keeps the authenticator secret and password hash out of the reissued session token', async () => {
    const email = 'customer-deluxe@example.test'
    const userId = await registerUser(email, 'customer')
    const totpSecret = await enableTwoFactor(email)
    const authentication = await finishTwoFactorLogin(email, totpSecret)
    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set({ Authorization: 'Bearer ' + authentication.token, 'content-type': 'application/json' })
      .send({ paymentMode: null, UserId: 1 })
    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.equal(typeof res.body.data.token, 'string')
    await assertWhoami(res.body.data.token, userId)
    assertSessionPayload(res.body.data.token, {
      userId,
      role: 'deluxe',
      bid: authentication.bid,
      passwordHash: security.hash(PLACEHOLDER_PASSWORD),
      totpSecret
    })
  })
})
