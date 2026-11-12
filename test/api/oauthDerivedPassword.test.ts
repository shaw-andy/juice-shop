/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

// Same derivation the Google sign-in client applies to the profile email.
function passwordDerivedFromEmail (email: string): string {
  return btoa(email.split('').reverse().join(''))
}

async function registerWithDerivedPassword (email: string) {
  const password = passwordDerivedFromEmail(email)
  return await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({ email, password, passwordRepeat: password })
}

async function expectDerivedPasswordRejected (email: string, extra: Record<string, unknown> = {}) {
  const res = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email, password: passwordDerivedFromEmail(email), ...extra })

  const bodyKeys = res.body !== null && typeof res.body === 'object' ? Object.keys(res.body).join(',') : typeof res.body
  assert.equal(res.status, 401, `email-derived password must not authenticate (body keys: ${bodyKeys})`)
  assert.notEqual(res.body?.status, 'totp_token_required')
  if (res.body !== null && typeof res.body === 'object') {
    assert.equal(Object.hasOwn(res.body, 'authentication'), false)
  }
}

void describe('Google sign-in password derived from the email', () => {
  void it('does not authenticate the seeded Google account from its email alone', async () => {
    await expectDerivedPasswordRejected('bjoern.kimminich@gmail.com')
  })

  void it('does not authenticate an account registered with the Google sign-in password body', async () => {
    const email = 'oauth.probe.8673@example.test'
    await registerWithDerivedPassword(email)
    await expectDerivedPasswordRejected(email)
  })

  void it('does not authenticate that account when the oauth flag is also set', async () => {
    const email = 'oauth.flag.8673@example.test'
    await registerWithDerivedPassword(email)
    await expectDerivedPasswordRejected(email, { oauth: true })
  })

  void it('does not authenticate a second distinct email registered the same way, including after a repeat registration', async () => {
    const email = 'oauth.second.8673@example.test'
    await registerWithDerivedPassword(email)
    await registerWithDerivedPassword(email)
    await expectDerivedPasswordRejected(email)
    await expectDerivedPasswordRejected(email, { oauth: true })
  })
})
