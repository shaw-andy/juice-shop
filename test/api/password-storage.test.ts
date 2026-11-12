/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { generateSecret, generateSync } from 'otplib'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const replacementPassword = 'placeholder-password-next'
const resetPassword = 'placeholder-password-reset'
const placeholderAnswer = 'placeholder-answer'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function unsaltedMd5 (password: string) {
  return crypto.createHash('md5').update(password).digest('hex')
}

function assertSlowSaltedHash (stored: string) {
  assert.notEqual(stored, '')
  assert.equal(stored.includes(placeholderPassword), false)
  assert.equal(stored.includes(replacementPassword), false)
  assert.equal(stored.includes(resetPassword), false)
  const bcrypt = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/.exec(stored)
  if (bcrypt != null) {
    assert.ok(Number(bcrypt[1]) >= 10)
    return
  }
  assert.match(stored, /^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/)
}

function decodedTokenPayload (token: string) {
  const parts = token.split('.')
  assert.equal(parts.length, 3)
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  assert.equal(typeof payload, 'object')
  assert.notEqual(payload, null)
  return payload as Record<string, unknown>
}

function assertPayloadOmitsSecrets (payload: unknown, secrets: string[]) {
  const keys = new Set<string>()
  const walk = (value: unknown) => {
    if (Array.isArray(value)) {
      value.forEach(walk)
      return
    }
    if (value !== null && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        keys.add(key)
        walk(child)
      }
    }
  }
  walk(payload)
  assert.equal(keys.has('password'), false)
  assert.equal(keys.has('totpSecret'), false)
  const serialized = JSON.stringify(payload)
  for (const secret of secrets) {
    assert.equal(serialized.includes(secret), false)
  }
}

async function storedPassword (email: string) {
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  assert.equal(typeof user.password, 'string')
  return { id: user.id, password: user.password }
}

async function register (email: string, password: string) {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password, passwordRepeat: password })
  assert.equal(res.status, 201)
}

async function login (email: string, password: string) {
  return await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
}

function tokenFromSetCookie (res: Response) {
  const raw = res.headers['set-cookie']
  const cookies = Array.isArray(raw) ? raw : (raw != null ? [raw] : [])
  const tokenCookie = cookies.find((cookie) => cookie.startsWith('token='))
  assert.ok(tokenCookie)
  return decodeURIComponent(tokenCookie.slice('token='.length).split(';')[0])
}

void describe('password storage', () => {
  void it('registration stores a distinct slow salted hash and the login token omits it', async () => {
    const firstEmail = 'password-storage-a@example.test'
    const secondEmail = 'password-storage-b@example.test'
    await register(firstEmail, placeholderPassword)
    await register(secondEmail, placeholderPassword)

    const res = await login(firstEmail, placeholderPassword)
    assert.equal(res.status, 200)
    const token = res.body.authentication.token
    assert.equal(typeof token, 'string')
    const first = await storedPassword(firstEmail)
    const second = await storedPassword(secondEmail)
    assertPayloadOmitsSecrets(decodedTokenPayload(token), [first.password, unsaltedMd5(placeholderPassword)])
    assertSlowSaltedHash(first.password)
    assertSlowSaltedHash(second.password)
    assert.notEqual(first.password, second.password)
    assert.notEqual(first.password, unsaltedMd5(placeholderPassword))
    assert.notEqual(first.password, placeholderPassword)

    const presentedHash = await login(firstEmail, unsaltedMd5(placeholderPassword))
    assert.equal(presentedHash.status, 401)
  })

  void it('whoami does not return the password hash or totp secret from the login session', async () => {
    const email = 'password-storage-whoami@example.test'
    await register(email, placeholderPassword)
    const stored = await storedPassword(email)
    const res = await login(email, placeholderPassword)
    assert.equal(res.status, 200)
    const token = res.body.authentication.token

    const whoami = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'id,email,password,totpSecret' })
      .set('Cookie', `token=${token}`)
    assert.equal(whoami.status, 200)
    assert.equal(whoami.body.user.id, stored.id)
    assert.equal(whoami.body.user.password, undefined)
    assert.equal(whoami.body.user.totpSecret, undefined)
    assert.equal(JSON.stringify(whoami.body).includes(stored.password), false)
    assert.equal(JSON.stringify(whoami.body).includes(unsaltedMd5(placeholderPassword)), false)
  })

  void it('password change replaces the stored hash with a new slow salted hash', async () => {
    const email = 'password-storage-change@example.test'
    await register(email, placeholderPassword)
    const before = await storedPassword(email)
    const loginRes = await login(email, placeholderPassword)
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token

    const wrong = await request(app)
      .get('/rest/user/change-password')
      .query({ current: 'placeholder-password-wrong', new: replacementPassword, repeat: replacementPassword })
      .set('Authorization', 'Bearer ' + token)
    assert.equal(wrong.status, 401)

    const changed = await request(app)
      .get('/rest/user/change-password')
      .query({ current: placeholderPassword, new: replacementPassword, repeat: replacementPassword })
      .set('Authorization', 'Bearer ' + token)
    assert.equal(changed.status, 200)

    const after = await storedPassword(email)
    assert.equal(after.id, before.id)
    assertSlowSaltedHash(after.password)
    assert.notEqual(after.password, before.password)
    assert.notEqual(after.password, unsaltedMd5(replacementPassword))
    assert.notEqual(after.password, replacementPassword)
    assert.equal(JSON.stringify(changed.body).includes(unsaltedMd5(replacementPassword)), false)

    const oldLogin = await login(email, placeholderPassword)
    assert.equal(oldLogin.status, 401)
    const newLogin = await login(email, replacementPassword)
    assert.equal(newLogin.status, 200)
    assertPayloadOmitsSecrets(decodedTokenPayload(newLogin.body.authentication.token), [after.password])
  })

  void it('password reset stores a slow salted hash for the new password', async () => {
    const email = 'password-storage-reset@example.test'
    await register(email, placeholderPassword)
    const user = await storedPassword(email)

    const answer = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({
        UserId: user.id,
        SecurityQuestionId: 1,
        answer: placeholderAnswer
      })
    assert.equal(answer.status, 201)

    const reset = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email,
        answer: placeholderAnswer,
        new: resetPassword,
        repeat: resetPassword
      })
    assert.equal(reset.status, 200)

    const after = await storedPassword(email)
    assert.equal(after.id, user.id)
    assertSlowSaltedHash(after.password)
    assert.notEqual(after.password, unsaltedMd5(resetPassword))
    assert.notEqual(after.password, resetPassword)
    assert.equal(JSON.stringify(reset.body).includes(unsaltedMd5(resetPassword)), false)

    const loginRes = await login(email, resetPassword)
    assert.equal(loginRes.status, 200)
    assertPayloadOmitsSecrets(decodedTokenPayload(loginRes.body.authentication.token), [after.password])
  })

  void it('second-factor login token omits the password hash and the totp secret', async () => {
    const email = 'password-storage-totp@example.test'
    const totpSecret = generateSecret()
    await register(email, placeholderPassword)
    const created = await storedPassword(email)
    const loginRes = await login(email, placeholderPassword)
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token

    const setup = await request(app)
      .post('/rest/2fa/setup')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        password: placeholderPassword,
        setupToken: security.authorize({
          secret: totpSecret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret: totpSecret })
      })
    assert.equal(setup.status, 200)

    const passwordStep = await login(email, placeholderPassword)
    assert.equal(passwordStep.status, 401)
    assert.equal(passwordStep.body.status, 'totp_token_required')
    assertPayloadOmitsSecrets(decodedTokenPayload(passwordStep.body.data.tmpToken), [created.password, totpSecret])

    const verified = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: passwordStep.body.data.tmpToken,
        totpToken: generateSync({ secret: totpSecret })
      })
    assert.equal(verified.status, 200)
    const sessionToken = verified.body.authentication.token
    const stored = await storedPassword(email)
    assertPayloadOmitsSecrets(decodedTokenPayload(sessionToken), [stored.password, totpSecret, unsaltedMd5(placeholderPassword)])
    assertSlowSaltedHash(stored.password)

    const whoami = await request(app)
      .get('/rest/user/whoami')
      .query({ fields: 'password,totpSecret' })
      .set('Cookie', `token=${sessionToken}`)
    assert.equal(whoami.status, 200)
    assert.equal(JSON.stringify(whoami.body).includes(stored.password), false)
    assert.equal(JSON.stringify(whoami.body).includes(totpSecret), false)

    const disabled = await request(app)
      .post('/rest/2fa/disable')
      .set({ Authorization: 'Bearer ' + sessionToken, 'content-type': 'application/json' })
      .send({ password: placeholderPassword })
    assert.equal(disabled.status, 200)
  })

  void it('profile update token omits the password hash and totp secret', async () => {
    const email = 'password-storage-profile@example.test'
    await register(email, placeholderPassword)
    const loginRes = await login(email, placeholderPassword)
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token
    const stored = await storedPassword(email)

    const profile = await request(app)
      .post('/profile')
      .set('Cookie', `token=${token}`)
      .type('form')
      .send({ username: 'placeholder-user' })
      .redirects(0)
    assert.equal(profile.status, 302)
    const profileToken = tokenFromSetCookie(profile)
    assertPayloadOmitsSecrets(decodedTokenPayload(profileToken), [stored.password, unsaltedMd5(placeholderPassword)])
  })

  void it('deluxe upgrade token omits the password hash and totp secret', async () => {
    const email = 'password-storage-deluxe@example.test'
    await register(email, placeholderPassword)
    const loginRes = await login(email, placeholderPassword)
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token
    const stored = await storedPassword(email)

    const deluxe = await request(app)
      .post('/rest/deluxe-membership')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ paymentMode: 'invoice' })
    assert.equal(deluxe.status, 200)
    assert.equal(deluxe.body.status, 'success')
    assertPayloadOmitsSecrets(decodedTokenPayload(deluxe.body.data.token), [stored.password, unsaltedMd5(placeholderPassword)])
  })

  void it('product search does not return an unsalted MD5 of a registered password', async () => {
    const email = 'password-storage-search@example.test'
    await register(email, placeholderPassword)
    const stored = await storedPassword(email)

    const res = await request(app)
      .get("/rest/products/search?q=')) union select id,'2','3',email,password,'6','7','8','9' from Users--")
    assert.equal(res.status, 200)
    const body = JSON.stringify(res.body)
    assert.equal(body.includes(unsaltedMd5(placeholderPassword)), false)
    assertSlowSaltedHash(stored.password)
    assert.notEqual(stored.password, unsaltedMd5(placeholderPassword))
  })
})
