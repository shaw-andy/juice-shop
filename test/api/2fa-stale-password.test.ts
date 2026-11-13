/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import type { Response } from 'supertest'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { SecurityQuestionModel } from '../../models/securityQuestion'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const previousPassword = 'placeholder-previous'
const replacementPassword = 'placeholder-replacement'
const latestPassword = 'placeholder-latest'
const securityAnswer = 'placeholder-answer'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function loginResult (email: string, password: string) {
  return await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
}

function assertTotpRequired (res: Response) {
  assert.equal(res.status, 401)
  assert.equal(res.body.status, 'totp_token_required')
}

function assertPasswordRejected (res: Response) {
  assert.equal(res.status, 401)
  assert.notEqual(res.body.status, 'totp_token_required')
  assert.equal(res.body.authentication, undefined)
}

function assertLoggedIn (res: Response) {
  assert.equal(res.status, 200)
  assert.equal(typeof res.body.authentication?.token, 'string')
}

async function userByEmail (email: string) {
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  return user
}

function sameSecret (actual: string, expected: string) {
  assert.equal(actual === expected, true)
}

async function changePassword (token: string, current: string, next: string, userId?: number) {
  const params = new URLSearchParams({
    current,
    new: next,
    repeat: next
  })
  if (userId !== undefined) {
    params.set('id', String(userId))
    params.set('userId', String(userId))
    params.set('UserId', String(userId))
  }
  return await request(app)
    .get('/rest/user/change-password?' + params.toString())
    .set({ Authorization: 'Bearer ' + token })
}

async function accountWithTotp (label: string) {
  const email = `${label}-${crypto.randomBytes(4).toString('hex')}@example.test`
  const totpSecret = generateSecret()
  await register(app, { email, password: previousPassword, totpSecret })
  const { token } = await login(app, { email, password: previousPassword, totpSecret })
  const user = await userByEmail(email)
  return { email, token, id: user.id, totpSecret }
}

async function accountWithoutTotp (label: string) {
  const email = `${label}-${crypto.randomBytes(4).toString('hex')}@example.test`
  await register(app, { email, password: previousPassword })
  const { token } = await login(app, { email, password: previousPassword })
  const user = await userByEmail(email)
  return { email, token, id: user.id }
}

function foreignIds (id: number) {
  return { id, userId: id, UserId: id }
}

void describe('stale session password', { concurrency: false }, () => {
  void it('does not disable two-factor authentication with the password from before it was changed', async () => {
    const account = await accountWithTotp('disable-previous')
    const other = await accountWithTotp('disable-previous-other')

    const changed = await changePassword(account.token, previousPassword, replacementPassword, other.id)
    assert.equal(changed.status, 200)
    assertTotpRequired(await loginResult(account.email, replacementPassword))
    assertPasswordRejected(await loginResult(account.email, previousPassword))

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set(bearer(account.token))
      .send({
        password: previousPassword,
        ...foreignIds(other.id)
      })

    assert.equal(disableRes.status, 401)
    sameSecret((await userByEmail(account.email)).totpSecret, account.totpSecret)
    sameSecret((await userByEmail(other.email)).totpSecret, other.totpSecret)
    assertTotpRequired(await loginResult(account.email, replacementPassword))
    assertPasswordRejected(await loginResult(account.email, previousPassword))
  })

  void it('disables two-factor authentication only for the authenticated account when the current password is sent', async () => {
    const account = await accountWithTotp('disable-current')
    const other = await accountWithTotp('disable-current-other')

    const changed = await changePassword(account.token, previousPassword, replacementPassword)
    assert.equal(changed.status, 200)

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set(bearer(account.token))
      .send({
        password: replacementPassword,
        ...foreignIds(other.id)
      })

    assert.equal(disableRes.status, 200)
    assert.equal((await userByEmail(account.email)).totpSecret, '')
    sameSecret((await userByEmail(other.email)).totpSecret, other.totpSecret)
    assertLoggedIn(await loginResult(account.email, replacementPassword))
    assertPasswordRejected(await loginResult(account.email, previousPassword))
  })

  void it('does not set up two-factor authentication with the password from before it was changed', async () => {
    const account = await accountWithoutTotp('setup-previous')
    const other = await accountWithTotp('setup-previous-other')
    const secret = generateSecret()

    const changed = await changePassword(account.token, previousPassword, replacementPassword, other.id)
    assert.equal(changed.status, 200)

    const setupRes = await request(app)
      .post('/rest/2fa/setup')
      .set(bearer(account.token))
      .send({
        password: previousPassword,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret }),
        ...foreignIds(other.id)
      })

    assert.equal(setupRes.status, 401)
    assert.equal((await userByEmail(account.email)).totpSecret, '')
    sameSecret((await userByEmail(other.email)).totpSecret, other.totpSecret)
    assertLoggedIn(await loginResult(account.email, replacementPassword))
  })

  void it('sets up two-factor authentication only for the authenticated account when the current password is sent', async () => {
    const account = await accountWithoutTotp('setup-current')
    const other = await accountWithTotp('setup-current-other')
    const secret = generateSecret()

    const changed = await changePassword(account.token, previousPassword, replacementPassword)
    assert.equal(changed.status, 200)

    const setupRes = await request(app)
      .post('/rest/2fa/setup')
      .set(bearer(account.token))
      .send({
        password: replacementPassword,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret }),
        ...foreignIds(other.id)
      })

    assert.equal(setupRes.status, 200)
    sameSecret((await userByEmail(account.email)).totpSecret, secret)
    sameSecret((await userByEmail(other.email)).totpSecret, other.totpSecret)
    assertTotpRequired(await loginResult(account.email, replacementPassword))
  })

  void it('does not disable two-factor authentication with the password from before a reset', async () => {
    const account = await accountWithTotp('reset-previous')
    const question = await SecurityQuestionModel.findOne()
    assert.ok(question)
    await SecurityAnswerModel.create({
      UserId: account.id,
      SecurityQuestionId: question.id,
      answer: securityAnswer
    })

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: account.email,
        answer: securityAnswer,
        new: replacementPassword,
        repeat: replacementPassword
      })

    assert.equal(resetRes.status, 200)
    assertTotpRequired(await loginResult(account.email, replacementPassword))

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set(bearer(account.token))
      .send({ password: previousPassword })

    assert.equal(disableRes.status, 401)
    sameSecret((await userByEmail(account.email)).totpSecret, account.totpSecret)
    assertTotpRequired(await loginResult(account.email, replacementPassword))
    assertPasswordRejected(await loginResult(account.email, previousPassword))
  })

  void it('does not accept the previous password for a later password change', async () => {
    const account = await accountWithoutTotp('change-previous')
    const other = await accountWithoutTotp('change-previous-other')

    const first = await changePassword(account.token, previousPassword, replacementPassword)
    assert.equal(first.status, 200)
    assertLoggedIn(await loginResult(account.email, replacementPassword))

    const second = await changePassword(account.token, previousPassword, latestPassword, other.id)
    assert.equal(second.status, 401)
    assertLoggedIn(await loginResult(account.email, replacementPassword))
    assertPasswordRejected(await loginResult(account.email, latestPassword))
    assertPasswordRejected(await loginResult(account.email, previousPassword))
    assertLoggedIn(await loginResult(other.email, previousPassword))
  })

  void it('accepts the current password for a later password change of the authenticated account only', async () => {
    const account = await accountWithoutTotp('change-current')
    const other = await accountWithoutTotp('change-current-other')

    const first = await changePassword(account.token, previousPassword, replacementPassword)
    assert.equal(first.status, 200)

    const second = await changePassword(account.token, replacementPassword, latestPassword, other.id)
    assert.equal(second.status, 200)
    assertLoggedIn(await loginResult(account.email, latestPassword))
    assertPasswordRejected(await loginResult(account.email, replacementPassword))
    assertLoggedIn(await loginResult(other.email, previousPassword))
  })
})
