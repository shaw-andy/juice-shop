/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const password = 'placeholder-password'
const jsonHeader = { 'content-type': 'application/json' }

let app: Express

function bearer (token: string) {
  return {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function openSessions () {
  const email = `session-invalidation-${crypto.randomBytes(8).toString('hex')}@example.test`
  await register(app, { email, password })
  const earlier = await login(app, { email, password })
  const userId = security.authenticatedUsers.get(earlier.token)?.data?.id
  await UserModel.update({ lastLoginIp: '203.0.113.10' }, { where: { email } })
  const owner = await login(app, { email, password })
  assert.notEqual(earlier.token, owner.token)
  assert.equal(typeof userId, 'number')
  assert.equal(typeof owner.bid, 'number')
  const secret = await turnOnSecondFactor(owner.token)
  return {
    email,
    userId: userId as number,
    basketId: owner.bid as number,
    earlierToken: earlier.token as string,
    secret
  }
}

async function turnOnSecondFactor (token: string) {
  const statusRes = await request(app)
    .get('/rest/2fa/status')
    .set(bearer(token))

  assert.equal(statusRes.status, 200)
  assert.equal(statusRes.body.setup, false)
  assert.equal(typeof statusRes.body.secret, 'string')
  assert.equal(typeof statusRes.body.setupToken, 'string')

  const setupRes = await request(app)
    .post('/rest/2fa/setup')
    .set(bearer(token))
    .send({
      password,
      setupToken: statusRes.body.setupToken,
      initialToken: generateSync({ secret: statusRes.body.secret })
    })

  assert.equal(setupRes.status, 200)
  return statusRes.body.secret as string
}

async function expectSecondFactorStillRequired (email: string, secret: string) {
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })

  assert.equal(loginRes.status, 401)
  assert.equal(loginRes.body.status, 'totp_token_required')

  const verifyRes = await request(app)
    .post('/rest/2fa/verify')
    .set(jsonHeader)
    .send({
      tmpToken: loginRes.body.data.tmpToken,
      totpToken: generateSync({ secret })
    })

  assert.equal(verifyRes.status, 200)
  assert.equal(typeof verifyRes.body.authentication.token, 'string')
}

void describe('sessions issued before two-factor setup', () => {
  void it('drops every earlier session token when two-factor authentication is turned on', async () => {
    const { earlierToken } = await openSessions()

    assert.equal(security.authenticatedUsers.get(earlierToken) !== undefined, false)
  })

  void it('rejects an earlier bearer token on signature-gated APIs', async () => {
    const { earlierToken, userId, basketId } = await openSessions()
    const paths = [
      '/api/Users',
      '/api/Complaints',
      '/rest/user/authentication-details',
      `/api/Users/${userId}`,
      `/rest/basket/${basketId}`
    ]

    const failures: string[] = []
    for (const path of paths) {
      const res = await request(app).get(path).set(bearer(earlierToken))
      if (res.status !== 401) failures.push(path + ' ' + String(res.status))
    }
    assert.deepEqual(failures, [])
  })

  void it('rejects an earlier bearer token on session-map APIs', async () => {
    const { earlierToken } = await openSessions()
    const paths = [
      '/rest/2fa/status',
      '/rest/wallet/balance',
      '/api/Cards',
      '/api/Addresss'
    ]

    const failures: string[] = []
    for (const path of paths) {
      const res = await request(app).get(path).set(bearer(earlierToken))
      if (res.status !== 401) failures.push(path + ' ' + String(res.status))
    }
    const orders = await request(app)
      .get('/rest/order-history')
      .set(bearer(earlierToken))
    if (orders.status === 200 || orders.body?.status === 'success') {
      failures.push('/rest/order-history ' + String(orders.status))
    }
    assert.deepEqual(failures, [])
  })

  void it('rejects an earlier token presented as a cookie', async () => {
    const { email, earlierToken } = await openSessions()

    const res = await request(app)
      .get('/rest/user/whoami')
      .set('Cookie', `token=${earlierToken}`)

    assert.notEqual(res.body?.user?.email, email)
    assert.equal(security.authenticatedUsers.get(earlierToken) !== undefined, false)
  })

  void it('does not let an earlier bearer token and the password disable two-factor authentication', async () => {
    const { email, earlierToken, secret } = await openSessions()

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set(bearer(earlierToken))
      .send({ password })
    const row = await UserModel.findOne({ where: { email } })

    assert.deepEqual({
      status: disableRes.status,
      secretCleared: row?.totpSecret === ''
    }, {
      status: 401,
      secretCleared: false
    })
    await expectSecondFactorStillRequired(email, secret)
  })

  void it('does not let an earlier bearer token and the password replace the authenticator secret', async () => {
    const { email, earlierToken, secret } = await openSessions()
    const replacement = generateSecret()

    const setupRes = await request(app)
      .post('/rest/2fa/setup')
      .set(bearer(earlierToken))
      .send({
        password,
        setupToken: security.authorize({
          secret: replacement,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret: replacement })
      })

    const row = await UserModel.findOne({ where: { email } })
    assert.deepEqual({
      status: setupRes.status,
      secretReplaced: row?.totpSecret !== secret
    }, {
      status: 401,
      secretReplaced: false
    })
    await expectSecondFactorStillRequired(email, secret)
  })

  void it('does not let an earlier bearer token change the password or the saved login IP', async () => {
    const { email, earlierToken, secret } = await openSessions()
    const before = await UserModel.findOne({ where: { email } })
    assert.ok(before)

    const passwordRes = await request(app)
      .get('/rest/user/change-password')
      .query({
        current: password,
        new: 'placeholder-new-password',
        repeat: 'placeholder-new-password'
      })
      .set(bearer(earlierToken))

    const ipRes = await request(app)
      .get('/rest/saveLoginIp')
      .set(bearer(earlierToken))
      .set('True-Client-IP', '203.0.113.50')

    const after = await UserModel.findOne({ where: { email } })
    assert.deepEqual({
      passwordStatus: passwordRes.status,
      ipStatus: ipRes.status,
      passwordUnchanged: after?.password === before.password,
      ipUnchanged: after?.lastLoginIp === before.lastLoginIp
    }, {
      passwordStatus: 401,
      ipStatus: 401,
      passwordUnchanged: true,
      ipUnchanged: true
    })
    await expectSecondFactorStillRequired(email, secret)
  })

  void it('does not put a dropped earlier bearer token back into the session map', async () => {
    const { earlierToken } = await openSessions()
    delete security.authenticatedUsers.tokenMap[earlierToken]
    assert.equal(security.authenticatedUsers.get(earlierToken), undefined)

    const statusRes = await request(app)
      .get('/rest/2fa/status')
      .set(bearer(earlierToken))
    const usersRes = await request(app)
      .get('/api/Users')
      .set(bearer(earlierToken))

    assert.equal(statusRes.status, 401)
    assert.equal(usersRes.status, 401)
    assert.equal(security.authenticatedUsers.get(earlierToken) !== undefined, false)
  })

  void it('does not put a dropped earlier cookie token back into the session map', async () => {
    const { email, earlierToken } = await openSessions()
    delete security.authenticatedUsers.tokenMap[earlierToken]

    const res = await request(app)
      .get('/rest/user/whoami')
      .set('Cookie', `token=${earlierToken}`)

    assert.notEqual(res.body?.user?.email, email)
    assert.equal(security.authenticatedUsers.get(earlierToken) !== undefined, false)
  })
})
