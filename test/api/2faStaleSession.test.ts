/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const password = 'placeholder-password'
const rotatedPassword = 'placeholder-password-rotated'

let app: Express

function authHeader (token: string) {
  return {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
}

function getStatus (token: string) {
  return request(app)
    .get('/rest/2fa/status')
    .set(authHeader(token))
}

function postSetup (token: string, body: { password: string, setupToken: string, initialToken: string }) {
  return request(app)
    .post('/rest/2fa/setup')
    .set(authHeader(token))
    .send(body)
}

function postDisable (token: string, currentPassword: string) {
  return request(app)
    .post('/rest/2fa/disable')
    .set(authHeader(token))
    .send({ password: currentPassword })
}

async function loginWithoutSecondFactor (email: string, currentPassword: string) {
  return await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password: currentPassword })
}

async function openSessions (email: string) {
  await register(app, { email, password })
  const first = await loginWithoutSecondFactor(email, password)
  assert.equal(first.status, 200)
  assert.equal(typeof first.body.authentication?.token, 'string')
  let secondToken = ''
  for (let attempt = 0; attempt < 3 && secondToken === ''; attempt++) {
    await new Promise((resolve) => {
      setTimeout(resolve, 1100)
    })
    const second = await loginWithoutSecondFactor(email, password)
    assert.equal(second.status, 200)
    assert.equal(typeof second.body.authentication?.token, 'string')
    if (second.body.authentication.token !== first.body.authentication.token) {
      secondToken = second.body.authentication.token as string
    }
  }
  assert.equal(secondToken === '', false)
  return {
    firstToken: first.body.authentication.token as string,
    secondToken
  }
}

async function savedSecret (email: string) {
  const row = await UserModel.findOne({ where: { email } })
  assert.ok(row)
  return row.totpSecret
}

async function enroll (token: string, currentPassword: string) {
  const status = await getStatus(token)
  assert.equal(status.status, 200)
  assert.equal(status.body.setup, false)
  assert.equal(typeof status.body.secret, 'string')
  assert.equal(typeof status.body.setupToken, 'string')
  const secret = status.body.secret as string
  const setup = await postSetup(token, {
    password: currentPassword,
    setupToken: status.body.setupToken as string,
    initialToken: generateSync({ secret })
  })
  assert.equal(setup.status, 200)
  return secret
}

function assertNoSetupMaterial (body: { secret?: unknown, setupToken?: unknown }) {
  assert.equal(typeof body.secret, 'undefined')
  assert.equal(typeof body.setupToken, 'undefined')
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('pre-enrollment session cannot replace a saved authenticator', { concurrency: 1 }, () => {
  void it('status on an earlier session stops offering setup after another session enrolls', async () => {
    const email = 'stale-status-earlier@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    const enrolledSecret = await enroll(secondToken, password)

    const status = await getStatus(firstToken)

    assert.ok(status.status === 401 || (status.status === 200 && status.body.setup === true))
    assertNoSetupMaterial(status.body)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
  })

  void it('status on a later session stops offering setup after an earlier session enrolls', async () => {
    const email = 'stale-status-later@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    await enroll(firstToken, password)

    const status = await getStatus(secondToken)

    assert.ok(status.status === 401 || (status.status === 200 && status.body.setup === true))
    assertNoSetupMaterial(status.body)
  })

  void it('setup with a token issued before enrollment does not replace the saved secret', async () => {
    const email = 'stale-setup-before@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    const before = await getStatus(firstToken)
    assert.equal(before.status, 200)
    assert.equal(before.body.setup, false)
    const attackerSecret = before.body.secret as string
    const attackerSetupToken = before.body.setupToken as string
    const enrolledSecret = await enroll(secondToken, password)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
    assert.equal(attackerSecret === enrolledSecret, false)

    const replace = await postSetup(firstToken, {
      password,
      setupToken: attackerSetupToken,
      initialToken: generateSync({ secret: attackerSecret })
    })

    assert.equal(replace.status, 401)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
    assert.equal(await savedSecret(email) === attackerSecret, false)

    const victimLogin = await loginWithoutSecondFactor(email, password)
    assert.equal(victimLogin.status, 401)
    assert.equal(victimLogin.body.status, 'totp_token_required')
    const victimCode = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: victimLogin.body.data.tmpToken,
        totpToken: generateSync({ secret: enrolledSecret })
      })
    assert.equal(victimCode.status, 200)
    assert.equal(typeof victimCode.body.authentication?.token, 'string')

    const attackerLogin = await loginWithoutSecondFactor(email, password)
    assert.equal(attackerLogin.body.status, 'totp_token_required')
    const attackerCode = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: attackerLogin.body.data.tmpToken,
        totpToken: generateSync({ secret: attackerSecret })
      })
    assert.equal(attackerCode.status, 401)
  })

  void it('setup from the later session does not replace a secret saved by the earlier session', async () => {
    const email = 'stale-setup-later@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    const before = await getStatus(secondToken)
    assert.equal(before.status, 200)
    assert.equal(before.body.setup, false)
    const attackerSecret = before.body.secret as string
    const attackerSetupToken = before.body.setupToken as string
    const enrolledSecret = await enroll(firstToken, password)

    const replace = await postSetup(secondToken, {
      password,
      setupToken: attackerSetupToken,
      initialToken: generateSync({ secret: attackerSecret })
    })

    assert.equal(replace.status, 401)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
    assert.equal(await savedSecret(email) === attackerSecret, false)
  })

  void it('setup still rejects a pre-enrollment token when status is consulted again after enrollment', async () => {
    const email = 'stale-setup-after-status@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    const before = await getStatus(firstToken)
    const attackerSecret = before.body.secret as string
    const attackerSetupToken = before.body.setupToken as string
    const enrolledSecret = await enroll(secondToken, password)

    const again = await getStatus(firstToken)
    const secretForAttempt = typeof again.body.secret === 'string' ? again.body.secret : attackerSecret
    const tokenForAttempt = typeof again.body.setupToken === 'string' ? again.body.setupToken : attackerSetupToken

    const replace = await postSetup(firstToken, {
      password,
      setupToken: tokenForAttempt,
      initialToken: generateSync({ secret: secretForAttempt })
    })

    assert.equal(replace.status, 401)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
    assert.equal(await savedSecret(email) === secretForAttempt, false)
    assertNoSetupMaterial(again.body)
  })

  void it('restoring a pre-enrollment token into the session map does not allow replacement', async () => {
    const email = 'stale-restored-session@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    const before = await getStatus(firstToken)
    assert.equal(before.status, 200)
    assert.equal(before.body.setup, false)
    const attackerSecret = before.body.secret as string
    const attackerSetupToken = before.body.setupToken as string
    const enrolledSecret = await enroll(secondToken, password)
    delete security.authenticatedUsers.tokenMap[firstToken]

    const replace = await postSetup(firstToken, {
      password,
      setupToken: attackerSetupToken,
      initialToken: generateSync({ secret: attackerSecret })
    })

    assert.equal(replace.status, 401)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
    assert.equal(await savedSecret(email) === attackerSecret, false)
  })

  void it('disable from a pre-enrollment session does not clear a saved authenticator', async () => {
    const email = 'stale-disable@example.test'
    const { firstToken, secondToken } = await openSessions(email)
    const enrolledSecret = await enroll(secondToken, password)

    const disable = await postDisable(firstToken, password)

    assert.equal(disable.status, 401)
    assert.equal(await savedSecret(email) === enrolledSecret, true)
    assert.equal((await savedSecret(email)).length > 0, true)

    const stillEnrolled = await getStatus(secondToken)
    assert.equal(stillEnrolled.status, 200)
    assert.equal(stillEnrolled.body.setup, true)
  })

  void it('setup compares the password with the hash on the user row', async () => {
    const email = 'stale-password@example.test'
    const { firstToken } = await openSessions(email)
    const row = await UserModel.findOne({ where: { email } })
    assert.ok(row)
    const sessionHash = security.authenticatedUsers.get(firstToken)?.data?.password
    await row.update({ password: rotatedPassword })
    await row.reload()
    assert.equal(row.password === sessionHash, false)

    const status = await getStatus(firstToken)
    assert.equal(status.status, 200)
    assert.equal(status.body.setup, false)
    const secret = status.body.secret as string

    const usingSessionPassword = await postSetup(firstToken, {
      password,
      setupToken: status.body.setupToken as string,
      initialToken: generateSync({ secret })
    })

    assert.equal(usingSessionPassword.status, 401)
    assert.equal(await savedSecret(email), '')

    const freshStatus = await getStatus(firstToken)
    assert.equal(freshStatus.status, 200)
    assert.equal(freshStatus.body.setup, false)
    const accepted = await postSetup(firstToken, {
      password: rotatedPassword,
      setupToken: freshStatus.body.setupToken as string,
      initialToken: generateSync({ secret: freshStatus.body.secret as string })
    })

    assert.equal(accepted.status, 200)
    assert.equal(await savedSecret(email) === (freshStatus.body.secret as string), true)
  })

  void it('a newly issued secret can still be enrolled when the user row has none', async () => {
    const email = 'fresh-enroll@example.test'
    const { firstToken } = await openSessions(email)
    const status = await getStatus(firstToken)
    assert.equal(status.status, 200)
    assert.equal(status.body.setup, false)
    const issuedSecret = status.body.secret as string

    const setup = await postSetup(firstToken, {
      password,
      setupToken: status.body.setupToken as string,
      initialToken: generateSync({ secret: issuedSecret })
    })

    assert.equal(setup.status, 200)
    assert.equal(await savedSecret(email) === issuedSecret, true)
    const after = await getStatus(firstToken)
    assert.equal(after.status, 200)
    assert.equal(after.body.setup, true)
    assertNoSetupMaterial(after.body)
  })
})
