/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const attemptBudget = 100

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function placeholderPassword () {
  return `placeholder-${crypto.randomBytes(18).toString('base64url')}`
}

function emailFor (label: string) {
  return `${label}-${crypto.randomBytes(4).toString('hex')}@${config.get<string>('application.domain')}`
}

function forwardedAddress (prefix: number, host: number) {
  return `203.0.${prefix}.${host}`
}

async function registerAndLogin (label: string) {
  const email = emailFor(label)
  const password = placeholderPassword()
  await register(app, { email, password })
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  assert.equal(loginRes.status, 200)
  return { email, password, token: loginRes.body.authentication.token as string }
}

async function enableSecondFactor (token: string, password: string) {
  const statusRes = await request(app)
    .get('/rest/2fa/status')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
  assert.equal(statusRes.status, 200)
  assert.equal(statusRes.body.setup, false)
  const secret = statusRes.body.secret as string
  const setupRes = await request(app)
    .post('/rest/2fa/setup')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({
      password,
      setupToken: statusRes.body.setupToken,
      initialToken: generateSync({ secret })
    })
  assert.equal(setupRes.status, 200)
  return secret
}

async function postWithForwardedAddress (path: string, body: Record<string, unknown>, address: string, token?: string) {
  const headers: Record<string, string> = {
    ...jsonHeader,
    'X-Forwarded-For': address
  }
  if (token !== undefined) {
    headers.Authorization = 'Bearer ' + token
  }
  return await request(app).post(path).set(headers).send(body)
}

async function exhaustBudget (path: string, body: Record<string, unknown>, prefix: number, token?: string) {
  const responses: Response[] = []
  for (let attempt = 1; attempt <= attemptBudget; attempt++) {
    responses.push(await postWithForwardedAddress(path, body, forwardedAddress(prefix, attempt), token))
  }
  return responses
}

void describe('two-factor rate limit', () => {
  void it('returns 429 for the 101st verify from one forwarded address', async () => {
    const account = await registerAndLogin('stable-verify')
    const secret = await enableSecondFactor(account.token, account.password)
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: account.email, password: account.password })
    assert.equal(loginRes.status, 401)
    assert.equal(loginRes.body.status, 'totp_token_required')
    const address = forwardedAddress(1, 250)
    const wrong = { tmpToken: loginRes.body.data.tmpToken, totpToken: 'not-a-code' }
    for (let attempt = 1; attempt <= attemptBudget; attempt++) {
      const res = await postWithForwardedAddress('/rest/2fa/verify', wrong, address)
      assert.equal(res.status, 401)
    }
    const blocked = await postWithForwardedAddress('/rest/2fa/verify', {
      tmpToken: loginRes.body.data.tmpToken,
      totpToken: generateSync({ secret })
    }, address)
    assert.equal(blocked.status, 429)
    assert.equal(blocked.body?.authentication, undefined)
  }, { timeout: 120000 })

  void it('keeps the verify budget for one tmpToken when the forwarded address changes', async () => {
    const account = await registerAndLogin('rotating-verify')
    const secret = await enableSecondFactor(account.token, account.password)
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: account.email, password: account.password })
    assert.equal(loginRes.status, 401)
    assert.equal(loginRes.body.status, 'totp_token_required')
    const tmpToken = loginRes.body.data.tmpToken as string
    const guesses = await exhaustBudget('/rest/2fa/verify', { tmpToken, totpToken: 'not-a-code' }, 2)
    assert.equal(guesses[0].status, 401)
    const accepted = await postWithForwardedAddress('/rest/2fa/verify', {
      tmpToken,
      totpToken: generateSync({ secret })
    }, forwardedAddress(2, 250))
    assert.equal(accepted.status, 429)
    assert.equal(accepted.body?.authentication, undefined)
  }, { timeout: 120000 })

  void it('keeps the setup budget for one account when the forwarded address changes', async () => {
    const account = await registerAndLogin('rotating-setup')
    const statusRes = await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + account.token, 'content-type': 'application/json' })
    assert.equal(statusRes.status, 200)
    assert.equal(statusRes.body.setup, false)
    const secret = statusRes.body.secret as string
    const guesses = await exhaustBudget('/rest/2fa/setup', {
      password: account.password,
      setupToken: statusRes.body.setupToken,
      initialToken: 'not-a-code'
    }, 3, account.token)
    assert.equal(guesses[0].status, 401)
    const accepted = await postWithForwardedAddress('/rest/2fa/setup', {
      password: account.password,
      setupToken: statusRes.body.setupToken,
      initialToken: generateSync({ secret })
    }, forwardedAddress(3, 250), account.token)
    assert.equal(accepted.status, 429)
    const after = await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + account.token, 'content-type': 'application/json' })
    assert.equal(after.status, 200)
    assert.equal(after.body.setup, false)
  }, { timeout: 120000 })

  void it('keeps the disable budget for one account when the forwarded address changes', async () => {
    const account = await registerAndLogin('rotating-disable')
    await enableSecondFactor(account.token, account.password)
    const guesses = await exhaustBudget('/rest/2fa/disable', {
      password: placeholderPassword()
    }, 4, account.token)
    assert.equal(guesses[0].status, 401)
    const accepted = await postWithForwardedAddress('/rest/2fa/disable', {
      password: account.password
    }, forwardedAddress(4, 250), account.token)
    assert.equal(accepted.status, 429)
    const after = await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + account.token, 'content-type': 'application/json' })
    assert.equal(after.status, 200)
    assert.equal(after.body.setup, true)
  }, { timeout: 120000 })
})
