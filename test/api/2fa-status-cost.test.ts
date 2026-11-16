/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import type { Response } from 'supertest'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const password = 'placeholder-password'
const statusLimit = 100
const originalCreateSign = crypto.createSign
let privateKeySigns = 0

crypto.createSign = function (algorithm: string) {
  privateKeySigns += 1
  return originalCreateSign.call(crypto, algorithm)
}

function authorization (token: string) {
  return { Authorization: 'Bearer ' + token }
}

function getStatus (app: Express, token: string) {
  return request(app).get('/rest/2fa/status').set(authorization(token))
}

function algorithmOf (token: unknown) {
  if (typeof token !== 'string' || !token.includes('.')) {
    return 'missing'
  }
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'))
    return typeof header.alg === 'string' ? header.alg : 'missing'
  } catch {
    return 'missing'
  }
}

function signatureChecks (token: unknown) {
  if (typeof token !== 'string') {
    return false
  }
  try {
    return security.verify(token) === true
  } catch {
    return false
  }
}

function hasSetupToken (res: Response) {
  return res.body != null && typeof res.body === 'object' && Object.hasOwn(res.body, 'setupToken')
}

async function customer (app: Express, email: string) {
  await register(app, { email, password })
  const authentication = await login(app, { email, password })
  return authentication.token as string
}

async function enableThenDisable (app: Express, token: string) {
  const issued = await getStatus(app, token)
  assert.equal(issued.status, 200)
  assert.equal(issued.body.setup, false)
  const setupRes = await request(app)
    .post('/rest/2fa/setup')
    .set(authorization(token))
    .send({
      password,
      setupToken: issued.body.setupToken,
      initialToken: generateSync({ secret: issued.body.secret })
    })
  assert.equal(setupRes.status, 200)
  const disableRes = await request(app)
    .post('/rest/2fa/disable')
    .set(authorization(token))
    .send({ password })
  assert.equal(disableRes.status, 200)
}

after(() => {
  crypto.createSign = originalCreateSign
})

void describe('GET /rest/2fa/status setup signing', { concurrency: 1 }, () => {
  void it('reuses one signed setup token for a newly registered account', async () => {
    const { app } = await createTestApp()
    const token = await customer(app, 'status-reuse@juice-sh.op')
    const beforeFirst = privateKeySigns
    const first = await getStatus(app, token)
    const afterFirst = privateKeySigns
    const second = await getStatus(app, token)
    const afterSecond = privateKeySigns

    assert.deepEqual({
      firstStatus: first.status,
      secondStatus: second.status,
      firstSetup: first.body?.setup,
      firstAlg: algorithmOf(first.body?.setupToken),
      firstVerified: signatureChecks(first.body?.setupToken),
      sameSecret: first.body?.secret === second.body?.secret,
      sameToken: first.body?.setupToken === second.body?.setupToken,
      signsForFirst: afterFirst - beforeFirst,
      signsForSecond: afterSecond - afterFirst
    }, {
      firstStatus: 200,
      secondStatus: 200,
      firstSetup: false,
      firstAlg: 'RS256',
      firstVerified: true,
      sameSecret: true,
      sameToken: true,
      signsForFirst: 1,
      signsForSecond: 0
    })
  }, { timeout: 120000 })

  void it('stops signing setup tokens after 100 requests in the five minute window', async () => {
    const { app } = await createTestApp()
    const token = await customer(app, 'status-limit@juice-sh.op')
    const before = privateKeySigns
    const results = await Promise.all(
      Array.from({ length: statusLimit + 1 }, async () => await getStatus(app, token))
    )
    const signDelta = privateKeySigns - before
    const accepted = results.filter((res) => res.status === 200)
    const limited = results.filter((res) => res.status === 429)
    const distinctTokens = new Set(accepted.map((res) => res.body?.setupToken)).size
    const sample = accepted[0]

    assert.deepEqual({
      accepted: accepted.length,
      limited: limited.length,
      limitedWithoutSetupToken: limited.filter((res) => !hasSetupToken(res)).length,
      distinctTokens,
      signDelta,
      firstSetup: sample?.body?.setup ?? null,
      firstAlg: algorithmOf(sample?.body?.setupToken),
      firstVerified: signatureChecks(sample?.body?.setupToken)
    }, {
      accepted: statusLimit,
      limited: 1,
      limitedWithoutSetupToken: 1,
      distinctTokens: 1,
      signDelta: 1,
      firstSetup: false,
      firstAlg: 'RS256',
      firstVerified: true
    })
  }, { timeout: 120000 })

  void it('reuses one setup token after two-factor authentication is disabled', async () => {
    const { app } = await createTestApp()
    const token = await customer(app, 'status-disable-reuse@juice-sh.op')
    await enableThenDisable(app, token)
    const beforeFirst = privateKeySigns
    const first = await getStatus(app, token)
    const afterFirst = privateKeySigns
    const second = await getStatus(app, token)
    const afterSecond = privateKeySigns

    assert.deepEqual({
      firstStatus: first.status,
      secondStatus: second.status,
      firstSetup: first.body?.setup,
      firstAlg: algorithmOf(first.body?.setupToken),
      firstVerified: signatureChecks(first.body?.setupToken),
      sameSecret: first.body?.secret === second.body?.secret,
      sameToken: first.body?.setupToken === second.body?.setupToken,
      signsForFirst: afterFirst - beforeFirst,
      signsForSecond: afterSecond - afterFirst
    }, {
      firstStatus: 200,
      secondStatus: 200,
      firstSetup: false,
      firstAlg: 'RS256',
      firstVerified: true,
      sameSecret: true,
      sameToken: true,
      signsForFirst: 1,
      signsForSecond: 0
    })
  }, { timeout: 120000 })

  void it('applies the same request cap after two-factor authentication is disabled', async () => {
    const { app } = await createTestApp()
    const token = await customer(app, 'status-disable-limit@juice-sh.op')
    const priorStatusCalls = 1
    await enableThenDisable(app, token)
    const before = privateKeySigns
    const burst = statusLimit + 1
    const results = await Promise.all(
      Array.from({ length: burst }, async () => await getStatus(app, token))
    )
    const signDelta = privateKeySigns - before
    const accepted = results.filter((res) => res.status === 200)
    const limited = results.filter((res) => res.status === 429)
    const overTheCap = priorStatusCalls + burst - statusLimit

    assert.deepEqual({
      accepted: accepted.length,
      limited: limited.length,
      limitedWithoutSetupToken: limited.filter((res) => !hasSetupToken(res)).length,
      distinctTokens: new Set(accepted.map((res) => res.body?.setupToken)).size,
      verified: signatureChecks(accepted[0]?.body?.setupToken),
      signDelta
    }, {
      accepted: burst - overTheCap,
      limited: overTheCap,
      limitedWithoutSetupToken: overTheCap,
      distinctTokens: 1,
      verified: true,
      signDelta: 1
    })
  }, { timeout: 120000 })
})
