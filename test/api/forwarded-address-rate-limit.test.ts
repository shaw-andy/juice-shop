/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express

const budget = 100
const jsonHeader = { 'content-type': 'application/json' }
const originalPassword = 'placeholder-password'
const replacementPassword = 'placeholder-replacement'
const securityAnswer = 'placeholder-answer'
const wrongAnswer = 'placeholder-wrong-answer'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function repeat (times: number, send: () => Promise<Response>) {
  let last: Response | undefined
  for (let attempt = 1; attempt <= times; attempt++) {
    last = await send()
    assert.notEqual(last.status, 429, `attempt ${attempt} was limited before the budget of ${budget}`)
  }
  return last
}

void describe('client-supplied forwarded address must not reset a rate-limit budget', () => {
  void it('POST /rest/user/reset-password stays limited for one account when X-Forwarded-For changes', async () => {
    const email = 'rate-limit-reset@example.test'
    const registered = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: originalPassword, passwordRepeat: originalPassword })
    assert.equal(registered.status, 201)
    assert.equal(typeof registered.body.data.id, 'number')

    const saved = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
      .send({
        UserId: registered.body.data.id,
        SecurityQuestionId: 1,
        answer: securityAnswer
      })
    assert.equal(saved.status, 201)

    const reset = (forwardedFor: string, answer: string, nextPassword: string) => {
      return request(app)
        .post('/rest/user/reset-password')
        .set({ ...jsonHeader, 'X-Forwarded-For': forwardedFor })
        .send({ email, answer, new: nextPassword, repeat: nextPassword })
    }

    const first = await reset('203.0.113.10', wrongAnswer, replacementPassword)
    assert.equal(first.status, 401)
    assert.match(first.text, /Wrong answer to security question/)

    await repeat(budget - 1, async () => await reset('203.0.113.10', wrongAnswer, replacementPassword))

    const blocked = await reset('203.0.113.10', securityAnswer, replacementPassword)
    assert.equal(blocked.status, 429)

    const unchanged = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: originalPassword })
    assert.equal(unchanged.status, 200)

    const rotated = await reset('203.0.113.11', securityAnswer, replacementPassword)
    const rotatedChain = await reset('198.51.100.8, 203.0.113.10', securityAnswer, replacementPassword)
    assert.deepEqual(
      { rotated: rotated.status, chain: rotatedChain.status },
      { rotated: 429, chain: 429 }
    )

    const stillOriginal = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: originalPassword })
    assert.equal(stillOriginal.status, 200)

    const replacement = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: replacementPassword })
    assert.notEqual(replacement.status, 200)
  }, { timeout: 180000 })

  void it('POST /rest/2fa/verify stays limited when X-Forwarded-For changes', async () => {
    const verify = (forwardedFor: string) => {
      return request(app)
        .post('/rest/2fa/verify')
        .set({ ...jsonHeader, 'X-Forwarded-For': forwardedFor })
        .send({ tmpToken: 'placeholder-token', totpToken: 'placeholder-token' })
    }

    const first = await verify('203.0.113.20')
    assert.equal(first.status, 401)
    await repeat(budget - 1, async () => await verify('203.0.113.20'))
    const blocked = await verify('203.0.113.20')
    const rotated = await verify('203.0.113.21')
    const chain = await verify('198.51.100.21, 203.0.113.20')
    assert.deepEqual(
      { blocked: blocked.status, rotated: rotated.status, chain: chain.status },
      { blocked: 429, rotated: 429, chain: 429 }
    )
  }, { timeout: 180000 })

  void it('POST /rest/2fa/setup stays limited when X-Forwarded-For changes', async () => {
    const setup = (forwardedFor: string) => {
      return request(app)
        .post('/rest/2fa/setup')
        .set({ ...jsonHeader, 'X-Forwarded-For': forwardedFor })
        .send({})
    }

    const first = await setup('203.0.113.30')
    assert.notEqual(first.status, 429)
    await repeat(budget - 1, async () => await setup('203.0.113.30'))
    const blocked = await setup('203.0.113.30')
    const rotated = await setup('203.0.113.31')
    const chain = await setup('198.51.100.31, 203.0.113.30')
    assert.deepEqual(
      { blocked: blocked.status, rotated: rotated.status, chain: chain.status },
      { blocked: 429, rotated: 429, chain: 429 }
    )
  }, { timeout: 180000 })

  void it('POST /rest/2fa/disable stays limited when X-Forwarded-For changes', async () => {
    const disable = (forwardedFor: string) => {
      return request(app)
        .post('/rest/2fa/disable')
        .set({ ...jsonHeader, 'X-Forwarded-For': forwardedFor })
        .send({})
    }

    const first = await disable('203.0.113.40')
    assert.notEqual(first.status, 429)
    await repeat(budget - 1, async () => await disable('203.0.113.40'))
    const blocked = await disable('203.0.113.40')
    const rotated = await disable('203.0.113.41')
    const chain = await disable('198.51.100.41, 203.0.113.40')
    assert.deepEqual(
      { blocked: blocked.status, rotated: rotated.status, chain: chain.status },
      { blocked: 429, rotated: 429, chain: 429 }
    )
  }, { timeout: 180000 })
})
