/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const loginLimit = 100

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function tokensFor (userId: number): string[] {
  return Object.entries(security.authenticatedUsers.tokenMap)
    .filter(([, entry]) => entry?.data?.id === userId)
    .map(([token]) => token)
    .sort()
}

void describe('login rate limit', () => {
  void it('rejects the login after the limit and does not retain a session for that request', async () => {
    const email = 'rate-limit@example.test'
    await register(app, { email, password: placeholderPassword })

    const statuses: number[] = []
    let userId: number | undefined
    let previousTokens: string[] = []

    for (let attempt = 0; attempt < loginLimit + 1; attempt++) {
      const res = await request(app)
        .post('/rest/user/login')
        .set(jsonHeader)
        .send({ email, password: placeholderPassword })
      statuses.push(res.status)

      const token = res.body?.authentication?.token as string | undefined
      if (token != null && userId === undefined) {
        userId = (security.decode(token) as { data: { id: number } }).data.id
        previousTokens = tokensFor(userId)
      }

      if (res.status === 429 && userId !== undefined) {
        assert.deepEqual(tokensFor(userId), previousTokens)
        if (token != null) {
          assert.equal(security.authenticatedUsers.get(token), undefined)
        }
      }

      if (userId !== undefined) {
        previousTokens = tokensFor(userId)
      }
    }

    assert.ok(statuses.includes(429), `statuses were ${statuses.join(',')}`)
  })
})
