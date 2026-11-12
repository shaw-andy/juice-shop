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
const sessionCap = 50

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function delay (ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

function retainedCount (): number {
  return Object.keys(security.authenticatedUsers.tokenMap).length
}

void describe('session map cap', () => {
  void it('retains at most the cap and rejects a login that would exceed it', async () => {
    const tokens: string[] = []
    for (let index = 0; index < sessionCap + 1; index++) {
      tokens.push(security.authorize({
        data: {
          id: 50000 + index,
          email: `cap-${index}@example.test`,
          role: 'customer'
        },
        bid: 1
      }))
    }

    for (const token of tokens) {
      await request(app)
        .get('/rest/admin/application-version')
        .set({ Authorization: 'Bearer ' + token })
      await delay(20)
    }

    assert.equal(retainedCount(), sessionCap)
    const dropped = tokens.filter((token) => security.authenticatedUsers.get(token) === undefined)
    assert.ok(dropped.length >= 1)

    const email = 'over-cap@example.test'
    await register(app, { email, password: placeholderPassword })
    const before = retainedCount()
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: placeholderPassword })

    assert.notEqual(res.status, 200)
    const issued = res.body?.authentication?.token as string | undefined
    if (issued != null) {
      assert.equal(security.authenticatedUsers.get(issued), undefined)
    }
    assert.ok(retainedCount() <= before)
  })
})
