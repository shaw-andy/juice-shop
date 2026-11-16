/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

const email = 'placeholder-route-param@example.test'
const originalPassword = 'placeholder-password'
const nextPassword = 'placeholder-next'

before(async () => {
  const result = await createTestApp()
  app = result.app
  await register(app, { email, password: originalPassword })
}, { timeout: 60000 })

void describe('GET /rest/user/change-password without the current password', () => {
  void it('does not replace the signed-in account password', async () => {
    const { token } = await login(app, { email, password: originalPassword })

    await request(app)
      .get('/rest/user/change-password')
      .query({ new: nextPassword, repeat: nextPassword })
      .set('Authorization', 'Bearer ' + token)

    const withOriginal = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email, password: originalPassword })
    assert.equal(withOriginal.status, 200)

    const withReplacement = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email, password: nextPassword })
    assert.notEqual(withReplacement.status, 200)
  })
})
