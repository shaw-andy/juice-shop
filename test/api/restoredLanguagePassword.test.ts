/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const accountA = { email: 'language-cookie-a@example.com', password: 'placeholder-current' }
const accountB = { email: 'language-cookie-b@example.com', password: 'placeholder-other' }
const chosenPassword = 'placeholder-chosen'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function register (email: string, password: string): Promise<void> {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password })
  assert.equal(res.status, 201)
}

async function loginStatus (email: string, password: string): Promise<number> {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  return res.status
}

async function bearerFor (email: string, password: string): Promise<string> {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  assert.equal(res.status, 200)
  assert.equal(typeof res.body?.authentication?.token, 'string')
  return res.body.authentication.token
}

void describe('/rest/user/change-password', () => {
  void it('does not replace the signed-in account password when current is omitted', async () => {
    await register(accountA.email, accountA.password)
    await register(accountB.email, accountB.password)
    const token = await bearerFor(accountA.email, accountA.password)

    await request(app)
      .get('/rest/user/change-password?new=' + encodeURIComponent(chosenPassword) + '&repeat=' + encodeURIComponent(chosenPassword))
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(await loginStatus(accountA.email, accountA.password), 200)
    assert.equal(await loginStatus(accountA.email, chosenPassword), 401)
    assert.equal(await loginStatus(accountB.email, accountB.password), 200)
    assert.equal(await loginStatus(accountB.email, chosenPassword), 401)
  })
})
