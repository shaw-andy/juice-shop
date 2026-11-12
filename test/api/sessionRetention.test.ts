/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { generateSecret } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'

let app: Express
let sequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function delay (ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

function userIdFrom (token: string): number {
  const payload = security.decode(token) as { data: { id: number } }
  return payload.data.id
}

function retained (token: string): boolean {
  return security.authenticatedUsers.get(token) !== undefined
}

function sessionCountFor (userId: number): number {
  return Object.values(security.authenticatedUsers.tokenMap).filter((entry) => {
    return entry?.data?.id === userId
  }).length
}

async function registerCustomer (label: string): Promise<{ email: string, password: string }> {
  sequence += 1
  const email = `${label}-${sequence}@example.test`
  await register(app, { email, password: placeholderPassword })
  return { email, password: placeholderPassword }
}

async function loginToken (credentials: { email: string, password: string, totpSecret?: string }): Promise<string> {
  const authentication = await login(app, credentials)
  assert.equal(typeof authentication.token, 'string')
  return authentication.token
}

async function nextDistinctToken (credentials: { email: string, password: string, totpSecret?: string }, previous: string): Promise<string> {
  let token = previous
  for (let attempt = 0; attempt < 5 && token === previous; attempt++) {
    await delay(1100)
    token = await loginToken(credentials)
  }
  assert.notEqual(token, previous)
  return token
}

function tokenFromSetCookie (res: { headers: Record<string, string | string[] | undefined> }): string {
  const raw = res.headers['set-cookie']
  const cookies = Array.isArray(raw) ? raw : (raw != null ? [raw] : [])
  for (const cookie of cookies) {
    const match = /^token=([^;]+)/.exec(cookie)
    if (match != null) {
      return decodeURIComponent(match[1])
    }
  }
  assert.fail('profile response did not set a session token')
}

async function presentBearer (token: string): Promise<void> {
  await request(app)
    .get('/rest/admin/application-version')
    .set({ Authorization: 'Bearer ' + token })
  await delay(50)
}

void describe('session retention', () => {
  void it('drops the previous login session and does not restore it', async () => {
    const credentials = await registerCustomer('login-retention')
    const first = await loginToken(credentials)
    const userId = userIdFrom(first)
    const beforeNext = sessionCountFor(userId)
    const second = await nextDistinctToken(credentials, first)

    assert.equal(retained(first), false)
    assert.equal(retained(second), true)
    assert.ok(sessionCountFor(userId) <= beforeNext)

    await presentBearer(first)
    assert.equal(retained(first), false)
    assert.equal(sessionCountFor(userId), 1)
  })

  void it('drops sessions replaced by profile updates and does not restore them', async () => {
    const credentials = await registerCustomer('profile-retention')
    let current = await loginToken(credentials)
    const userId = userIdFrom(current)
    const issued = [current]

    for (let update = 1; update <= 4; update++) {
      const res = await request(app)
        .post('/profile')
        .set({ ...jsonHeader, Cookie: 'token=' + current })
        .redirects(0)
        .send({ username: 'kept-name-' + update })
      assert.equal(res.status, 302)
      current = tokenFromSetCookie(res)
      issued.push(current)
    }

    const distinct = new Set(issued)
    assert.equal(distinct.size, issued.length)
    for (const token of issued) {
      assert.equal(retained(token), token === current)
    }
    assert.equal(sessionCountFor(userId), 1)

    await presentBearer(issued[0])
    assert.equal(retained(issued[0]), false)
    assert.equal(sessionCountFor(userId), 1)
  })

  void it('drops the previous session when a deluxe token is issued', async () => {
    const credentials = await registerCustomer('deluxe-retention')
    const previous = await loginToken(credentials)
    const userId = userIdFrom(previous)
    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + previous })
      .send({ paymentMode: 'none' })

    assert.equal(res.status, 200)
    const upgraded = res.body.data.token as string
    assert.notEqual(upgraded, previous)
    assert.equal(retained(previous), false)
    assert.equal(retained(upgraded), true)

    await presentBearer(previous)
    assert.equal(retained(previous), false)
    assert.equal(sessionCountFor(userId), 1)
  })

  void it('drops the previous two-factor session and does not restore it', async () => {
    sequence += 1
    const credentials = {
      email: `two-factor-retention-${sequence}@example.test`,
      password: placeholderPassword,
      totpSecret: generateSecret()
    }
    await register(app, credentials)
    const first = await loginToken(credentials)
    const userId = userIdFrom(first)
    const second = await nextDistinctToken(credentials, first)

    assert.equal(retained(first), false)
    assert.equal(retained(second), true)
    await presentBearer(first)
    assert.equal(retained(first), false)
    assert.equal(sessionCountFor(userId), 1)
  })
})
