/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'

let unsetEnvApp: Express
let productionEnvApp: Express

before(async () => {
  unsetEnvApp = (await createAppWithNodeEnv(undefined)).app
  productionEnvApp = (await createAppWithNodeEnv('production')).app
}, { timeout: 120000 })

void describe('unhandled errors do not disclose internals', () => {
  void it('POST /rest/user/login with a broken query returns no stack, SQL, or filesystem path as JSON when NODE_ENV is unset', async () => {
    const res = await request(unsetEnvApp)
      .post('/rest/user/login')
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .send({ email: "foo'", password: 'placeholder-password' })

    assertClientSafeError(res)
    assert.equal(res.text.includes('SELECT * FROM Users'), false, res.text)
  })

  void it('POST /rest/user/login with a broken query returns no stack or SQL as HTML when NODE_ENV is unset', async () => {
    const res = await request(unsetEnvApp)
      .post('/rest/user/login')
      .set('Accept', 'text/html')
      .set('Content-Type', 'application/json')
      .send({ email: "foo'", password: 'placeholder-password' })

    assertClientSafeError(res)
    assert.equal(res.text.includes('SELECT * FROM Users'), false, res.text)
  })

  void it('POST /rest/user/login with a broken query returns no stack or SQL as plain text when NODE_ENV is unset', async () => {
    const res = await request(unsetEnvApp)
      .post('/rest/user/login')
      .set('Accept', 'text/plain')
      .set('Content-Type', 'application/json')
      .send({ email: "foo'", password: 'placeholder-password' })

    assertClientSafeError(res)
    assert.equal(res.text.includes('SELECT * FROM Users'), false, res.text)
  })

  void it('POST /rest/user/login with a broken query returns no stack or SQL when the app was started with NODE_ENV=production', async () => {
    const res = await request(productionEnvApp)
      .post('/rest/user/login')
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .send({ email: "foo'", password: 'placeholder-password' })

    assertClientSafeError(res)
    assert.equal(res.text.includes('SELECT * FROM Users'), false, res.text)
  })

  void it('POST /rest/user/login with a body that is not JSON returns no stack or filesystem path', async () => {
    const res = await request(unsetEnvApp)
      .post('/rest/user/login')
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .send('{')

    assertClientSafeError(res)
  })

  void it('GET /rest/products/search with a broken query returns no stack, SQL, or filesystem path', async () => {
    const res = await request(unsetEnvApp)
      .get('/rest/products/search')
      .query({ q: "x'" })
      .set('Accept', 'application/json')

    assertClientSafeError(res)
    assert.equal(res.text.includes('SELECT * FROM Products'), false, res.text)
  })

  void it('PUT /rest/basket/:id/coupon for a missing basket returns no stack or filesystem path', async () => {
    const { token } = await registerAndLogin(unsetEnvApp)
    const res = await request(unsetEnvApp)
      .put('/rest/basket/999999/coupon/none')
      .set('Authorization', 'Bearer ' + token)
      .set('Accept', 'application/json')

    assertClientSafeError(res)
  })

  void it('GET /rest/user/change-password without a token returns no stack or filesystem path', async () => {
    const res = await request(unsetEnvApp)
      .get('/rest/user/change-password')
      .query({ new: 'placeholder-password', repeat: 'placeholder-password' })
      .set('Accept', 'application/json')

    assertClientSafeError(res)
  })

  void it('POST /rest/user/reset-password without an email returns no stack or filesystem path', async () => {
    const res = await request(unsetEnvApp)
      .post('/rest/user/reset-password')
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .send({})

    assertClientSafeError(res)
  })

  void it('GET /profile without a session returns no stack or filesystem path', async () => {
    const res = await request(unsetEnvApp)
      .get('/profile')
      .set('Accept', 'application/json')

    assertClientSafeError(res)
  })

  void it('GET /dataerasure without a session returns no stack or filesystem path', async () => {
    const res = await request(unsetEnvApp)
      .get('/dataerasure')
      .set('Accept', 'application/json')

    assertClientSafeError(res)
  })

  void it('POST /b2b/v2/orders with input that fails evaluation returns no stack or filesystem path', async () => {
    const { token } = await registerAndLogin(unsetEnvApp)
    const res = await request(unsetEnvApp)
      .post('/b2b/v2/orders')
      .set('Authorization', 'Bearer ' + token)
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .send({ orderLinesData: '(' })

    assertClientSafeError(res)
  })

  void it('POST /api/BasketItems for an unknown product returns no stack or filesystem path', async () => {
    const { token, bid } = await registerAndLogin(unsetEnvApp)
    const res = await request(unsetEnvApp)
      .post('/api/BasketItems')
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer ' + token)
      .send({ ProductId: 999999, BasketId: bid, quantity: 1 })

    assertClientSafeError(res)
  })

  void it('the repository image sets NODE_ENV to production', () => {
    const dockerfile = fs.readFileSync('Dockerfile', 'utf8')
    assert.match(dockerfile, /^ENV\s+NODE_ENV=production\s*$/m)
  })
})

async function createAppWithNodeEnv (nodeEnv: string | undefined) {
  const previous = process.env.NODE_ENV
  if (nodeEnv === undefined) {
    delete process.env.NODE_ENV
  } else {
    process.env.NODE_ENV = nodeEnv
  }
  try {
    return await createTestApp()
  } finally {
    if (previous === undefined) {
      delete process.env.NODE_ENV
    } else {
      process.env.NODE_ENV = previous
    }
  }
}

async function registerAndLogin (app: Express) {
  const email = `error-disclosure-${Math.random().toString(16).slice(2)}@example.test`
  const password = 'placeholder-password'
  await request(app)
    .post('/api/Users')
    .set('Content-Type', 'application/json')
    .send({ email, password })
    .expect(201)
  const login = await request(app)
    .post('/rest/user/login')
    .set('Content-Type', 'application/json')
    .send({ email, password })
    .expect(200)
  return login.body.authentication as { token: string, bid: number }
}

function assertClientSafeError (res: Response) {
  assert.ok(res.status >= 400, res.text)
  assert.equal(/\bat .+:\d+:\d+/.test(res.text), false, res.text)
  assert.equal(res.text.includes(process.cwd()), false, res.text)
  assert.equal(res.text.includes('node_modules'), false, res.text)
  assert.equal(res.text.includes('server.ts'), false, res.text)
  assert.equal(res.text.includes('SQLITE_ERROR'), false, res.text)
}
