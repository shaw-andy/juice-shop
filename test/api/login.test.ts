/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { loginWithGoogle, stubGoogleTokenInfo, validGoogleTokenInfo } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/login', () => {
  void it('POST login newly created user', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kalli@kasper.le',
        password: 'kallliiii'
      })
      .expect(201)

    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kalli@kasper.le',
        password: 'kallliiii'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(typeof res.body.authentication.umail, 'string')
    assert.equal(typeof res.body.authentication.bid, 'number')
  })

  void it('POST login non-existing user', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'otto@mei.er',
        password: 'ooootto'
      })

    assert.equal(res.status, 401)
  })

  void it('POST login without credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: undefined,
        password: undefined
      })

    assert.equal(res.status, 401)
  })

  void it('POST login with admin credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'admin@' + config.get<string>('application.domain'),
        password: 'admin123'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with support-team credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'support@' + config.get<string>('application.domain'),
        password: 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with MC SafeSearch credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'mc.safesearch@' + config.get<string>('application.domain'),
        password: 'Mr. N00dles'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with Amy credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'amy@' + config.get<string>('application.domain'),
        password: 'K1f.....................'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with wurstbrot credentials expects 2FA token', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'wurstbrot@' + config.get<string>('application.domain'),
        password: 'EinBelegtesBrotMitSchinkenSCHINKEN!'
      })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.tmpToken, 'string')
    assert.equal(res.body.status, 'totp_token_required')
  })

  void it('POST login with WHERE-clause disabling SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: '\' or 1=1--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "admin@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'admin@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "jim@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "bender@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bender@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with non-existing email "acc0unt4nt@juice-sh.op" via UNION SELECT injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: `' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@${config.get<string>('application.domain')}' as 'email', '12345' as 'password', 'accounting' as 'role', '' as deluxeToken, '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--`,
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with query-breaking SQL Injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: '\';',
        password: undefined
      })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/user/oauth', () => {
  async function oauthLoginWith (tokenInfo: Record<string, unknown>, status = 200) {
    const restoreFetch = stubGoogleTokenInfo(tokenInfo, status)
    try {
      return await request(app)
        .post('/rest/user/oauth')
        .set({ 'content-type': 'application/json' })
        .send({ accessToken: 'placeholder-google-access-token' })
    } finally {
      restoreFetch()
    }
  }

  void it('POST logs in the existing account of a verified Google email', async () => {
    const authentication = await loginWithGoogle(app, 'bjoern.kimminich@gmail.com')

    assert.equal(typeof authentication.token, 'string')
    assert.equal(authentication.umail, 'bjoern.kimminich@gmail.com')
  })

  void it('POST creates an account on first sign-in with a verified Google email', async () => {
    const res = await oauthLoginWith(validGoogleTokenInfo('first.google.signin@example.test'))

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(res.body.authentication.umail, 'first.google.signin@example.test')
  })

  void it('POST requires second factor for Google accounts with 2FA enabled', async () => {
    const res = await oauthLoginWith(validGoogleTokenInfo(`wurstbrot@${config.get<string>('application.domain')}`))

    assert.equal(res.status, 401)
    assert.equal(res.body.status, 'totp_token_required')
    assert.equal(typeof res.body.data.tmpToken, 'string')
  })

  void it('POST rejects access tokens issued to another OAuth client', async () => {
    const res = await oauthLoginWith({ ...validGoogleTokenInfo('bjoern.kimminich@gmail.com'), aud: 'another-client.apps.googleusercontent.com' })

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  void it('POST rejects access tokens without verified email', async () => {
    const res = await oauthLoginWith({ ...validGoogleTokenInfo('bjoern.kimminich@gmail.com'), email_verified: 'false' })

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  void it('POST rejects expired access tokens', async () => {
    const res = await oauthLoginWith({ ...validGoogleTokenInfo('bjoern.kimminich@gmail.com'), exp: String(Math.floor(Date.now() / 1000) - 60) })

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  void it('POST rejects access tokens Google does not recognize', async () => {
    const res = await oauthLoginWith({ error: 'invalid_token' }, 400)

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  void it('POST rejects requests without access token', async () => {
    const res = await request(app)
      .post('/rest/user/oauth')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern.kimminich@gmail.com' })

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })
})

void describe('/rest/saveLoginIp', () => {
  void it('GET last login IP will be saved as True-Client-IP header value', async () => {
    const authentication = await loginWithGoogle(app, 'bjoern.kimminich@gmail.com')

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + authentication.token,
        'true-client-ip': '1.2.3.4'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '1.2.3.4')
  })

  void it('GET last login IP will be saved as remote IP when True-Client-IP is not present', async () => {
    const authentication = await loginWithGoogle(app, 'bjoern.kimminich@gmail.com')

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + authentication.token
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '127.0.0.1')
  })

  void it('GET last login IP returns 401 Unauthorized when no token is provided', async () => {
    const res = await request(app).get('/rest/saveLoginIp')

    assert.equal(res.status, 401)
  })
})
