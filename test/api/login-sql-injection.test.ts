/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { BasketModel } from '../../models/basket'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const wrongPassword = 'wrong-placeholder'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface ObservedLogin {
  status: number
  umail: string | null
  id: number | null
  role: string | null
  totpBypass: boolean
  walletAuthorized: boolean
  usersAuthorized: boolean
  basketAuthorized: boolean
  whoamiId: number | null
  sessionStored: boolean
  basketRows: number
}

function identityFromToken (token: unknown): { id: number | null, email: string | null, role: string | null } {
  if (typeof token !== 'string') {
    return { id: null, email: null, role: null }
  }
  const segment = token.split('.')[1]
  if (segment == null || segment === '') {
    return { id: null, email: null, role: null }
  }
  try {
    const parsed = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))
    const data = parsed?.data ?? {}
    const id = typeof data.id === 'number' ? data.id : null
    const email = typeof data.email === 'string' ? data.email : null
    const role = typeof data.role === 'string' ? data.role : null
    return { id, email, role }
  } catch {
    return { id: null, email: null, role: null }
  }
}

async function observeLogin (email: unknown, password: string): Promise<ObservedLogin> {
  const sessionsBefore = Object.keys(security.authenticatedUsers.tokenMap).length
  const basketsBefore = await BasketModel.count()
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  const token = res.body?.authentication?.token
  const identity = identityFromToken(token)
  let walletStatus = 0
  let usersStatus = 0
  let basketStatus = 0
  let whoamiId: number | null = null
  if (typeof token === 'string') {
    const wallet = await request(app)
      .get('/rest/wallet/balance')
      .set({ Authorization: 'Bearer ' + token })
    walletStatus = wallet.status
    const users = await request(app)
      .get('/api/Users')
      .set({ Authorization: 'Bearer ' + token })
    usersStatus = users.status
    const bid = res.body?.authentication?.bid
    if (typeof bid === 'number') {
      const basket = await request(app)
        .get('/rest/basket/' + String(bid))
        .set({ Authorization: 'Bearer ' + token })
      basketStatus = basket.status
    }
    const who = await request(app)
      .get('/rest/user/whoami')
      .set('Cookie', 'token=' + token)
    whoamiId = typeof who.body?.user?.id === 'number' ? who.body.user.id : null
  }
  const sessionsAfter = Object.keys(security.authenticatedUsers.tokenMap).length
  const basketsAfter = await BasketModel.count()
  return {
    status: res.status,
    umail: typeof res.body?.authentication?.umail === 'string' ? res.body.authentication.umail : null,
    id: identity.id,
    role: identity.role,
    totpBypass: res.body?.status === 'totp_token_required',
    walletAuthorized: walletStatus === 200,
    usersAuthorized: usersStatus === 200,
    basketAuthorized: basketStatus === 200,
    whoamiId,
    sessionStored: sessionsAfter !== sessionsBefore,
    basketRows: basketsAfter - basketsBefore
  }
}

const rejected: ObservedLogin = {
  status: 401,
  umail: null,
  id: null,
  role: null,
  totpBypass: false,
  walletAuthorized: false,
  usersAuthorized: false,
  basketAuthorized: false,
  whoamiId: null,
  sessionStored: false,
  basketRows: 0
}

void describe('login rejects email SQL that skips the password check', () => {
  void it('does not authenticate when the email closes the quote and forces the WHERE clause true', async () => {
    const first = await UserModel.findOne({ order: [['id', 'ASC']] })
    const observed = await observeLogin("' OR 1=1--", wrongPassword)
    assert.deepEqual({ ...observed, firstUserEmail: first?.email ?? null, firstUserRole: first?.role ?? null }, {
      ...rejected,
      firstUserEmail: first?.email ?? null,
      firstUserRole: first?.role ?? null
    })
  })

  void it('does not authenticate when the email comments out the password predicate for an existing account', async () => {
    const email = 'login-spec@example.test'
    const created = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: placeholderPassword })
    assert.equal(created.status, 201)

    const observed = await observeLogin(email + "'--", wrongPassword)
    assert.deepEqual(observed, rejected)
  })

  void it('does not authenticate when the email is a one-element array containing the same quote break', async () => {
    const observed = await observeLogin(["' OR 1=1--"], wrongPassword)
    assert.deepEqual(observed, rejected)
  })

  void it('does not authenticate when the email unions a forged user row', async () => {
    const existing = await UserModel.findOne({ order: [['id', 'ASC']] })
    assert.ok(existing)
    const email = `' UNION SELECT * FROM (SELECT ${existing.id} as 'id', '' as 'username', 'forged@example.test' as 'email', 'placeholder-password' as 'password', 'customer' as 'role', '' as 'deluxeToken', '0.0.0.0' as 'lastLoginIp', '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:14:41.644 +00:00' as 'updatedAt', null as 'deletedAt')--`
    const observed = await observeLogin(email, wrongPassword)
    assert.deepEqual(observed, rejected)
  })

  void it('does not treat a second factor as already satisfied when the email comments out the password predicate', async () => {
    const users = await UserModel.findAll()
    const totpUser = users.find((user) => typeof user.totpSecret === 'string' && user.totpSecret !== '')
    assert.ok(totpUser?.email)
    const observed = await observeLogin(totpUser.email + "'--", wrongPassword)
    assert.deepEqual(observed, rejected)
  })

  void it('does not authenticate when only the password contains a quote break', async () => {
    const observed = await observeLogin('does-not-exist@example.test', "' OR 1=1--")
    assert.deepEqual(observed, rejected)
  })

  void it('still authenticates an account whose email and password match exactly', async () => {
    const email = 'login-exact@example.test'
    const created = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: placeholderPassword })
    assert.equal(created.status, 201)

    const sessionsBefore = Object.keys(security.authenticatedUsers.tokenMap).length
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: placeholderPassword })
    const token = res.body?.authentication?.token
    assert.equal(res.status, 200)
    assert.equal(typeof token, 'string')
    assert.equal(res.body?.authentication?.umail, email)
    const wallet = await request(app)
      .get('/rest/wallet/balance')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(wallet.status, 200)
    const sessionsAfter = Object.keys(security.authenticatedUsers.tokenMap).length
    assert.equal(sessionsAfter, sessionsBefore + 1)
  })
})
