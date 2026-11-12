/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomBytes } from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'

const placeholderPassword = 'placeholder-not-a-secret'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface AccountProfile {
  id?: number
  email?: string
  role?: string
  password?: string
  totpSecret?: string
}

function uniqueEmail (label: string) {
  return `${label}-${randomBytes(4).toString('hex')}@directory.test`
}

function profilesOf (body: { data?: unknown }): AccountProfile[] {
  const data = body?.data
  if (Array.isArray(data)) return data as AccountProfile[]
  if (data !== null && typeof data === 'object') return [data as AccountProfile]
  return []
}

function bearer (token: string) {
  return { Authorization: `Bearer ${token}` }
}

async function registerCustomer (email: string) {
  const res = await register(app, { email, password: placeholderPassword })
  assert.equal(typeof res.body.data.id, 'number')
  return { email, id: res.body.data.id as number }
}

async function registerAdministrator (email: string) {
  const user = await registerCustomer(email)
  const [updated] = await UserModel.update({ role: 'admin' }, { where: { id: user.id } })
  assert.equal(updated, 1)
  const stored = await UserModel.findByPk(user.id)
  assert.equal(stored?.role, 'admin')
  return user
}

async function sessionFor (email: string) {
  const authentication = await login(app, { email, password: placeholderPassword })
  assert.equal(typeof authentication.token, 'string')
  return authentication.token as string
}

function assertOnlyCaller (profiles: AccountProfile[], caller: { email: string, id: number }) {
  assert.deepEqual(profiles.map((profile) => profile.email), [caller.email])
  assert.equal(profiles.length, 1)
  assert.equal(profiles[0].id, caller.id)
  assert.equal(profiles[0].role, 'customer')
  assert.ok(profiles[0].password === undefined || /^\*+$/.test(profiles[0].password))
  const totpSecret = profiles[0].totpSecret
  assert.ok(totpSecret === undefined || totpSecret === '' || /^\*+$/.test(totpSecret))
}

void describe('account directory authorization', { concurrency: 1 }, () => {
  void it('rejects authentication-details when no session is presented', async () => {
    const res = await request(app).get('/rest/user/authentication-details')
    assert.equal(res.status, 401)
  })

  void it('returns only the caller from authentication-details for a customer session', async () => {
    const caller = await registerCustomer(uniqueEmail('caller'))
    const other = await registerCustomer(uniqueEmail('other'))
    const token = await sessionFor(caller.email)

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .query({ id: other.id, email: other.email })
      .set({ ...bearer(token), 'x-user-email': other.email })

    assert.equal(res.status, 200)
    assertOnlyCaller(profilesOf(res.body), caller)
    assert.equal(JSON.stringify(res.body).includes(other.email), false)
  })

  void it('returns every account from authentication-details for an administrator session', async () => {
    const administrator = await registerAdministrator(uniqueEmail('admin'))
    const customer = await registerCustomer(uniqueEmail('listed'))
    const token = await sessionFor(administrator.email)

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(bearer(token))

    assert.equal(res.status, 200)
    const emails = profilesOf(res.body).map((profile) => profile.email)
    assert.ok(emails.includes(administrator.email))
    assert.ok(emails.includes(customer.email))
  })

  void it('does not list every account through /api/Users for a customer session', async () => {
    const caller = await registerCustomer(uniqueEmail('api-caller'))
    const other = await registerCustomer(uniqueEmail('api-other'))
    const token = await sessionFor(caller.email)

    const res = await request(app)
      .get('/api/Users')
      .set(bearer(token))

    if (res.status === 403) {
      assert.equal(JSON.stringify(res.body).includes(other.email), false)
    } else {
      assert.equal(res.status, 200)
      assertOnlyCaller(profilesOf(res.body), caller)
      assert.equal(JSON.stringify(res.body).includes(other.email), false)
    }
  })

  void it('does not let a customer session select another account with /api/Users query parameters', async () => {
    const caller = await registerCustomer(uniqueEmail('query-caller'))
    const other = await registerCustomer(uniqueEmail('query-other'))
    const token = await sessionFor(caller.email)

    const filtered = await request(app)
      .get('/api/Users')
      .query({ email: other.email })
      .set(bearer(token))

    assert.equal(JSON.stringify(filtered.body).includes(other.email), false)
    if (filtered.status === 200) {
      assertOnlyCaller(profilesOf(filtered.body), caller)
    } else {
      assert.equal(filtered.status, 403)
    }
  })

  void it('lists every account through /api/Users for an administrator session', async () => {
    const administrator = await registerAdministrator(uniqueEmail('api-admin'))
    const customer = await registerCustomer(uniqueEmail('api-listed'))
    const token = await sessionFor(administrator.email)

    const res = await request(app)
      .get('/api/Users')
      .set(bearer(token))

    assert.equal(res.status, 200)
    const emails = profilesOf(res.body).map((profile) => profile.email)
    assert.ok(emails.includes(administrator.email))
    assert.ok(emails.includes(customer.email))
  })

  void it('does not read another account through /api/Users/:id for a customer session', async () => {
    const caller = await registerCustomer(uniqueEmail('read-caller'))
    const other = await registerCustomer(uniqueEmail('read-other'))
    const token = await sessionFor(caller.email)

    const res = await request(app)
      .get(`/api/Users/${other.id}`)
      .set(bearer(token))

    assert.equal(JSON.stringify(res.body).includes(other.email), false)
    if (res.status === 200) {
      assertOnlyCaller(profilesOf(res.body), caller)
    } else {
      assert.ok(res.status === 403 || res.status === 404)
    }
  })

  void it('reads the caller through /api/Users/:id for a customer session', async () => {
    const caller = await registerCustomer(uniqueEmail('read-self'))
    const token = await sessionFor(caller.email)

    const res = await request(app)
      .get(`/api/Users/${caller.id}`)
      .set(bearer(token))

    assert.equal(res.status, 200)
    assert.equal(profilesOf(res.body)[0]?.email, caller.email)
    assert.equal(profilesOf(res.body)[0]?.id, caller.id)
  })
})
