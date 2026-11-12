/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import config from 'config'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express

const placeholderPassword = 'placeholder-password'
const jsonHeader = { 'content-type': 'application/json' }
const domain = config.get<string>('application.domain')
const seededAdminEmail = `admin@${domain}`
const seededAccountantEmail = `accountant@${domain}`
const seededDeluxeEmail = `ciso@${domain}`

interface Session {
  id: number
  email: string
  token: string
}

let customer: Session
let otherCustomer: Session
let deluxe: Session
let accounting: Session
let admin: Session

before(async () => {
  const result = await createTestApp()
  app = result.app
  customer = await createSession({ email: 'directory-customer@example.test' })
  otherCustomer = await createSession({ email: 'directory-other@example.test' })
  deluxe = await createSession({
    email: 'directory-deluxe@example.test',
    role: 'deluxe',
    deluxeToken: 'placeholder-deluxe-token'
  })
  accounting = await createSession({ email: 'directory-accounting@example.test', role: 'accounting' })
  admin = await createSession({ email: 'directory-admin@example.test', role: 'admin' })
}, { timeout: 60000 })

const directoryEmails = () => [
  seededAdminEmail,
  seededAccountantEmail,
  seededDeluxeEmail,
  otherCustomer.email,
  deluxe.email,
  accounting.email,
  admin.email
]

void describe('generated user directory', () => {
  void it('refuses the user collection to a customer session', async () => {
    const res = await request(app).get('/api/Users').set(bearer(customer.token))
    assertDirectoryRefused(res, directoryEmails().filter(email => email !== customer.email))
  })

  void it('refuses a customer collection query that names another account', async () => {
    const probes = [
      `/api/Users?email=${encodeURIComponent(seededAdminEmail)}`,
      '/api/Users?role=admin',
      '/api/Users?id=1',
      `/api/Users?q=${encodeURIComponent('admin@')}`
    ]
    for (const path of probes) {
      const res = await request(app).get(path).set(bearer(customer.token))
      assertDirectoryRefused(res, [seededAdminEmail, seededAccountantEmail])
    }
  })

  void it('refuses the user collection to deluxe and accounting sessions', async () => {
    for (const session of [deluxe, accounting]) {
      const res = await request(app).get('/api/Users').set(bearer(session.token))
      assertDirectoryRefused(res, [seededAdminEmail, seededAccountantEmail, customer.email])
    }
  })

  void it('refuses the user collection to a signed token with no role and no id', async () => {
    const res = await request(app).get('/api/Users').set(bearer(security.authorize()))
    assertDirectoryRefused(res, [seededAdminEmail, seededAccountantEmail, customer.email])
  })

  void it('refuses a customer read of another account id', async () => {
    const res = await request(app).get(`/api/Users/${otherCustomer.id}`).set(bearer(customer.token))
    assertDirectoryRefused(res, [otherCustomer.email])
    assert.equal(res.body?.data?.id, undefined)
  })

  void it('refuses a customer read of the seeded administrator id', async () => {
    const res = await request(app).get('/api/Users/1').set(bearer(customer.token))
    assertDirectoryRefused(res, [seededAdminEmail])
  })

  void it('refuses a customer read when the query names their id but the path names another account', async () => {
    const res = await request(app)
      .get(`/api/Users/${otherCustomer.id}?id=${customer.id}&email=${encodeURIComponent(customer.email)}`)
      .set(bearer(customer.token))
    assertDirectoryRefused(res, [otherCustomer.email])
    assert.notEqual(res.body?.data?.id, otherCustomer.id)
  })

  void it('refuses deluxe and accounting reads of another account id', async () => {
    for (const session of [deluxe, accounting]) {
      const res = await request(app).get(`/api/Users/${customer.id}`).set(bearer(session.token))
      assertDirectoryRefused(res, [customer.email])
    }
  })

  void it('refuses a signed token with no role and no id to read an account', async () => {
    const res = await request(app).get('/api/Users/1').set(bearer(security.authorize()))
    assertDirectoryRefused(res, [seededAdminEmail])
  })

  void it('lets a customer read only the account id in that session', async () => {
    const res = await request(app).get(`/api/Users/${customer.id}`).set(bearer(customer.token))
    assert.equal(res.status, 200, bodySummary(res))
    assert.equal(res.body.data.id, customer.id)
    assert.equal(res.body.data.email, customer.email)
    assert.equal(res.body.data.role, 'customer')
    assertAccountSecretsOmitted(res.body)
    assert.deepEqual(emailsIn(res.body).filter(email => email !== customer.email), [])
  })

  void it('keeps a customer read of their own id on that account when the query names another email', async () => {
    const res = await request(app)
      .get(`/api/Users/${customer.id}?email=${encodeURIComponent(seededAdminEmail)}&id=1`)
      .set(bearer(customer.token))
    assert.equal(res.status, 200, bodySummary(res))
    assert.equal(res.body.data.id, customer.id)
    assert.equal(res.body.data.email, customer.email)
    assert.equal(JSON.stringify(res.body).includes(seededAdminEmail), false)
    assertAccountSecretsOmitted(res.body)
  })

  void it('lets deluxe and accounting sessions read only their own account and omits the deluxe token', async () => {
    for (const session of [deluxe, accounting]) {
      const res = await request(app).get(`/api/Users/${session.id}`).set(bearer(session.token))
      assert.equal(res.status, 200, bodySummary(res))
      assert.equal(res.body.data.id, session.id)
      assert.equal(res.body.data.email, session.email)
      assertAccountSecretsOmitted(res.body)
    }
  })

  void it('lets an admin session list every account without password, totp secret, or deluxe token', async () => {
    const res = await request(app).get('/api/Users').set(bearer(admin.token))
    assert.equal(res.status, 200, bodySummary(res))
    const emails = emailsIn(res.body)
    assert.ok(emails.includes(seededAdminEmail))
    assert.ok(emails.includes(seededAccountantEmail))
    assert.ok(emails.includes(customer.email))
    assertAccountSecretsOmitted(res.body)
    const administrator = rowsIn(res.body).find(row => row.email === seededAdminEmail)
    const accountant = rowsIn(res.body).find(row => row.email === seededAccountantEmail)
    assert.equal(administrator?.role, 'admin')
    assert.equal(accountant?.role, 'accounting')
    assert.equal(typeof administrator?.lastLoginIp, 'string')
    assert.equal(typeof administrator?.profileImage, 'string')
  })

  void it('lets an admin session read another account by id without the deluxe token', async () => {
    const res = await request(app).get(`/api/Users/${deluxe.id}`).set(bearer(admin.token))
    assert.equal(res.status, 200, bodySummary(res))
    assert.equal(res.body.data.id, deluxe.id)
    assert.equal(res.body.data.email, deluxe.email)
    assert.equal(res.body.data.role, 'deluxe')
    assertAccountSecretsOmitted(res.body)
  })

  void it('does not return a deluxe token from user creation', async () => {
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'directory-created-deluxe@example.test',
        password: placeholderPassword,
        passwordRepeat: placeholderPassword,
        role: 'deluxe',
        deluxeToken: 'placeholder-deluxe-token'
      })
    assert.equal(res.status, 201)
    assertAccountSecretsOmitted(res.body)
  })
})

void describe('authentication details directory', () => {
  void it('refuses the account directory to a customer session', async () => {
    const res = await request(app).get('/rest/user/authentication-details').set(bearer(customer.token))
    assertDirectoryRefused(res, directoryEmails().filter(email => email !== customer.email))
  })

  void it('refuses the account directory to deluxe, accounting, and empty signed sessions', async () => {
    for (const token of [deluxe.token, accounting.token, security.authorize()]) {
      const res = await request(app).get('/rest/user/authentication-details').set(bearer(token))
      assertDirectoryRefused(res, [seededAdminEmail, seededAccountantEmail, customer.email])
    }
  })

  void it('lets an admin session list accounts without a deluxe token', async () => {
    const res = await request(app).get('/rest/user/authentication-details').set(bearer(admin.token))
    assert.equal(res.status, 200, bodySummary(res))
    const emails = emailsIn(res.body)
    assert.ok(emails.includes(seededAdminEmail))
    assert.ok(emails.includes(seededAccountantEmail))
    for (const row of rowsIn(res.body)) {
      assert.equal('deluxeToken' in row, false)
      assert.equal(isMaskedOrAbsent(row.password), true)
      assert.equal(isMaskedOrAbsent(row.totpSecret), true)
    }
  })
})

async function createSession (fields: { email: string, role?: string, deluxeToken?: string }): Promise<Session> {
  const created = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email: fields.email,
      password: placeholderPassword,
      passwordRepeat: placeholderPassword,
      role: fields.role,
      deluxeToken: fields.deluxeToken
    })
  assert.equal(created.status, 201, `register ${fields.email} returned ${created.status}`)
  const authentication = await login(app, { email: fields.email, password: placeholderPassword })
  return { id: created.body.data.id, email: fields.email, token: authentication.token }
}

function bearer (token: string) {
  return { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}

function rowsIn (body: any): any[] {
  if (Array.isArray(body?.data)) return body.data
  if (body?.data != null && typeof body.data === 'object') return [body.data]
  return []
}

function emailsIn (body: any): string[] {
  return rowsIn(body).map(row => row.email).filter((email: unknown) => typeof email === 'string')
}

function bodySummary (res: { status: number, body: any }) {
  const rows = rowsIn(res.body)
  const emails = emailsIn(res.body)
  const present = ['email', 'username', 'role', 'lastLoginIp', 'profileImage', 'deluxeToken', 'password', 'totpSecret']
    .filter(field => rows.some(row => row[field] !== undefined))
  return `status ${res.status}; accounts ${emails.length}; emails ${emails.join('|')}; fields ${present.join(',')}`
}

function assertDirectoryRefused (res: { status: number, body: any }, forbiddenEmails: string[]) {
  const leaked = forbiddenEmails.filter(email => emailsIn(res.body).includes(email))
  assert.equal(res.status, 403, `${bodySummary(res)}; leaked ${leaked.join('|')}`)
  assert.deepEqual(leaked, [])
}

function assertAccountSecretsOmitted (body: any) {
  for (const row of rowsIn(body)) {
    assert.equal('password' in row, false)
    assert.equal('totpSecret' in row, false)
    assert.equal('deluxeToken' in row, false)
  }
}

function isMaskedOrAbsent (value: unknown) {
  return value === undefined || (typeof value === 'string' && /^[*]*$/.test(value))
}
