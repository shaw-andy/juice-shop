/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import config from 'config'
import { QueryTypes } from 'sequelize'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
let sequelize: Sequelize

const placeholderPassword = 'placeholder\'not-a-real-password'
let profileMarker = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

void describe('login query must not treat the email as SQL', { concurrency: 1 }, () => {
  void it('rejects a quote and comment that leaves the first returned row', async () => {
    await assertLoginRejected(closeQuote('1=1'))
  })

  void it('rejects a quote and comment that selects only the seeded administrator', async () => {
    const adminEmail = seededAdminEmail()
    await assertLoginRejected(closeQuote(`email = '${adminEmail}'`), adminEmail)
  })

  void it('rejects a block comment that selects only the seeded administrator', async () => {
    const adminEmail = seededAdminEmail()
    await assertLoginRejected(`' OR email = '${adminEmail}'/*`, adminEmail)
  })

  void it('rejects a quote and comment with no trailing space that selects only the seeded administrator', async () => {
    const adminEmail = seededAdminEmail()
    await assertLoginRejected(`' OR email = '${adminEmail}'--`, adminEmail)
  })
})

function seededAdminEmail (): string {
  return 'admin@' + config.get<string>('application.domain')
}

function closeQuote (predicate: string): string {
  return `' OR ${predicate}-- `
}

async function assertLoginRejected (email: string, accountEmail?: string): Promise<void> {
  const firstRow = await firstSeededUser()
  const watchedEmail = accountEmail ?? firstRow?.email
  const targetBefore = watchedEmail ? await usernameOf(watchedEmail) : undefined

  const loginRes = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email, password: placeholderPassword })

  const marker = 'not-a-real-username-' + String(++profileMarker)
  const token = loginRes.body?.authentication?.token as string | undefined
  const tmpToken = loginRes.body?.data?.tmpToken as string | undefined
  const identity = identityFrom(token)
  let usersStatus: number | undefined
  let ordersStatus: number | undefined
  let profileStatus: number | undefined

  if (token) {
    const usersRes = await request(app)
      .get('/api/Users')
      .set('Authorization', 'Bearer ' + token)
    usersStatus = usersRes.status

    const ordersRes = await request(app)
      .get('/rest/order-history')
      .set('Authorization', 'Bearer ' + token)
    ordersStatus = ordersRes.status

    const profileRes = await request(app)
      .post('/profile')
      .set('Cookie', 'token=' + token)
      .set({ 'content-type': 'application/json' })
      .send({ username: marker })
    profileStatus = profileRes.status
  }

  const targetAfter = watchedEmail ? await usernameOf(watchedEmail) : undefined
  const usernameUnchanged = watchedEmail === undefined || targetBefore === targetAfter

  assert.ok(
    loginRes.status === 401 &&
      token === undefined &&
      tmpToken === undefined &&
      usernameUnchanged &&
      usersStatus !== 200 &&
      ordersStatus !== 200 &&
      profileStatus !== 302 &&
      profileStatus !== 200,
    'login must reject the email without issuing a session or changing a profile; ' +
      `status=${loginRes.status} sessionEmail=${identity.email ?? ''} sessionRole=${identity.role ?? ''} ` +
      `tmpToken=${tmpToken === undefined ? 'absent' : 'present'} ` +
      `usersStatus=${usersStatus ?? 'not-called'} ordersStatus=${ordersStatus ?? 'not-called'} profileStatus=${profileStatus ?? 'not-called'} ` +
      `usernameBefore=${targetBefore ?? ''} usernameAfter=${targetAfter ?? ''} ` +
      `firstSeededEmail=${firstRow?.email ?? ''} firstSeededRole=${firstRow?.role ?? ''}`
  )
}

function identityFrom (token?: string): { email?: string, role?: string } {
  if (!token) {
    return {}
  }
  const decoded = security.decode(token) as { data?: { email?: string, role?: string } } | string | null
  const payload = typeof decoded === 'string' ? JSON.parse(decoded) as { data?: { email?: string, role?: string } } : decoded
  return {
    email: payload?.data?.email,
    role: payload?.data?.role
  }
}

async function firstSeededUser (): Promise<{ email?: string, role?: string } | undefined> {
  const rows = await sequelize.query(
    'SELECT email, role FROM Users ORDER BY id ASC LIMIT 1',
    { type: QueryTypes.SELECT }
  ) as Array<{ email?: string, role?: string }>
  return rows[0]
}

async function usernameOf (email: string): Promise<string | null> {
  const rows = await sequelize.query(
    'SELECT username FROM Users WHERE email = :email',
    { replacements: { email }, type: QueryTypes.SELECT }
  ) as Array<{ username?: string | null }>
  if (rows.length === 0) {
    return null
  }
  return rows[0].username ?? ''
}
