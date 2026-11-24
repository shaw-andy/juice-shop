/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

const jsonHeader = { 'content-type': 'application/json' }
const attackerEmail = 'hidden-search-attacker@example.test'
const attackerPassword = 'placeholder-password-attacker'
const firstEmail = 'hidden-search-first@example.test'
const secondEmail = 'hidden-search-second@example.test'
const victimTotp = 'PLACEHOLDER2FASECRETVALUE'
const absentProbe = 'qqqqqqqqqqqqqqqq'

let app: Express
let authHeader: Record<string, string>
let firstPassword = ''
let secondPassword = ''

interface ListedUser {
  id: number
  email: string
  role?: string
  password?: string
  totpSecret?: string
}

function passwordsWithHashOrderOppositeCreation (): { first: string, second: string } {
  for (let i = 0; i < 30; i++) {
    const first = `placeholder-password-first-${i}`
    const second = `placeholder-password-second-${i}`
    if (security.hash(first) > security.hash(second)) {
      return { first, second }
    }
  }
  throw new Error('could not choose stored values whose order differs from creation order')
}

async function register (email: string, password: string) {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password, passwordRepeat: password })
  assert.equal(res.status, 201)
  assert.equal(res.body?.data?.password, undefined)
  assert.equal(res.body?.data?.totpSecret, undefined)
  return res.body?.data as ListedUser
}

async function listUsers (query: Record<string, string> = {}): Promise<Response> {
  const req = request(app).get('/api/Users').set(authHeader)
  if (Object.keys(query).length > 0) {
    return await req.query(query)
  }
  return await req
}

function rowsOf (res: Response): ListedUser[] {
  const data: unknown = res.body?.data
  assert.ok(Array.isArray(data))
  return data as ListedUser[]
}

function includesEmail (res: Response, email: string): boolean {
  return rowsOf(res).some(row => row.email === email)
}

function hiddenFieldsAbsent (res: Response) {
  for (const row of rowsOf(res)) {
    assert.equal(row.password, undefined)
    assert.equal(row.totpSecret, undefined)
  }
}

function hiddenWindow (secret: string, visible: string): string {
  const haystack = visible.toLowerCase()
  const source = secret.toLowerCase()
  for (let length = 2; length <= source.length; length++) {
    for (let start = 0; start + length <= source.length; start++) {
      const window = source.slice(start, start + length)
      if (!haystack.includes(window) && !absentProbe.includes(window)) {
        return window
      }
    }
  }
  throw new Error('hidden column is not distinguishable from visible user fields')
}

function extendedWindow (secret: string, window: string): string {
  const source = secret.toLowerCase()
  const start = source.indexOf(window)
  assert.ok(start >= 0)
  assert.ok(start + window.length < source.length)
  return source.slice(start, start + window.length + 1)
}

// A fix may reject the query, refuse the list to this customer, or return a
// list that does not depend on the hidden column. Membership of the target
// must not change between a value that occurs only in that column and one
// that does not.
function assertNoMembershipOracle (match: Response, miss: Response, email: string) {
  const closed = (status: number) => status === 400 || status === 401 || status === 403
  if (closed(match.status) && closed(miss.status)) {
    return
  }
  assert.equal(match.status, 200)
  assert.equal(miss.status, 200)
  hiddenFieldsAbsent(match)
  hiddenFieldsAbsent(miss)
  assert.equal(includesEmail(match, email), includesEmail(miss, email))
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  const pair = passwordsWithHashOrderOppositeCreation()
  firstPassword = pair.first
  secondPassword = pair.second
  const attacker = await register(attackerEmail, attackerPassword)
  await register(firstEmail, firstPassword)
  await register(secondEmail, secondPassword)
  assert.equal(attacker.role, 'customer')
  const [updated] = await UserModel.update({ totpSecret: victimTotp }, { where: { email: firstEmail } })
  assert.equal(updated, 1)
  const { token } = await login(app, { email: attackerEmail, password: attackerPassword })
  authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('GET /api/Users hidden column search', () => {
  void it('does not reveal a password-column substring through q', async () => {
    const open = await listUsers()
    if (open.status === 401 || open.status === 403) return
    assert.equal(open.status, 200)
    const probe = hiddenWindow(security.hash(firstPassword), JSON.stringify(open.body))
    const match = await listUsers({ q: probe })
    const miss = await listUsers({ q: absentProbe })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not reveal the next character of a password-column match through q', async () => {
    const open = await listUsers()
    if (open.status === 401 || open.status === 403) return
    assert.equal(open.status, 200)
    const probe = hiddenWindow(security.hash(firstPassword), JSON.stringify(open.body))
    const longer = extendedWindow(security.hash(firstPassword), probe)
    const match = await listUsers({ q: longer })
    const miss = await listUsers({ q: absentProbe })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not reveal an overlapping password-column window through q', async () => {
    const open = await listUsers()
    if (open.status === 401 || open.status === 403) return
    assert.equal(open.status, 200)
    const hash = security.hash(firstPassword)
    const visible = JSON.stringify(open.body)
    const first = hiddenWindow(hash, visible)
    const start = hash.toLowerCase().indexOf(first)
    const overlapped = hash.toLowerCase().slice(start + 1, start + 1 + Math.max(first.length, 2))
    assert.ok(overlapped.length >= 2)
    assert.equal(visible.toLowerCase().includes(overlapped), false)
    const match = await listUsers({ q: overlapped })
    const miss = await listUsers({ q: absentProbe })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not reveal a totpSecret substring through q', async () => {
    const open = await listUsers()
    if (open.status === 401 || open.status === 403) return
    assert.equal(open.status, 200)
    const probe = hiddenWindow(victimTotp, JSON.stringify(open.body))
    const match = await listUsers({ q: probe })
    const miss = await listUsers({ q: absentProbe })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not reveal the next character of a totpSecret match through q', async () => {
    const open = await listUsers()
    if (open.status === 401 || open.status === 403) return
    assert.equal(open.status, 200)
    const probe = hiddenWindow(victimTotp, JSON.stringify(open.body))
    const longer = extendedWindow(victimTotp, probe)
    const match = await listUsers({ q: longer })
    const miss = await listUsers({ q: absentProbe })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not exact-match the password column from a query parameter', async () => {
    const match = await listUsers({ password: security.hash(firstPassword) })
    const miss = await listUsers({ password: security.hash('placeholder-password-unused') })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not exact-match the totpSecret column from a query parameter', async () => {
    const match = await listUsers({ totpSecret: victimTotp })
    const miss = await listUsers({ totpSecret: 'PLACEHOLDER2FASECRETOTHER' })
    await assertNoMembershipOracle(match, miss, firstEmail)
  })

  void it('does not order rows by the password column', async () => {
    const unsorted = await listUsers()
    const sorted = await listUsers({ sort: 'password' })
    if ((unsorted.status === 401 || unsorted.status === 403) &&
      (sorted.status === 401 || sorted.status === 403 || sorted.status === 400)) {
      return
    }
    assert.equal(unsorted.status, 200)
    if (sorted.status === 400) return
    assert.equal(sorted.status, 200)
    hiddenFieldsAbsent(sorted)
    const unsortedRows = rowsOf(unsorted)
    const sortedRows = rowsOf(sorted)
    const unsortedFirst = unsortedRows.findIndex(row => row.email === firstEmail)
    const unsortedSecond = unsortedRows.findIndex(row => row.email === secondEmail)
    const sortedFirst = sortedRows.findIndex(row => row.email === firstEmail)
    const sortedSecond = sortedRows.findIndex(row => row.email === secondEmail)
    assert.ok(unsortedFirst >= 0 && unsortedSecond >= 0)
    assert.ok(unsortedFirst < unsortedSecond)
    assert.ok(sortedFirst >= 0 && sortedSecond >= 0)
    assert.ok(sortedFirst < sortedSecond)
  })

  void it('does not order rows by the totpSecret column', async () => {
    const unsorted = await listUsers()
    const sorted = await listUsers({ sort: 'totpSecret' })
    if ((unsorted.status === 401 || unsorted.status === 403) &&
      (sorted.status === 401 || sorted.status === 403 || sorted.status === 400)) {
      return
    }
    assert.equal(unsorted.status, 200)
    if (sorted.status === 400) return
    assert.equal(sorted.status, 200)
    hiddenFieldsAbsent(sorted)
    const unsortedRows = rowsOf(unsorted)
    const sortedRows = rowsOf(sorted)
    const unsortedFirst = unsortedRows.findIndex(row => row.email === firstEmail)
    const unsortedSecond = unsortedRows.findIndex(row => row.email === secondEmail)
    const sortedFirst = sortedRows.findIndex(row => row.email === firstEmail)
    const sortedSecond = sortedRows.findIndex(row => row.email === secondEmail)
    assert.ok(unsortedFirst >= 0 && unsortedSecond >= 0)
    assert.ok(unsortedFirst < unsortedSecond)
    assert.ok(sortedFirst >= 0 && sortedSecond >= 0)
    assert.ok(sortedFirst < sortedSecond)
  })
})
