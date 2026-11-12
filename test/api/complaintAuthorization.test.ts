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

const placeholderPassword = 'placeholder-password'
const callerMessage = 'caller-a-complaint-marker'
const otherMessage = 'caller-b-complaint-marker'
const callerFile = 'caller-a-attachment.txt'
const otherFile = 'caller-b-attachment.txt'

interface ComplaintRow {
  UserId: number
  message: string
  file: string | null
}

interface Session {
  userId: number
  token: string
}

let caller: Session
let other: Session

before(async () => {
  const result = await createTestApp()
  app = result.app
  caller = await openCustomerSession('complaint-caller-a@example.test')
  other = await openCustomerSession('complaint-caller-b@example.test')
  await createComplaint(caller, callerMessage, callerFile)
  await createComplaint(other, otherMessage, otherFile)
}, { timeout: 60000 })

void describe('GET /api/Complaints authorization', () => {
  void it('rejects an anonymous list', async () => {
    const res = await request(app).get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('returns only the authenticated customer complaints', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(bearer(caller.token))
    assert.equal(res.status, 200)
    const data = complaintRows(res.body)
    assert.ok(data.some(row => row.UserId === caller.userId && row.message === callerMessage && row.file === callerFile))
    assertOnlyCaller(data, caller.userId)
    assert.equal(data.some(row => row.message === otherMessage || row.file === otherFile), false)
  })

  void it('does not return another customer when the query names that user id', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .query({ UserId: other.userId })
      .set(bearer(caller.token))
    assert.equal(res.status, 200)
    assertOnlyCaller(complaintRows(res.body), caller.userId)
  })

  void it('does not return another customer when the query names that message', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .query({ message: otherMessage })
      .set(bearer(caller.token))
    assert.equal(res.status, 200)
    const data = complaintRows(res.body)
    assertOnlyCaller(data, caller.userId)
    assert.equal(data.some(row => row.message === otherMessage), false)
  })

  void it('does not return another customer when the query searches that message', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .query({ q: otherMessage })
      .set(bearer(caller.token))
    assert.equal(res.status, 200)
    const data = complaintRows(res.body)
    assertOnlyCaller(data, caller.userId)
    assert.equal(data.some(row => row.message === otherMessage), false)
  })

  void it('does not return another customer when the query names that file', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .query({ file: otherFile })
      .set(bearer(caller.token))
    assert.equal(res.status, 200)
    const data = complaintRows(res.body)
    assertOnlyCaller(data, caller.userId)
    assert.equal(data.some(row => row.file === otherFile), false)
  })
})

async function openCustomerSession (email: string): Promise<Session> {
  const registered = await register(app, { email, password: placeholderPassword })
  const userId = registered.body?.data?.id
  assert.equal(typeof userId, 'number')
  assert.equal(registered.body.data.role, 'customer')
  const { token } = await login(app, { email, password: placeholderPassword })
  assert.equal(typeof token, 'string')
  return { userId, token }
}

async function createComplaint (session: Session, message: string, file: string) {
  const res = await request(app)
    .post('/api/Complaints')
    .set(bearer(session.token))
    .send({ UserId: session.userId, message, file })
  assert.equal(res.status, 201)
  assert.equal(res.body.data.UserId, session.userId)
  assert.equal(res.body.data.message, message)
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function complaintRows (body: { data?: ComplaintRow[] }): ComplaintRow[] {
  assert.ok(Array.isArray(body.data))
  return body.data
}

function assertOnlyCaller (data: ComplaintRow[], callerId: number) {
  for (const row of data) {
    assert.equal(row.UserId, callerId)
  }
}
