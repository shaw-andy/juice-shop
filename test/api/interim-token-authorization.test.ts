/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
let readerToken = ''
let interimToken = ''
let holderId = 0

const jsonHeader = { 'content-type': 'application/json' }
const password = 'placeholder-password'
const readerEmail = 'interim-reader@example.test'
const holderEmail = 'interim-holder@example.test'
const complaintMarker = 'placeholder-complaint-must-not-persist'

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function listedCount (body: { data?: unknown }) {
  return Array.isArray(body?.data) ? body.data.length : 0
}

function rejected (status: number) {
  return status === 401 || status === 403
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const reader = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email: readerEmail, password, passwordRepeat: password })
  assert.equal(reader.status, 201)

  const readerLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: readerEmail, password })
  assert.equal(readerLogin.status, 200)
  readerToken = readerLogin.body.authentication.token

  const holder = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email: holderEmail, password, passwordRepeat: password })
  assert.equal(holder.status, 201)
  holderId = holder.body.data.id

  const sessionLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: holderEmail, password })
  assert.equal(sessionLogin.status, 200)

  const totpSecret = generateSecret()
  const setup = await request(app)
    .post('/rest/2fa/setup')
    .set(bearer(sessionLogin.body.authentication.token))
    .send({
      password,
      setupToken: security.authorize({
        secret: totpSecret,
        type: 'totp_setup_secret'
      }),
      initialToken: generateSync({ secret: totpSecret })
    })
  assert.equal(setup.status, 200)

  const passwordLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: holderEmail, password })
  assert.equal(passwordLogin.status, 401)
  assert.equal(passwordLogin.body.status, 'totp_token_required')
  interimToken = passwordLogin.body.data.tmpToken
  const decoded = security.decode(interimToken) as { type?: string, userId?: number }
  assert.equal(decoded?.type, 'password_valid_needs_second_factor_token')
  assert.equal(decoded?.userId, holderId)
}, { timeout: 60000 })

void describe('password-proof bearer token', { concurrency: 1 }, () => {
  void it('is rejected by GET /api/Users', async () => {
    const readerUsers = await request(app)
      .get('/api/Users')
      .set(bearer(readerToken))
    assert.equal(readerUsers.status, 200)
    assert.equal(
      readerUsers.body.data.some((user: { email?: string, role?: string }) => user.email === holderEmail && typeof user.role === 'string'),
      true
    )

    const users = await request(app)
      .get('/api/Users')
      .set(bearer(interimToken))
    const userBody = JSON.stringify(users.body)
    assert.equal(
      rejected(users.status) && listedCount(users.body) === 0 && !userBody.includes(holderEmail) && !userBody.includes(readerEmail),
      true,
      `GET /api/Users status ${users.status} count ${listedCount(users.body)} includesAccounts ${userBody.includes(holderEmail)}`
    )
  })

  void it('is rejected by GET /api/Users/:id', async () => {
    const oneUser = await request(app)
      .get('/api/Users/' + holderId)
      .set(bearer(interimToken))
    const oneBody = JSON.stringify(oneUser.body)
    assert.equal(
      rejected(oneUser.status) && oneUser.body?.data?.email !== holderEmail && !oneBody.includes(holderEmail),
      true,
      `GET /api/Users/${holderId} status ${oneUser.status} includesAccount ${oneBody.includes(holderEmail)}`
    )
  })

  void it('is rejected by GET /api/Complaints', async () => {
    const complaints = await request(app)
      .get('/api/Complaints')
      .set(bearer(interimToken))
    assert.equal(
      rejected(complaints.status) && listedCount(complaints.body) === 0,
      true,
      `GET /api/Complaints status ${complaints.status} count ${listedCount(complaints.body)}`
    )
  })

  void it('does not persist a complaint from POST /api/Complaints', async () => {
    const complaintsBefore = await request(app)
      .get('/api/Complaints')
      .set(bearer(readerToken))
    assert.equal(complaintsBefore.status, 200)
    const beforeCount = listedCount(complaintsBefore.body)

    const created = await request(app)
      .post('/api/Complaints')
      .set(bearer(interimToken))
      .send({ message: complaintMarker, UserId: holderId })

    const complaintsAfter = await request(app)
      .get('/api/Complaints')
      .set(bearer(readerToken))
    assert.equal(complaintsAfter.status, 200)
    assert.equal(listedCount(complaintsAfter.body), beforeCount)
    assert.equal(
      complaintsAfter.body.data.some((complaint: { message?: string }) => complaint.message === complaintMarker),
      false
    )
    assert.equal(rejected(created.status), true, `POST /api/Complaints status ${created.status}`)
    assert.equal(JSON.stringify(created.body ?? {}).includes(complaintMarker), false)
  })
})
