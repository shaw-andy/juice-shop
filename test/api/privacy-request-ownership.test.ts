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
import { PrivacyRequestModel } from '../../models/privacyRequests'

const password = 'placeholder-password'

let app: Express
let callerToken: string
let callerId: number
let nextOther = 0

before(async () => {
  const result = await createTestApp()
  app = result.app

  const callerEmail = 'privacy-caller@example.test'
  const caller = await register(app, { email: callerEmail, password })
  assert.equal(caller.body.data.role, 'customer')
  callerId = caller.body.data.id

  const authentication = await login(app, { email: callerEmail, password })
  callerToken = authentication.token

  const whoami = await request(app)
    .get('/rest/user/whoami')
    .set({ Cookie: 'token=' + callerToken })
  assert.equal(whoami.status, 200)
  assert.equal(whoami.body.user.id, callerId)
}, { timeout: 60000 })

async function registerOtherCustomer () {
  const email = `privacy-other-${nextOther++}@example.test`
  const other = await register(app, { email, password })
  assert.equal(other.body.data.role, 'customer')
  assert.notEqual(other.body.data.id, callerId)
  return other.body.data.id as number
}

async function rowsFor (userId: number) {
  return await PrivacyRequestModel.findAll({ where: { UserId: userId } })
}

async function postPrivacy (body: Record<string, unknown>, type: 'json' | 'form') {
  const req = request(app)
    .post('/api/PrivacyRequests')
    .set({ Authorization: 'Bearer ' + callerToken })
  if (type === 'form') {
    return await req.type('form').send(body)
  }
  return await req.set({ 'content-type': 'application/json' }).send(body)
}

async function assertDeletionIsNotQueuedFor (userId: number, res: { status: number, body: any }) {
  const storedForTarget = await rowsFor(userId)
  assert.equal(
    storedForTarget.length,
    0,
    `status ${res.status} left a privacy request for user ${userId}: ${JSON.stringify(storedForTarget.map((row) => row.toJSON()))}`
  )
  if (res.status >= 200 && res.status < 300) {
    assert.equal(res.body?.data?.UserId, callerId)
    assert.equal(res.body?.data?.deletionRequested, true)
    const stored = await PrivacyRequestModel.findByPk(res.body.data.id)
    assert.ok(stored)
    assert.equal(stored.UserId, callerId)
    assert.equal(stored.deletionRequested, true)
  }
}

void describe('POST /api/PrivacyRequests user binding', () => {
  void it('does not file a deletion request for another user from a JSON body', async () => {
    const otherId = await registerOtherCustomer()
    const res = await postPrivacy({ UserId: otherId, deletionRequested: true }, 'json')
    await assertDeletionIsNotQueuedFor(otherId, res)
  })

  void it('does not file a deletion request when the other user id is a string', async () => {
    const otherId = await registerOtherCustomer()
    const res = await postPrivacy({ UserId: String(otherId), deletionRequested: true }, 'json')
    await assertDeletionIsNotQueuedFor(otherId, res)
  })

  void it('does not file a deletion request from a form body naming another user', async () => {
    const otherId = await registerOtherCustomer()
    const res = await postPrivacy({ UserId: String(otherId), deletionRequested: 'true' }, 'form')
    await assertDeletionIsNotQueuedFor(otherId, res)
  })

  void it('records a deletion request for the signed-in customer when the body names that customer', async () => {
    const res = await postPrivacy({ UserId: callerId, deletionRequested: true }, 'json')
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, callerId)
    assert.equal(res.body.data.deletionRequested, true)
    const stored = await PrivacyRequestModel.findByPk(res.body.data.id)
    assert.ok(stored)
    assert.equal(stored.UserId, callerId)
    assert.equal(stored.deletionRequested, true)
  })

  void it('records a deletion request for the signed-in customer when the body omits the user id', async () => {
    const res = await postPrivacy({ deletionRequested: true }, 'json')
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, callerId)
    assert.equal(res.body.data.deletionRequested, true)
    const stored = await PrivacyRequestModel.findByPk(res.body.data.id)
    assert.ok(stored)
    assert.equal(stored.UserId, callerId)
    assert.equal(stored.deletionRequested, true)
  })

  void it('does not create a privacy request without a bearer token', async () => {
    const otherId = await registerOtherCustomer()
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set({ 'content-type': 'application/json' })
      .send({ UserId: otherId, deletionRequested: true })
    assert.equal(res.status, 401)
    assert.equal((await rowsFor(otherId)).length, 0)
  })

  void it('does not let PUT or PATCH retarget an existing privacy request', async () => {
    const otherId = await registerOtherCustomer()
    const created = await postPrivacy({ UserId: callerId, deletionRequested: true }, 'json')
    assert.equal(created.status, 201)
    const id = created.body.data.id

    const put = await request(app)
      .put('/api/PrivacyRequests/' + id)
      .set({ Authorization: 'Bearer ' + callerToken, 'content-type': 'application/json' })
      .send({ UserId: otherId, deletionRequested: true })
    const patch = await request(app)
      .patch('/api/PrivacyRequests/' + id)
      .set({ Authorization: 'Bearer ' + callerToken, 'content-type': 'application/json' })
      .send({ UserId: otherId, deletionRequested: true })

    assert.equal(put.status, 401)
    assert.ok(patch.status === 401 || patch.status === 404)
    const stored = await PrivacyRequestModel.findByPk(id)
    assert.ok(stored)
    assert.equal(stored.UserId, callerId)
    assert.equal((await rowsFor(otherId)).length, 0)
  })
})
