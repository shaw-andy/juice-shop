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
import * as security from '../../lib/insecurity'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let userId: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const credentials = { email: 'privacy-request@example.test', password: 'placeholder-password' }
  const registration = await register(app, credentials)
  userId = registration.body.data.id
  const { token } = await login(app, credentials)
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/api/PrivacyRequests', () => {
  void it('POST new privacy request for the logged-in user', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(authHeader)
      .send({
        deletionRequested: false
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.UserId, userId)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('POST new privacy request for another user is bound to the logged-in user', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(authHeader)
      .send({
        UserId: 1,
        deletionRequested: true
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, userId)
  })

  void it('POST new privacy request with a token that is not a logged-in session is forbidden', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
      .send({
        UserId: 1,
        deletionRequested: true
      })
    assert.equal(res.status, 401)
  })

  void it('GET all privacy requests is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests')
    assert.equal(res.status, 401)
  })
})

void describe('/api/PrivacyRequests/:id', () => {
  void it('GET all privacy requests is forbidden', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests')
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('GET existing privacy request by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing privacy request is forbidden', async () => {
    const res = await request(app)
      .put('/api/PrivacyRequests/1')
      .set(authHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing privacy request is forbidden', async () => {
    const res = await request(app)
      .delete('/api/PrivacyRequests/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
