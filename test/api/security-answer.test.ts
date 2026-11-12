/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
const authHeader = { Authorization: `Bearer ${security.authorize()}`, ...jsonHeader }
const password = 'placeholder-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function registerAndLogin (prefix: string, securityQuestion: { id: number } | null = null, securityAnswer: string | null = null) {
  const email = `${prefix}-${Date.now()}@te.st`
  const userRes = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password, passwordRepeat: password, securityQuestion, securityAnswer })
  assert.equal(userRes.status, 201)
  const { token } = await login(app, { email, password })
  return { id: userRes.body.data.id as number, email, authHeader: { Authorization: `Bearer ${token}`, ...jsonHeader } }
}

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new security answer for own account that already has one fails from unique constraint', async () => {
    const user = await registerAndLogin('answered', { id: 1 }, 'Horst')
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(user.authHeader)
      .send({
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })

  void it('POST new security answer without being logged in is forbidden', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer with a token that belongs to no logged-in user is forbidden', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(authHeader)
      .send({
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer for a different user is forbidden', async () => {
    const caller = await registerAndLogin('caller')
    const target = await registerAndLogin('target')
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(caller.authHeader)
      .send({
        UserId: target.id,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 403)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST security answer for own newly registered account', async () => {
    const user = await registerAndLogin('new.user')
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(user.authHeader)
      .send({
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.UserId, user.id)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('PUT update existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .put('/api/SecurityAnswers/1')
      .set(authHeader)
      .send({
        answer: 'Blurp'
      })

    assert.equal(res.status, 401)
  })

  void it('DELETE existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })
})

void describe('/api/Users', () => {
  void it('POST new user stores the security answer given during registration', async () => {
    const user = await registerAndLogin('registered', { id: 1 }, 'Horst')
    const res = await request(app)
      .get('/rest/user/security-question')
      .query({ email: user.email })

    assert.equal(res.status, 200)
    assert.equal(res.body.question.id, 1)
  })

  void it('POST new user with an unknown security question is rejected without creating the user', async () => {
    const email = `unknown.question-${Date.now()}@te.st`
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password, passwordRepeat: password, securityQuestion: { id: 99999 }, securityAnswer: 'Horst' })

    assert.equal(res.status, 400)
    assert.equal(await UserModel.count({ where: { email }, paranoid: false }), 0)
  })
})
