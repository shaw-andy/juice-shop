/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { UserModel } from '../../models/user'

const ATTACKER_ORIGIN = 'https://attacker.example'
const PRODUCT_MARKER = 'cors-spec-product-marker'
const HINT_MARKER = 'cors-spec-hint-marker'
const REVIEW_MARKER = 'cors-spec-review-marker'
const ANSWER_PLACEHOLDER = 'placeholder-answer'
const CREDENTIAL_FIELDS = ['password', 'totpSecret', 'deluxeToken']
const CONFIG_SECRET_FIELDS = ['geoStalkingMetaSecurityAnswer', 'geoStalkingVisualSecurityAnswer']

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function headerList (value: string | undefined): string[] {
  return (value ?? '').split(',').map(part => part.trim().toLowerCase()).filter(part => part.length > 0)
}

function crossOriginReadAllowed (res: { headers: Record<string, string | undefined> }): boolean {
  const allowOrigin = res.headers['access-control-allow-origin']
  return allowOrigin === '*' || allowOrigin === ATTACKER_ORIGIN
}

function preflightAllows (res: { headers: Record<string, string | undefined> }, method: string, requestHeader: string): boolean {
  return crossOriginReadAllowed(res) &&
    headerList(res.headers['access-control-allow-methods']).includes(method.toLowerCase()) &&
    headerList(res.headers['access-control-allow-headers']).includes(requestHeader.toLowerCase())
}

function hasOwnKey (value: unknown, key: string): boolean {
  if (Array.isArray(value)) {
    return value.some(item => hasOwnKey(item, key))
  }
  if (value !== null && typeof value === 'object') {
    for (const [childKey, childValue] of Object.entries(value)) {
      if (childKey === key || hasOwnKey(childValue, key)) return true
    }
  }
  return false
}

function assertRejected (status: number) {
  assert.ok(status === 401 || status === 403, 'unauthenticated request must be rejected')
}

void describe('cross-origin access to unauthenticated shop data', () => {
  void it('does not let an arbitrary origin read credential fields from GET /rest/memories', async () => {
    const res = await request(app)
      .get('/rest/memories')
      .set('Origin', ATTACKER_ORIGIN)

    assert.equal(crossOriginReadAllowed(res), false)
    assertRejected(res.status)
    for (const field of CREDENTIAL_FIELDS) {
      assert.equal(hasOwnKey(res.body, field), false)
    }
  })

  void it('does not let an arbitrary origin read GET /rest/admin/application-configuration', async () => {
    const res = await request(app)
      .get('/rest/admin/application-configuration')
      .set('Origin', ATTACKER_ORIGIN)

    assert.equal(crossOriginReadAllowed(res), false)
    assertRejected(res.status)
    for (const field of CONFIG_SECRET_FIELDS) {
      assert.equal(hasOwnKey(res.body, field), false)
    }
  })

  void it('does not let an arbitrary origin read GET /api/Products', async () => {
    const res = await request(app)
      .get('/api/Products')
      .set('Origin', ATTACKER_ORIGIN)

    assert.equal(crossOriginReadAllowed(res), false)
  })

  void it('does not let an arbitrary origin preflight and apply PUT /api/Products/:id', async () => {
    const listed = await request(app).get('/api/Products')
    const productId = listed.body.data[0].id
    const originalDescription = listed.body.data[0].description

    const preflight = await request(app)
      .options('/api/Products/' + productId)
      .set('Origin', ATTACKER_ORIGIN)
      .set('Access-Control-Request-Method', 'PUT')
      .set('Access-Control-Request-Headers', 'content-type')

    const update = await request(app)
      .put('/api/Products/' + productId)
      .set('Origin', ATTACKER_ORIGIN)
      .set('Content-Type', 'application/json')
      .send({ description: PRODUCT_MARKER })

    const after = await request(app).get('/api/Products/' + productId)

    assert.equal(preflightAllows(preflight, 'PUT', 'content-type'), false)
    assert.equal(crossOriginReadAllowed(update), false)
    assertRejected(update.status)
    assert.equal(after.body.data.description, originalDescription)
    assert.equal(after.body.data.description === PRODUCT_MARKER, false)
  })

  void it('does not let an arbitrary origin preflight and apply PUT /api/Hints/:id', async () => {
    const listed = await request(app).get('/api/Hints')
    const hintId = listed.body.data[0].id

    const preflight = await request(app)
      .options('/api/Hints/' + hintId)
      .set('Origin', ATTACKER_ORIGIN)
      .set('Access-Control-Request-Method', 'PUT')
      .set('Access-Control-Request-Headers', 'content-type')

    const update = await request(app)
      .put('/api/Hints/' + hintId)
      .set('Origin', ATTACKER_ORIGIN)
      .set('Content-Type', 'application/json')
      .send({ text: HINT_MARKER })

    const after = await request(app).get('/api/Hints')

    assert.equal(preflightAllows(preflight, 'PUT', 'content-type'), false)
    assert.equal(crossOriginReadAllowed(update), false)
    assertRejected(update.status)
    assert.equal(JSON.stringify(after.body).includes(HINT_MARKER), false)
  })

  void it('does not let an arbitrary origin preflight and apply PUT /rest/products/:id/reviews', async () => {
    const preflight = await request(app)
      .options('/rest/products/1/reviews')
      .set('Origin', ATTACKER_ORIGIN)
      .set('Access-Control-Request-Method', 'PUT')
      .set('Access-Control-Request-Headers', 'content-type')

    const update = await request(app)
      .put('/rest/products/1/reviews')
      .set('Origin', ATTACKER_ORIGIN)
      .set('Content-Type', 'application/json')
      .send({ message: REVIEW_MARKER, author: 'attacker@example' })

    const after = await request(app).get('/rest/products/1/reviews')

    assert.equal(preflightAllows(preflight, 'PUT', 'content-type'), false)
    assert.equal(crossOriginReadAllowed(update), false)
    assertRejected(update.status)
    assert.equal(JSON.stringify(after.body).includes(REVIEW_MARKER), false)
  })

  void it('does not let an arbitrary origin POST /api/SecurityAnswers for an account that has none', async () => {
    const users = await UserModel.findAll()
    const answers = await SecurityAnswerModel.findAll({ attributes: ['UserId'] })
    const answered = new Set(answers.map(answer => answer.UserId))
    const target = users.find(user => !answered.has(user.id))
    assert.ok(target)

    const preflight = await request(app)
      .options('/api/SecurityAnswers')
      .set('Origin', ATTACKER_ORIGIN)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type')

    const created = await request(app)
      .post('/api/SecurityAnswers')
      .set('Origin', ATTACKER_ORIGIN)
      .set('Content-Type', 'application/json')
      .send({
        UserId: target.id,
        SecurityQuestionId: 1,
        answer: ANSWER_PLACEHOLDER
      })

    const stored = await SecurityAnswerModel.count({ where: { UserId: target.id } })

    assert.equal(preflightAllows(preflight, 'POST', 'content-type'), false)
    assert.equal(crossOriginReadAllowed(created), false)
    assertRejected(created.status)
    assert.equal(stored, 0)
  })
})
