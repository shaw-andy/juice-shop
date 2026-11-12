/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const owner = { data: { id: 2, email: 'owner@recycle.test', role: 'customer' } }
const ownerToken = security.authorize(owner)
const other = { data: { id: 5, email: 'other@recycle.test', role: 'customer' } }
const otherToken = security.authorize(other)

before(async () => {
  const result = await createTestApp()
  app = result.app
  security.authenticatedUsers.put(ownerToken, owner as any)
  security.authenticatedUsers.put(otherToken, other as any)
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('Will prevent GET all recycles from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
  })

  void it('Will GET own existing recycle from this endpoint', async () => {
    const created = await request(app)
      .post('/api/Recycles')
      .set({ Authorization: 'Bearer ' + ownerToken, 'content-type': 'application/json' })
      .send({
        UserId: owner.data.id,
        quantity: 100,
        AddressId: '1',
        isPickup: false,
        date: '2017-06-01'
      })
    assert.equal(created.status, 201)

    const res = await request(app)
      .get(`/api/Recycles/${created.body.data.id}`)
      .set('Authorization', 'Bearer ' + ownerToken)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    assert.equal(items.length, 1)
    for (const item of items) {
      assert.equal(item.UserId, owner.data.id)
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.UserId, 'number')
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('GET existing recycle is forbidden without authentication', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
    assert.equal(res.status, 401)
  })

  void it('GET recycle of another user returns no rows', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
      .set('Authorization', 'Bearer ' + otherToken)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET recycle with a non-integer id is rejected', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + encodeURIComponent('[1,2]'))
      .set('Authorization', 'Bearer ' + otherToken)
    assert.equal(res.status, 400)
    assert.equal(res.body.data.err, 'Invalid recycle id.')
  })

  void it('PUT update existing recycle is forbidden', async () => {
    const res = await request(app)
      .put('/api/Recycles/1')
      .set(authHeader)
      .send({
        quantity: 100000
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing recycle is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Recycles/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
