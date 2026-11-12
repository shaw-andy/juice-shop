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
import { RecycleModel } from '../../models/recycle'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

interface RecycleRow {
  id: number
  UserId: number
  AddressId: number
  quantity: number
  isPickup: boolean
  date: string
}

let app: Express
let own: RecycleRow
let other: RecycleRow
let ownToken: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const recycles = await RecycleModel.findAll({ order: [['id', 'ASC']] })
  const rows = recycles.map(row => row.toJSON() as RecycleRow)
  const first = rows[0]
  const second = rows.find(row => row.UserId !== first.UserId)
  assert.ok(first)
  assert.ok(second)
  own = first
  other = second
  const user = await UserModel.findByPk(own.UserId, { attributes: ['id', 'email', 'role'] })
  assert.ok(user)
  const authenticatedUser = { data: { id: user.id, email: user.email, role: user.role } }
  ownToken = security.authorize(authenticatedUser)
  security.authenticatedUsers.put(ownToken, authenticatedUser as any)
}, { timeout: 60000 })

function recycleRows (body: unknown): RecycleRow[] {
  const found: RecycleRow[] = []
  const visit = (value: unknown) => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (value !== null && typeof value === 'object') {
      const record = value as Record<string, unknown>
      if ('UserId' in record && 'AddressId' in record && 'quantity' in record && 'id' in record) {
        found.push(record as unknown as RecycleRow)
      }
      for (const child of Object.values(record)) visit(child)
    }
  }
  visit(body)
  return found
}

function responseText (res: Response) {
  return `${JSON.stringify(res.body)}${res.text ?? ''}`
}

function assertDoesNotLeak (res: Response, row: RecycleRow) {
  const leaked = recycleRows(res.body).filter(found =>
    found.id === row.id ||
    (found.UserId === row.UserId && found.AddressId === row.AddressId && found.quantity === row.quantity)
  )
  assert.equal(leaked.length, 0, responseText(res))
  const text = responseText(res)
  assert.equal(text.includes(`"quantity":${row.quantity}`), false, text)
  assert.equal(text.includes(`"AddressId":${row.AddressId}`), false, text)
}

void describe('GET /api/Recycles/:id', () => {
  void it('does not return a recycle row without authentication', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${own.id}`)
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assertDoesNotLeak(res, own)
  })

  void it('does not return the next sequential recycle row without authentication', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${other.id}`)
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assertDoesNotLeak(res, other)
  })

  void it('does not return a recycle row for a case-variant path without authentication', async () => {
    const res = await request(app)
      .get(`/api/recycles/${own.id}`)
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assertDoesNotLeak(res, own)
  })

  void it('does not return a recycle row for a trailing slash without authentication', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${own.id}/`)
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assertDoesNotLeak(res, own)
  })

  void it('does not answer an unknown recycle id without authentication', async () => {
    const res = await request(app)
      .get('/api/Recycles/99999')
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assert.equal(recycleRows(res.body).length, 0)
  })

  void it('does not treat a JSON array id as a list of recycle rows without authentication', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + encodeURIComponent(JSON.stringify([own.id, other.id])))
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assertDoesNotLeak(res, own)
    assertDoesNotLeak(res, other)
  })

  void it('does not return recycle rows when an authenticated caller sends a JSON array id', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + encodeURIComponent(JSON.stringify([own.id, other.id])))
      .set('Authorization', 'Bearer ' + ownToken)
      .set('Accept', 'application/json')
    assert.equal(recycleRows(res.body).length, 0, responseText(res))
    assertDoesNotLeak(res, own)
    assertDoesNotLeak(res, other)
  })

  void it('does not treat a JSON object id as a recycle query', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + encodeURIComponent(JSON.stringify({ gt: 0 })))
      .set('Accept', 'application/json')
    assert.equal(res.status, 401, responseText(res))
    assertDoesNotLeak(res, own)
    assertDoesNotLeak(res, other)
  })

  void it('does not return another user recycle to an authenticated caller', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${other.id}`)
      .query({ UserId: other.UserId })
      .set('Authorization', 'Bearer ' + ownToken)
      .set('Accept', 'application/json')
    assertDoesNotLeak(res, other)
    assert.equal(recycleRows(res.body).some(row => row.UserId !== own.UserId), false, responseText(res))
  })

  void it('returns only the authenticated caller recycle row', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${own.id}`)
      .set('Authorization', 'Bearer ' + ownToken)
      .set('Accept', 'application/json')
    assert.equal(res.status, 200, responseText(res))
    const rows = recycleRows(res.body)
    assert.equal(rows.length, 1, responseText(res))
    assert.equal(rows[0].id, own.id)
    assert.equal(rows[0].UserId, own.UserId)
    assert.equal(rows[0].AddressId, own.AddressId)
    assert.equal(rows[0].quantity, own.quantity)
    assert.equal(rows[0].isPickup, own.isPickup)
    assert.equal(new Date(rows[0].date).toISOString(), new Date(own.date).toISOString())
    assertDoesNotLeak(res, other)
  })
})

void describe('GET /api/Recycles', () => {
  void it('does not list recycle rows', async () => {
    const res = await request(app)
      .get('/api/Recycles')
      .set('Accept', 'application/json')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
    assert.equal(recycleRows(res.body).length, 0)
    assertDoesNotLeak(res, own)
    assertDoesNotLeak(res, other)
  })
})
