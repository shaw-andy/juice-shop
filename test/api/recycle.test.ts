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
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
let customerHeader: Record<string, string>
let otherCustomerId: number
let ownAddressId: number
let foreignAddressId: number

async function registerCustomer (email: string) {
  const password = 'placeholder'
  const registered = await register(app, { email, password })
  const { token } = await login(app, { email, password })
  const header = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  const address = await request(app)
    .post('/api/Addresss')
    .set(header)
    .send({ fullName: 'Recycler', mobileNum: '9800000003', zipCode: '10001', streetAddress: 'Recycle Street', city: 'NYC', state: 'NY', country: 'US' })
  assert.equal(address.status, 201)
  return { header, id: registered.body.data.id as number, addressId: address.body.data.id as number }
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  const customer = await registerCustomer(`recycler-${Date.now()}@example.com`)
  const other = await registerCustomer(`other-recycler-${Date.now()}@example.com`)
  customerHeader = customer.header
  ownAddressId = customer.addressId
  otherCustomerId = other.id
  foreignAddressId = other.addressId
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(customerHeader)
      .send({
        quantity: 200,
        AddressId: String(ownAddressId),
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.AddressId, ownAddressId)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('POST new recycle records the signed-in user instead of a submitted UserId', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(customerHeader)
      .send({ quantity: 10, AddressId: ownAddressId, UserId: otherCustomerId, date: '2017-05-31' })
    assert.equal(res.status, 201)
    assert.notEqual(res.body.data.UserId, otherCustomerId)
  })

  void it('POST new recycle with an address of another user is rejected', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(customerHeader)
      .send({ quantity: 10, AddressId: foreignAddressId, UserId: otherCustomerId, date: '2017-05-31' })
    assert.equal(res.status, 400)
  })

  void it('POST new recycle with a list of address ids is rejected', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(customerHeader)
      .send({ quantity: 10, AddressId: [ownAddressId, foreignAddressId], date: '2017-05-31' })
    assert.equal(res.status, 400)
  })

  void it('POST new recycle without a registered session is rejected', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({ quantity: 10, AddressId: ownAddressId, date: '2017-05-31' })
    assert.equal(res.status, 401)
  })

  void it('Will prevent GET all recycles from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
  })

  void it('Will GET existing recycle from this endpoint', async () => {
    // First create a recycle so we can GET it
    await request(app)
      .post('/api/Recycles')
      .set(customerHeader)
      .send({
        quantity: 100,
        AddressId: ownAddressId,
        isPickup: false,
        date: '2017-06-01'
      })

    const res = await request(app)
      .get('/api/Recycles/1')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    for (const item of items) {
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
