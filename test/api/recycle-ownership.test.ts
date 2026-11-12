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
import { AddressModel } from '../../models/address'
import { RecycleModel } from '../../models/recycle'
import * as security from '../../lib/insecurity'

const placeholderPassword = 'placeholder-password'
const pickupDate = '2030-01-15T12:00:00.000Z'
const jsonHeader = { 'content-type': 'application/json' }

let app: Express
let attacker: Customer
let victim: Customer

interface Customer {
  id: number
  token: string
  addressId: number
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  attacker = await createCustomer('recycle-attacker@example.test')
  victim = await createCustomer('recycle-victim@example.test')
  assert.notEqual(attacker.id, victim.id)
  assert.notEqual(attacker.addressId, victim.addressId)
}, { timeout: 60000 })

void describe('POST /api/Recycles ownership', () => {
  void it('stores the session user when the body names another user', async () => {
    await assertRecycleIsOwnedByCaller('/api/Recycles', {
      UserId: victim.id,
      AddressId: attacker.addressId,
      quantity: 20,
      isPickup: true,
      date: pickupDate
    })
  })

  void it('stores the session user when the body user id is a numeric string', async () => {
    await assertRecycleIsOwnedByCaller('/api/Recycles', {
      UserId: String(victim.id),
      AddressId: attacker.addressId,
      quantity: 21,
      isPickup: true,
      date: pickupDate
    })
  })

  void it('stores the session user for the trailing-slash create used by the recycle form', async () => {
    await assertRecycleIsOwnedByCaller('/api/Recycles/', {
      UserId: victim.id,
      AddressId: attacker.addressId,
      quantity: 22,
      isPickup: true,
      date: pickupDate
    })
  })

  void it('stores the session user when the body is form-encoded', async () => {
    await assertRecycleIsOwnedByCaller('/api/Recycles', {
      UserId: String(victim.id),
      AddressId: String(attacker.addressId),
      quantity: 25,
      isPickup: true,
      date: pickupDate
    }, 'application/x-www-form-urlencoded')
  })

  void it('rejects another customer address even if a different field names the caller address', async () => {
    await assertForeignAddressRejected({
      UserId: attacker.id,
      AddressId: String(victim.addressId),
      addressId: attacker.addressId,
      quantity: 23,
      isPickup: true,
      date: pickupDate
    })
  })

  void it('rejects a recycle filed under another user and that user address', async () => {
    const victimRowsBefore = await recyclesForUser(victim.id)
    await assertForeignAddressRejected({
      UserId: victim.id,
      AddressId: victim.addressId,
      quantity: 24,
      isPickup: true,
      date: pickupDate
    })
    assert.equal(await recyclesForUser(victim.id), victimRowsBefore)
  })
})

async function assertRecycleIsOwnedByCaller (path: string, body: Record<string, unknown>, contentType = 'application/json') {
  const victimRowsBefore = await recyclesForUser(victim.id)
  const res = await request(app)
    .post(path)
    .set({ ...authHeader(attacker.token), 'content-type': contentType })
    .send(body)

  assert.equal(res.status, 201)
  const createdId = res.body.data.id as number

  const listed = await request(app).get('/api/Recycles/' + createdId)
  assert.equal(listed.status, 200)
  const items = listed.body.data
  assert.ok(Array.isArray(items))
  const match = items.find((item: { id: number }) => item.id === createdId)
  assert.ok(match)
  assert.equal(Number(match.UserId), attacker.id)
  assert.equal(Number(match.AddressId), attacker.addressId)
  assert.equal(Number(match.quantity), body.quantity)
  assert.equal(match.isPickup, true)
  assert.equal(sameInstant(match.date, pickupDate), true)

  assert.equal(Number(res.body.data.UserId), attacker.id)
  assert.equal(Number(res.body.data.AddressId), attacker.addressId)
  assert.equal(Number(res.body.data.quantity), body.quantity)
  assert.equal(res.body.data.isPickup, true)
  assert.equal(sameInstant(res.body.data.date, pickupDate), true)

  const row = await RecycleModel.findByPk(createdId)
  assert.ok(row)
  assert.equal(Number(row.get('UserId')), attacker.id)
  assert.equal(Number(row.get('AddressId')), attacker.addressId)
  assert.equal(Number(row.get('quantity')), body.quantity)
  assert.equal(row.get('isPickup'), true)
  assert.equal(sameInstant(row.get('date'), pickupDate), true)
  assert.equal(await recyclesForUser(victim.id), victimRowsBefore)
}

async function assertForeignAddressRejected (body: Record<string, unknown>) {
  const before = await recycleCount()
  const addressRowsBefore = await recyclesForAddress(victim.addressId)
  const res = await request(app)
    .post('/api/Recycles')
    .set(authHeader(attacker.token))
    .send(body)

  assert.equal(await recycleCount(), before)
  assert.equal(await recyclesForAddress(victim.addressId), addressRowsBefore)
  assert.ok(res.status >= 400 && res.status < 500, `expected a client error, got ${res.status}`)
}

async function createCustomer (email: string): Promise<Customer> {
  const registered = await register(app, { email, password: placeholderPassword })
  assert.equal(registered.status, 201)
  assert.equal(registered.body.data.role, 'customer')
  const id = registered.body.data.id as number
  const { token } = await login(app, { email, password: placeholderPassword })
  const payload = security.decode(token)
  const sessionUser = typeof payload === 'string' ? JSON.parse(payload) : payload
  assert.equal(sessionUser.data.id, id)

  const address = await request(app)
    .post('/api/Addresss')
    .set(authHeader(token))
    .send({
      fullName: email,
      mobileNum: 1000001,
      zipCode: '10001',
      streetAddress: '1 Pickup Road',
      city: 'Town',
      country: 'US'
    })
  assert.equal(address.status, 201)
  const addressId = address.body.data.id as number
  const addressRow = await AddressModel.findByPk(addressId)
  assert.ok(addressRow)
  assert.equal(Number(addressRow.get('UserId')), id)
  return { id, token, addressId }
}

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, ...jsonHeader }
}

async function recycleCount () {
  return await RecycleModel.count()
}

async function recyclesForUser (userId: number) {
  return await RecycleModel.count({ where: { UserId: userId } })
}

async function recyclesForAddress (addressId: number) {
  return await RecycleModel.count({ where: { AddressId: addressId } })
}

function sameInstant (stored: unknown, sent: string) {
  const parsed = new Date(stored as string)
  if (Number.isNaN(parsed.getTime())) {
    return String(stored).includes(sent.slice(0, 10))
  }
  return parsed.toISOString() === new Date(sent).toISOString()
}
