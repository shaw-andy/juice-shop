/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomBytes } from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { AddressModel } from '../../models/address'

let app: Express

function placeholderPassword () {
  return `placeholder-${randomBytes(18).toString('hex')}`
}

function authHeader (token: string) {
  return {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
}

async function customer () {
  const email = `customer-${randomBytes(8).toString('hex')}@example.test`
  const password = placeholderPassword()
  await register(app, { email, password })
  const { token } = await login(app, { email, password })
  return { header: authHeader(token) }
}

async function createAddress (header: { Authorization: string, 'content-type': string }, fields: Record<string, string>) {
  const res = await request(app).post('/api/Addresss').set(header).send(fields)
  assert.equal(res.status, 201)
  return res.body.data
}

function snapshot (address: {
  id: number
  UserId: number
  fullName: string
  mobileNum: number
  zipCode: string
  streetAddress: string
  city: string
  state: string | null
  country: string
  updatedAt: Date | string
}) {
  return {
    id: address.id,
    UserId: address.UserId,
    fullName: address.fullName,
    mobileNum: Number(address.mobileNum),
    zipCode: address.zipCode,
    streetAddress: address.streetAddress,
    city: address.city,
    state: address.state,
    country: address.country,
    updatedAt: new Date(address.updatedAt).toISOString()
  }
}

async function stored (id: number) {
  const row = await AddressModel.findByPk(id)
  assert.ok(row)
  return snapshot(row)
}

function expectedStatus (status: number) {
  return [400, 403, 404].includes(status) ? status : 400
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('PUT /api/Addresss/:id ownership', () => {
  void it('does not reveal or overwrite another customer address', async () => {
    const victim = await customer()
    const attacker = await customer()
    const victimAddress = await createAddress(victim.header, {
      fullName: 'Victim Customer',
      mobileNum: '9800000001',
      zipCode: 'NX 101',
      streetAddress: 'Original Street 1',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const attackerAddress = await createAddress(attacker.header, {
      fullName: 'Attacker Customer',
      mobileNum: '9800000002',
      zipCode: 'NX 102',
      streetAddress: 'Attacker Street 1',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const beforeVictim = await stored(victimAddress.id)
    const beforeAttacker = await stored(attackerAddress.id)

    const res = await request(app)
      .put('/api/Addresss/' + victimAddress.id)
      .set(attacker.header)
      .send({ streetAddress: 'Replaced Street 1' })

    const body = JSON.stringify(res.body)
    assert.deepEqual({
      status: res.status,
      leakedName: body.includes(beforeVictim.fullName),
      leakedPhone: body.includes(String(beforeVictim.mobileNum)),
      victim: await stored(victimAddress.id),
      attacker: await stored(attackerAddress.id)
    }, {
      status: expectedStatus(res.status),
      leakedName: false,
      leakedPhone: false,
      victim: beforeVictim,
      attacker: beforeAttacker
    })

    const victimRead = await request(app)
      .get('/api/Addresss/' + victimAddress.id)
      .set(victim.header)
    assert.equal(victimRead.status, 200)
    assert.equal(victimRead.body.data.streetAddress, beforeVictim.streetAddress)
    assert.equal(victimRead.body.data.fullName, beforeVictim.fullName)
    assert.equal(Number(victimRead.body.data.mobileNum), beforeVictim.mobileNum)
    assert.equal(victimRead.body.data.UserId, beforeVictim.UserId)
  })

  void it('does not apply an authorized address id to a different address row', async () => {
    const victim = await customer()
    const attacker = await customer()
    const urlAddress = await createAddress(victim.header, {
      fullName: 'Url Target',
      mobileNum: '9800000003',
      zipCode: 'NX 103',
      streetAddress: 'Url Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const bodyAddress = await createAddress(victim.header, {
      fullName: 'Body Target',
      mobileNum: '9800000004',
      zipCode: 'NX 104',
      streetAddress: 'Body Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const attackerAddress = await createAddress(attacker.header, {
      fullName: 'Attacker Own',
      mobileNum: '9800000005',
      zipCode: 'NX 105',
      streetAddress: 'Own Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const beforeUrl = await stored(urlAddress.id)
    const beforeBody = await stored(bodyAddress.id)
    const beforeAttacker = await stored(attackerAddress.id)

    const res = await request(app)
      .put('/api/Addresss/' + urlAddress.id)
      .set(attacker.header)
      .send({
        id: bodyAddress.id,
        UserId: urlAddress.UserId,
        streetAddress: 'Switched Street'
      })

    const body = JSON.stringify(res.body)
    assert.deepEqual({
      status: res.status,
      leakedUrlName: body.includes(beforeUrl.fullName),
      leakedBodyName: body.includes(beforeBody.fullName),
      leakedUrlPhone: body.includes(String(beforeUrl.mobileNum)),
      leakedBodyPhone: body.includes(String(beforeBody.mobileNum)),
      urlRow: await stored(urlAddress.id),
      bodyRow: await stored(bodyAddress.id),
      attackerRow: await stored(attackerAddress.id)
    }, {
      status: expectedStatus(res.status),
      leakedUrlName: false,
      leakedBodyName: false,
      leakedUrlPhone: false,
      leakedBodyPhone: false,
      urlRow: beforeUrl,
      bodyRow: beforeBody,
      attackerRow: beforeAttacker
    })
  })

  void it('still updates an address the caller owns', async () => {
    const owner = await customer()
    const other = await customer()
    const owned = await createAddress(owner.header, {
      fullName: 'Owner Customer',
      mobileNum: '9800000006',
      zipCode: 'NX 106',
      streetAddress: 'Owner Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const otherAddress = await createAddress(other.header, {
      fullName: 'Other Customer',
      mobileNum: '9800000007',
      zipCode: 'NX 107',
      streetAddress: 'Other Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    const beforeOther = await stored(otherAddress.id)

    const res = await request(app)
      .put('/api/Addresss/' + owned.id)
      .set(owner.header)
      .send({ streetAddress: 'Updated Owner Street' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.streetAddress, 'Updated Owner Street')
    assert.equal(res.body.data.fullName, 'Owner Customer')
    assert.equal(res.body.data.UserId, owned.UserId)
    const afterOwned = await stored(owned.id)
    assert.equal(afterOwned.streetAddress, 'Updated Owner Street')
    assert.equal(afterOwned.UserId, owned.UserId)
    assert.equal(afterOwned.fullName, 'Owner Customer')
    assert.deepEqual(await stored(otherAddress.id), beforeOther)
  })
})
