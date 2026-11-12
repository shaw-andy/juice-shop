/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import config from 'config'
import jws from 'jws'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'

type ForgedAlgorithm = 'none' | 'None' | 'HS256' | 'HS384' | 'HS512'

let app: Express
let publicKey = ''
let adminId = 0
let customerA = { id: 0, email: '', role: '' }
let customerB = { id: 0, email: '', role: '' }

function forgedToken (algorithm: ForgedAlgorithm, data: Record<string, unknown>): string {
  return jws.sign({
    header: { alg: algorithm, typ: 'JWT' },
    payload: { data },
    secret: algorithm.toLowerCase() === 'none' ? 'placeholder' : publicKey
  })
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function setCookieContains (res: Response, token: string) {
  const raw = res.headers['set-cookie']
  const serialized = Array.isArray(raw) ? raw.join('\n') : String(raw ?? '')
  return serialized.includes(token)
}

function captureSessions () {
  return {
    keys: new Set(Object.keys(security.authenticatedUsers.tokenMap)),
    ids: { ...security.authenticatedUsers.idMap }
  }
}

function assertSessionUnchanged (before: ReturnType<typeof captureSessions>, token: string) {
  assert.equal(security.authenticatedUsers.get(token), undefined)
  const added = Object.keys(security.authenticatedUsers.tokenMap).filter((key) => !before.keys.has(key))
  assert.deepEqual(added, [])
  assert.deepEqual(security.authenticatedUsers.idMap, before.ids)
}

const algorithms: ForgedAlgorithm[] = ['none', 'None', 'HS256', 'HS384', 'HS512']
const domain = () => config.get<string>('application.domain')

void describe('forged JWT sessions', { concurrency: false }, () => {
  before(async () => {
    const result = await createTestApp()
    app = result.app

    const keyRes = await request(app).get('/encryptionkeys/jwt.pub')
    assert.equal(keyRes.status, 200)
    assert.equal(keyRes.text === security.publicKey, true)
    publicKey = keyRes.text

    const users = await request(app).get('/api/Users').set(bearer(security.authorize()))
    assert.equal(users.status, 200)
    const rows = users.body.data as Array<{ id: number, email: string, role: string }>
    const admin = rows.find((user) => user.role === security.roles.admin)
    const customers = rows.filter((user) => user.role === security.roles.customer)
    assert.ok(admin)
    assert.ok(customers.length >= 2)
    adminId = admin.id
    customerA = customers[0]
    customerB = customers[1]
  }, { timeout: 60000 })

  void it('still accepts an RS256 session from authorize', async () => {
    const token = security.authorize({ data: { id: adminId, role: security.roles.admin } })
    const res = await request(app).get('/api/Users').set(bearer(token))
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
  })

  for (const algorithm of algorithms) {
    void it('rejects a ' + algorithm + ' bearer on protected routes and does not record the session', async () => {
      const email = algorithm + '-admin@' + domain()
      const token = forgedToken(algorithm, { id: adminId, email, role: security.roles.admin })
      const before = captureSessions()

      const users = await request(app).get('/api/Users').set(bearer(token))
      assert.equal(users.status, 401)
      assert.equal(users.body?.data, undefined)
      assert.equal(setCookieContains(users, token), false)

      const complaints = await request(app).get('/api/Complaints').set(bearer(token))
      assert.equal(complaints.status, 401)

      const details = await request(app).get('/rest/user/authentication-details').set(bearer(token))
      assert.equal(details.status, 401)
      assert.equal(details.body?.data, undefined)

      const basket = await request(app).get('/rest/basket/1').set(bearer(token))
      assert.equal(basket.status, 401)

      const wallet = await request(app).get('/rest/wallet/balance').set(bearer(token))
      assert.equal(wallet.status, 401)
      assert.notEqual(wallet.body?.status, 'success')

      const history = await request(app).get('/rest/order-history').set(bearer(token))
      assert.notEqual(history.status, 200)
      assert.notEqual(history.body?.status, 'success')

      const twoFactor = await request(app).get('/rest/2fa/status').set(bearer(token))
      assert.equal(twoFactor.status, 401)

      assertSessionUnchanged(before, token)
      assert.equal(setCookieContains(twoFactor, token), false)
    })

    void it('does not create a product for a ' + algorithm + ' bearer', async () => {
      const name = 'forged-' + algorithm + '-juice'
      const before = await request(app).get('/api/Products')
      const created = await request(app)
        .post('/api/Products')
        .set(bearer(forgedToken(algorithm, { id: adminId, email: 'product-' + algorithm + '@' + domain(), role: security.roles.admin })))
        .send({ name, description: 'not a product', price: 0.01, image: 'forged.jpg' })
      const after = await request(app).get('/api/Products')
      assert.equal(created.status, 401)
      assert.equal(after.body.data.some((product: { name: string }) => product.name === name), false)
      assert.equal(after.body.data.length, before.body.data.length)
    })

    void it('does not treat a ' + algorithm + ' token as an accounting or customer session', async () => {
      const accountingEmail = 'accountant-' + algorithm + '@' + domain()
      const accounting = forgedToken(algorithm, { id: adminId, email: accountingEmail, role: security.roles.accounting })
      const before = captureSessions()
      const orders = await request(app).get('/rest/order-history/orders').set(bearer(accounting))
      assert.equal(orders.status, 403)
      assert.notEqual(orders.body?.status, 'success')
      assertSessionUnchanged(before, accounting)

      const customer = forgedToken(algorithm, { id: customerA.id, email: customerA.email, role: security.roles.customer })
      const membershipBefore = captureSessions()
      const membership = await request(app).get('/rest/deluxe-membership').set(bearer(customer))
      assert.equal(membership.status, 400)
      assert.equal(membership.body.error, 'You are not eligible for deluxe membership!')
      assertSessionUnchanged(membershipBefore, customer)
    })

    void it('does not treat a ' + algorithm + ' token as deluxe when deluxeToken was produced by the server helper', async () => {
      const email = 'forged-deluxe-' + algorithm + '@' + domain()
      const token = forgedToken(algorithm, {
        id: adminId,
        email,
        role: security.roles.deluxe,
        deluxeToken: security.deluxeToken(email)
      })
      const before = captureSessions()
      const membership = await request(app).get('/rest/deluxe-membership').set(bearer(token))
      assert.equal(membership.status, 400)
      assert.equal(membership.body.error, 'You are not eligible for deluxe membership!')
      assertSessionUnchanged(before, token)
    })

    void it('does not return a ' + algorithm + ' cookie identity from whoami or keep it in the session map', async () => {
      const email = 'cookie-' + algorithm + '@' + domain()
      const token = forgedToken(algorithm, { id: adminId, email, role: security.roles.admin })
      const before = captureSessions()
      const whoami = await request(app).get('/rest/user/whoami').set('Cookie', 'token=' + token)
      assert.notEqual(whoami.body?.user?.email, email)
      assert.notEqual(whoami.body?.user?.id, adminId)
      assert.equal(setCookieContains(whoami, token), false)
      assertSessionUnchanged(before, token)
    })
  }

  void it('does not authorize one forged token and act on another', async () => {
    const cookieEmail = 'split-cookie@' + domain()
    const headerEmail = 'split-header@' + domain()
    const cookieToken = forgedToken('none', { id: adminId, email: cookieEmail, role: security.roles.admin })
    const headerToken = forgedToken('HS256', { id: customerA.id, email: headerEmail, role: security.roles.admin })
    const before = captureSessions()
    const res = await request(app)
      .get('/api/Users')
      .set('Cookie', 'token=' + cookieToken)
      .set(bearer(headerToken))
    assert.equal(res.status, 401)
    assert.equal(res.body?.data, undefined)
    assert.equal(setCookieContains(res, cookieToken), false)
    assert.equal(setCookieContains(res, headerToken), false)
    assertSessionUnchanged(before, cookieToken)
    assertSessionUnchanged(before, headerToken)
  })

  void it('does not upgrade the token user or the body user id for an unsigned deluxe purchase', async () => {
    const solvedBefore = challenges.freeDeluxeChallenge.solved === true
    const token = forgedToken('none', { id: customerA.id, email: customerA.email, role: security.roles.customer })
    const before = captureSessions()
    const rolesBefore = await request(app).get('/api/Users').set(bearer(security.authorize()))
    const upgraded = await request(app)
      .post('/rest/deluxe-membership')
      .set(bearer(token))
      .send({ UserId: customerB.id, paymentMode: 'invoice' })
    assert.equal(upgraded.status, 401)
    assert.equal(challenges.freeDeluxeChallenge.solved === true, solvedBefore)
    assertSessionUnchanged(before, token)

    const rolesAfter = await request(app).get('/api/Users').set(bearer(security.authorize()))
    for (const id of [customerA.id, customerB.id]) {
      const previous = rolesBefore.body.data.find((user: { id: number }) => user.id === id)
      const current = rolesAfter.body.data.find((user: { id: number }) => user.id === id)
      assert.equal(current.role, previous.role)
    }
  })

  void it('does not upgrade either user for an HMAC token signed with the public key', async () => {
    const solvedBefore = challenges.freeDeluxeChallenge.solved === true
    const token = forgedToken('HS256', { id: customerB.id, email: customerB.email, role: security.roles.customer })
    const rolesBefore = await request(app).get('/api/Users').set(bearer(security.authorize()))
    const upgraded = await request(app)
      .post('/rest/deluxe-membership')
      .set(bearer(token))
      .send({ UserId: customerA.id, paymentMode: 'invoice' })
    assert.equal(upgraded.status, 401)
    assert.equal(challenges.freeDeluxeChallenge.solved === true, solvedBefore)

    const rolesAfter = await request(app).get('/api/Users').set(bearer(security.authorize()))
    for (const id of [customerA.id, customerB.id]) {
      const previous = rolesBefore.body.data.find((user: { id: number }) => user.id === id)
      const current = rolesAfter.body.data.find((user: { id: number }) => user.id === id)
      assert.equal(current.role, previous.role)
    }
  })

  void it('does not mark the unsigned or public-key HMAC challenges solved', async () => {
    assert.ok(challenges.jwtUnsignedChallenge)
    assert.ok(challenges.jwtForgedChallenge)
    const unsignedBefore = challenges.jwtUnsignedChallenge.solved === true
    const forgedBefore = challenges.jwtForgedChallenge.solved === true
    const unsigned = forgedToken('none', { id: adminId, email: 'jwtn3d@' + domain(), role: security.roles.admin })
    const hmac = forgedToken('HS256', { id: adminId, email: 'rsa_lord@' + domain(), role: security.roles.admin })
    const before = captureSessions()
    const unsignedRes = await request(app).get('/api/Users').set(bearer(unsigned))
    const hmacRes = await request(app).get('/api/Users').set(bearer(hmac))
    assert.equal(unsignedRes.status, 401)
    assert.equal(hmacRes.status, 401)
    assert.equal(challenges.jwtUnsignedChallenge.solved === true, unsignedBefore)
    assert.equal(challenges.jwtForgedChallenge.solved === true, forgedBefore)
    assertSessionUnchanged(before, unsigned)
    assertSessionUnchanged(before, hmac)
  })

  void it('does not let an unsigned token pass denyAll or delete a product', async () => {
    const products = await request(app).get('/api/Products')
    const target = products.body.data[products.body.data.length - 1]
    const token = forgedToken('none', { id: adminId, email: 'deny-none@' + domain(), role: security.roles.admin })
    const deleted = await request(app).delete('/api/Products/' + target.id).set(bearer(token))
    const after = await request(app).get('/api/Products/' + target.id)
    assert.equal(deleted.status, 401)
    assert.equal(after.status, 200)
    assert.equal(after.body.data.id, target.id)
    assert.equal(after.body.data.name, target.name)
  })

  void it('does not let a None token pass denyAll or delete a product', async () => {
    const products = await request(app).get('/api/Products')
    const target = products.body.data[0]
    const token = forgedToken('None', { id: adminId, email: 'deny-None@' + domain(), role: security.roles.admin })
    const deleted = await request(app).delete('/api/Products/' + target.id).set(bearer(token))
    const after = await request(app).get('/api/Products/' + target.id)
    assert.equal(deleted.status, 401)
    assert.equal(after.status, 200)
    assert.equal(after.body.data.id, target.id)
  })

  void it('does not let an HMAC token signed with the public key pass denyAll', async () => {
    const products = await request(app).get('/api/Products')
    const target = products.body.data[1]
    const token = forgedToken('HS256', { id: adminId, email: 'deny-hs@' + domain(), role: security.roles.admin })
    const deleted = await request(app).delete('/api/Products/' + target.id).set(bearer(token))
    const after = await request(app).get('/api/Products/' + target.id)
    assert.equal(deleted.status, 401)
    assert.equal(after.status, 200)
    assert.equal(after.body.data.id, target.id)
  })
})
