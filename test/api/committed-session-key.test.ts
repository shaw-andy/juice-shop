/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import request from 'supertest'
import config from 'config'
import jwt from 'jsonwebtoken'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import { AddressModel } from '../../models/address'
import { ordersCollection } from '../../data/mongodb'

const skipDirs = new Set(['node_modules', 'frontend', '.git', 'build', 'dist', 'coverage', 'logs', 'test'])

let app: Express
let admin: UserModel
let customer: UserModel
let adminStreet: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const domain = config.get<string>('application.domain')
  const adminUser = await UserModel.findOne({ where: { email: 'admin@' + domain } })
  const customerUser = await UserModel.findOne({ where: { email: 'jim@' + domain } })
  assert.ok(adminUser)
  assert.ok(customerUser)
  admin = adminUser
  customer = customerUser
  const address = await AddressModel.findOne({ where: { UserId: admin.id } })
  assert.ok(address?.streetAddress)
  adminStreet = address.streetAddress
}, { timeout: 60000 })

function interpretPemEscapes (raw: string) {
  return raw.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n').replace(/\\r/g, '\r')
}

function committedPrivateKeys () {
  const found = new Set<string>()
  const visit = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (skipDirs.has(entry.name)) continue
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        visit(full)
      } else if (entry.isFile()) {
        let text: string
        try {
          text = fs.readFileSync(full, 'utf8')
        } catch {
          continue
        }
        const matches = text.match(/-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g) ?? []
        for (const match of matches) {
          const pem = interpretPemEscapes(match)
          try {
            crypto.createPrivateKey(pem)
          } catch {
            continue
          }
          found.add(pem)
        }
      }
    }
  }
  visit(process.cwd())
  return [...found]
}

function signSession (privateKey: string, data: Record<string, unknown>) {
  return jwt.sign({ data: { ...data } }, privateKey, { algorithm: 'RS256' })
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function deluxeMac (privateKey: string, email: string) {
  return crypto.createHmac('sha256', privateKey).update(email + 'deluxe').digest('hex')
}

function orderSnapshot (orders: Array<{ orderId?: string, delivered?: boolean }>) {
  return orders
    .map((order) => ({ orderId: order.orderId, delivered: order.delivered }))
    .sort((a, b) => String(a.orderId).localeCompare(String(b.orderId)))
}

void describe('sessions signed with a private key committed in the repository', () => {
  void it('rejects an RS256 session signed by an unrelated key', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()
    const token = signSession(pem, { id: admin.id, email: admin.email, role: 'accounting' })
    const res = await request(app)
      .get('/rest/order-history/orders')
      .set(bearer(token))
    assert.notEqual(res.status, 200)
    assert.equal(JSON.stringify(res.body).includes(admin.email.replace(/[aeiou]/gi, '*')), false)
  })

  void it('does not let a committed key read every customer order', async () => {
    const starred = admin.email.replace(/[aeiou]/gi, '*')
    for (const privateKey of committedPrivateKeys()) {
      const token = signSession(privateKey, { id: customer.id, email: customer.email, role: 'accounting' })
      const res = await request(app)
        .get('/rest/order-history/orders')
        .set(bearer(token))
      assert.notEqual(res.status, 200)
      assert.equal(JSON.stringify(res.body).includes(starred), false)
    }
  })

  void it('does not let a committed key change delivery status', async () => {
    const before = orderSnapshot(await ordersCollection.find())
    assert.ok(before.length > 0)
    const target = (await ordersCollection.find())[0]
    const responses = []
    for (const privateKey of committedPrivateKeys()) {
      const token = signSession(privateKey, { id: customer.id, email: customer.email, role: 'accounting' })
      responses.push(await request(app)
        .put('/rest/order-history/' + String(target._id) + '/delivery-status')
        .set(bearer(token))
        .send({ deliveryStatus: target.delivered }))
    }
    assert.deepEqual(orderSnapshot(await ordersCollection.find()), before)
    for (const res of responses) {
      assert.notEqual(res.status, 200)
    }
  })

  void it('does not let a committed key list user profiles', async () => {
    for (const privateKey of committedPrivateKeys()) {
      const token = signSession(privateKey, { id: customer.id, email: customer.email, role: 'admin' })
      const list = await request(app).get('/api/Users').set(bearer(token))
      const one = await request(app).get('/api/Users/' + String(admin.id)).set(bearer(token))
      const details = await request(app).get('/rest/user/authentication-details').set(bearer(token))
      const statuses = [list.status, one.status, details.status]
      assert.equal(statuses.every((status) => status !== 200), true, 'profile routes returned ' + statuses.join(','))
      for (const res of [list, one, details]) {
        const body = JSON.stringify(res.body)
        assert.equal(body.includes(customer.email), false)
        assert.equal(body.includes(admin.email), false)
      }
    }
  })

  void it('does not let a committed key read another customer basket', async () => {
    for (const privateKey of committedPrivateKeys()) {
      const token = signSession(privateKey, { id: customer.id, email: customer.email, role: 'customer' })
      const res = await request(app).get('/rest/basket/1').set(bearer(token))
      assert.notEqual(res.status, 200)
      assert.equal(JSON.stringify(res.body).includes('Apple Juice (1000ml)'), false)
    }
  })

  void it('does not let a committed key read another customer order history', async () => {
    const starred = admin.email.replace(/[aeiou]/gi, '*')
    for (const privateKey of committedPrivateKeys()) {
      const token = signSession(privateKey, { id: admin.id, email: admin.email, role: 'customer' })
      const orders = await request(app).get('/rest/order-history').set(bearer(token))
      assert.notEqual(orders.status, 200)
      assert.equal(JSON.stringify(orders.body).includes(starred), false)
    }
  })

  void it('does not let a committed key read another customer address or wallet', async () => {
    for (const privateKey of committedPrivateKeys()) {
      const asAdmin = signSession(privateKey, { id: admin.id, email: admin.email, role: 'customer' })
      const asCustomer = signSession(privateKey, { id: customer.id, email: customer.email, role: 'customer' })
      const addresses = await request(app).get('/api/Addresss').set(bearer(asAdmin))
      const wallet = await request(app).get('/rest/wallet/balance').set(bearer(asCustomer))
      assert.equal(addresses.status !== 200 && wallet.status !== 200, true, 'address and wallet returned ' + addresses.status + ',' + wallet.status)
      assert.equal(JSON.stringify(addresses.body).includes(adminStreet), false)
      assert.equal(typeof wallet.body?.data, 'number', false)
    }
  })

  void it('does not treat a committed key as customer membership', async () => {
    for (const privateKey of committedPrivateKeys()) {
      const customerToken = signSession(privateKey, { id: customer.id, email: customer.email, role: 'customer' })
      const asCustomer = await request(app).get('/rest/deluxe-membership').set(bearer(customerToken))
      assert.equal(JSON.stringify(asCustomer.body).includes('membershipCost'), false)
    }
  })

  void it('does not treat a committed key as deluxe membership', async () => {
    for (const privateKey of committedPrivateKeys()) {
      const deluxeToken = signSession(privateKey, {
        id: customer.id,
        email: customer.email,
        role: 'deluxe',
        deluxeToken: deluxeMac(privateKey, customer.email)
      })
      const deluxe = await request(app).get('/rest/deluxe-membership').set(bearer(deluxeToken))
      assert.equal(JSON.stringify(deluxe.body).includes('already a deluxe member'), false)
    }
  })

  void it('does not let a committed key identify itself from a cookie', async () => {
    for (const privateKey of committedPrivateKeys()) {
      const token = signSession(privateKey, { id: admin.id, email: admin.email, role: 'admin', username: admin.username })
      const whoami = await request(app).get('/rest/user/whoami').set('Cookie', 'token=' + token)
      assert.notEqual(whoami.body?.user?.id, admin.id)
      assert.notEqual(whoami.body?.user?.email, admin.email)
    }
  })

  void it('does not let a committed key change another user profile', async () => {
    const originalName = admin.username
    try {
      for (const privateKey of committedPrivateKeys()) {
        const token = signSession(privateKey, { id: admin.id, email: admin.email, role: 'admin', username: admin.username })
        const profile = await request(app)
          .post('/profile')
          .set('Cookie', 'token=' + token)
          .set('content-type', 'application/json')
          .send({ username: 'forged-profile-name' })
        const renamed = await UserModel.findByPk(admin.id)
        assert.equal(renamed?.username, originalName)
        assert.notEqual(profile.status, 302)
      }
    } finally {
      await UserModel.update({ username: originalName }, { where: { id: admin.id } })
    }
  })
})
