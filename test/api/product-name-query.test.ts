/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const maliciousName = 'Juice&url=https://attacker.example&'
const jsonHeader = { 'content-type': 'application/json' }
const i18nDir = path.resolve('i18n')
const i18nBackup = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-i18n-'))

let app: Express

function snapshotLocales () {
  for (const file of fs.readdirSync(i18nDir)) {
    const source = path.join(i18nDir, file)
    if (fs.statSync(source).isFile()) {
      fs.copyFileSync(source, path.join(i18nBackup, file))
    }
  }
}

function restoreLocales () {
  for (const file of fs.readdirSync(i18nDir)) {
    const target = path.join(i18nDir, file)
    if (!fs.statSync(target).isFile()) {
      continue
    }
    const backup = path.join(i18nBackup, file)
    if (fs.existsSync(backup)) {
      fs.copyFileSync(backup, target)
    } else {
      fs.rmSync(target)
    }
  }
}

before(async () => {
  snapshotLocales()
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  restoreLocales()
})

void describe('product name query characters', () => {
  void it('does not keep an unauthenticated query-bearing product name on the order', async () => {
    const update = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ name: maliciousName })
    assert.ok(update.status === 200 || update.status === 400, `unexpected status ${update.status}`)

    const saved = await request(app).get('/api/Products/1')
    assert.equal(saved.status, 200)
    const savedName = String(saved.body.data.name)
    const problems: string[] = []
    if (/[&?#]/.test(savedName)) {
      problems.push(`product name still contains a query delimiter: ${savedName}`)
    }

    await register(app, {
      email: 'tweet-link-customer@juice-sh.op',
      password: 'placeholder'
    })
    const { token, bid } = await login(app, {
      email: 'tweet-link-customer@juice-sh.op',
      password: 'placeholder'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const item = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 1, quantity: 1 })
    assert.equal(item.status, 200)

    const checkout = await request(app)
      .post('/rest/basket/' + bid + '/checkout')
      .set(authHeader)
      .send({ orderDetails: { paymentId: 'card', addressId: 1 } })
    assert.equal(checkout.status, 200)
    const orderId = checkout.body.orderConfirmation
    assert.equal(typeof orderId, 'string')

    const tracked = await request(app).get('/rest/track-order/' + orderId)
    assert.equal(tracked.status, 200)
    const products = tracked.body.data[0].products
    assert.ok(Array.isArray(products) && products.length > 0)
    for (const product of products) {
      const name = String(product.name)
      if (/[&?#]/.test(name)) {
        problems.push(`order copied a query delimiter: ${name}`)
      }
    }
    assert.deepEqual(problems, [])
  })
})
