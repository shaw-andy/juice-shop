/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { performance } from 'node:perf_hooks'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const PLACEHOLDER_PASSWORD = 'placeholder-password'
// Above Buffer.poolSize >>> 1 (4096), so Buffer.from takes the same
// array-like FastBuffer path as a hundreds-of-megabytes length.
const ATTACK_LENGTH = 40_000_000
const MAX_MS = 700
const ftpDir = path.resolve('ftp')

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function openCustomer () {
  const email = `coupon-buyer-${Math.random().toString(16).slice(2)}@example.test`
  await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  return authentication as { token: string, bid: number }
}

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function checkout (token: string, bid: number, body: unknown) {
  const before = new Set(fs.readdirSync(ftpDir))
  const started = performance.now()
  let maxGap = 0
  let last = started
  const timer = setInterval(() => {
    const now = performance.now()
    maxGap = Math.max(maxGap, now - last)
    last = now
  }, 20)
  try {
    const res = await request(app)
      .post(`/rest/basket/${bid}/checkout`)
      .set(authHeader(token))
      .send(body)
    const elapsed = performance.now() - started
    const created = fs.readdirSync(ftpDir).filter((name) => !before.has(name))
    return { res, elapsed, maxGap, created }
  } finally {
    clearInterval(timer)
    for (const name of fs.readdirSync(ftpDir)) {
      if (!before.has(name)) fs.unlinkSync(path.join(ftpDir, name))
    }
  }
}

void describe('checkout couponData', () => {
  void it('rejects couponData that is not a string before allocating or writing an order', async (t) => {
    const { token, bid } = await openCustomer()
    const basket = await request(app)
      .get(`/rest/basket/${bid}`)
      .set(authHeader(token))
    assert.equal(basket.status, 200)
    assert.equal(basket.body.data.coupon ?? null, null)

    await t.test('array-like object with a large length does not block checkout', async () => {
      const { res, elapsed, maxGap, created } = await checkout(token, bid, {
        couponData: { length: ATTACK_LENGTH }
      })
      assert.equal(res.status, 400, `status ${res.status} elapsed ${elapsed.toFixed(0)}ms gap ${maxGap.toFixed(0)}ms files ${created.join(',')}`)
      assert.equal(res.body.orderConfirmation, undefined)
      assert.ok(elapsed < MAX_MS, `checkout blocked for ${elapsed.toFixed(0)}ms`)
      assert.ok(maxGap < MAX_MS, `event loop stalled for ${maxGap.toFixed(0)}ms`)
      assert.deepEqual(created, [])
    })

    await t.test('array-like object under the buffer pool threshold is rejected', async () => {
      const { res, created } = await checkout(token, bid, {
        couponData: { length: 3, 0: 65, 1: 66, 2: 67 }
      })
      assert.equal(res.status, 400)
      assert.equal(res.body.orderConfirmation, undefined)
      assert.deepEqual(created, [])
    })

    await t.test('non-string couponData is rejected', async () => {
      for (const couponData of [1, true, ['A']]) {
        const { res, created } = await checkout(token, bid, { couponData })
        assert.equal(res.status, 400, `couponData ${JSON.stringify(couponData)} status ${res.status}`)
        assert.equal(res.body.orderConfirmation, undefined)
        assert.deepEqual(created, [])
      }
    })
  }, { timeout: 60000 })

  void it('still accepts a short base64 coupon string', async () => {
    const { token, bid } = await openCustomer()
    const validOn = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()
    const couponData = Buffer.from(`WMNSDY2019-${validOn}`).toString('base64')
    const { res, created } = await checkout(token, bid, { couponData })
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.orderConfirmation, 'string')
    assert.ok(created.some((name) => name.startsWith('order_') && name.endsWith('.pdf')))
  })
})
