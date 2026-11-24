/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as db from '../../data/mongodb'

// One account, and one client address, may place at most this many orders
// before further checkout calls are rejected. The limiter must use the
// authenticated user and the socket address. A client-supplied forwarding
// header must not start a new allowance.
const MAX_SUCCESSFUL_CHECKOUTS = 5

const jsonHeader = { 'content-type': 'application/json' }
const ftpDir = path.resolve('ftp')

let app: Express
let identitySequence = 0

interface Account {
  email: string
  password: string
  token: string
  bid: number
}

interface SideEffects {
  orderPdfWrites: string[]
  orderPdfDeletes: string[]
  orderInserts: number
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  for (const name of fs.readdirSync(ftpDir)) {
    if (name.startsWith('order_') && name.endsWith('.pdf')) {
      fs.rmSync(path.join(ftpDir, name), { force: true })
    }
  }
})

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function nextIdentity () {
  identitySequence += 1
  return {
    email: `checkout-limit-${identitySequence}@example.test`,
    password: 'test-password'
  }
}

async function openAccount (target: Express): Promise<Account> {
  const identity = nextIdentity()
  await register(target, identity)
  const authentication = await login(target, identity)
  return {
    email: identity.email,
    password: identity.password,
    token: authentication.token,
    bid: authentication.bid
  }
}

function orderPdfNames () {
  return fs.readdirSync(ftpDir)
    .filter((name) => name.startsWith('order_') && name.endsWith('.pdf'))
    .sort()
}

function isOrderPdf (filePath: fs.PathLike) {
  const resolved = path.resolve(String(filePath)).replace(/\\/g, '/')
  return resolved.includes('/ftp/order_') && resolved.endsWith('.pdf')
}

async function countOrders () {
  const orders = await db.ordersCollection.find({})
  return orders.length
}

interface CheckoutResponse {
  status: number
  text: string
  body: { orderConfirmation?: string }
}

async function withOrderSideEffects (fn: () => Promise<void>): Promise<SideEffects> {
  const effects: SideEffects = { orderPdfWrites: [], orderPdfDeletes: [], orderInserts: 0 }
  const originalCreateWriteStream = fs.createWriteStream
  const originalUnlink = fs.unlink
  const originalUnlinkSync = fs.unlinkSync
  const originalRm = fs.rm
  const originalRmSync = fs.rmSync
  const orders = db.ordersCollection
  const originalInsert = orders.insert

  const noteWrite = (filePath: fs.PathLike) => {
    if (isOrderPdf(filePath)) {
      effects.orderPdfWrites.push(path.resolve(String(filePath)))
    }
  }
  const noteDelete = (filePath: fs.PathLike) => {
    if (isOrderPdf(filePath)) {
      effects.orderPdfDeletes.push(path.resolve(String(filePath)))
    }
  }

  fs.createWriteStream = function (filePath: fs.PathLike, options?: BufferEncoding | fs.WriteStreamOptions) {
    noteWrite(filePath)
    return originalCreateWriteStream.call(fs, filePath, options as fs.WriteStreamOptions)
  }
  fs.unlink = function (filePath: fs.PathLike, callback: (err: NodeJS.ErrnoException | null) => void) {
    noteDelete(filePath)
    return originalUnlink.call(fs, filePath, callback)
  }
  fs.unlinkSync = function (filePath: fs.PathLike) {
    noteDelete(filePath)
    return originalUnlinkSync.call(fs, filePath)
  }
  fs.rm = function (filePath: fs.PathLike, options: fs.RmOptions, callback?: (err: NodeJS.ErrnoException | null) => void) {
    noteDelete(filePath)
    return originalRm.call(fs, filePath, options, callback as (err: NodeJS.ErrnoException | null) => void)
  }
  fs.rmSync = function (filePath: fs.PathLike, options?: fs.RmOptions) {
    noteDelete(filePath)
    return originalRmSync.call(fs, filePath, options)
  }
  orders.insert = function (doc: unknown, options?: unknown) {
    effects.orderInserts += 1
    return originalInsert.call(orders, doc, options)
  }

  try {
    await fn()
  } finally {
    fs.createWriteStream = originalCreateWriteStream
    fs.unlink = originalUnlink
    fs.unlinkSync = originalUnlinkSync
    fs.rm = originalRm
    fs.rmSync = originalRmSync
    orders.insert = originalInsert
  }
  return effects
}

function assertNoOrderSideEffects (effects: SideEffects) {
  assert.deepEqual(
    {
      writes: effects.orderPdfWrites,
      deletes: effects.orderPdfDeletes,
      inserts: effects.orderInserts
    },
    { writes: [], deletes: [], inserts: 0 }
  )
}

async function addProduct (target: Express, account: Account, quantity: number) {
  const res = await request(target)
    .post('/api/BasketItems')
    .set(bearer(account.token))
    .send({ BasketId: account.bid, ProductId: 1, quantity })
  assert.equal(res.status, 200, res.text)
  return res
}

function checkout (target: Express, account: Account, basketId: number, extraHeaders: Record<string, string> = {}) {
  return request(target)
    .post('/rest/basket/' + basketId + '/checkout')
    .set({ ...bearer(account.token), ...extraHeaders })
    .send({})
}

async function placeCheckout (target: Express, account: Account, basketId: number, extraHeaders: Record<string, string> = {}) {
  const outcome: CheckoutResponse = { status: 0, text: '', body: {} }
  const effects = await withOrderSideEffects(async () => {
    const res = await checkout(target, account, basketId, extraHeaders)
    outcome.status = res.status
    outcome.text = res.text
    outcome.body = res.body
  })
  return { effects, outcome }
}

void describe('checkout resource limits', { concurrency: false }, () => {
  void it('rejects an empty basket checkout before writing an order pdf or order record', async () => {
    const account = await openAccount(app)
    const basket = await request(app).get('/rest/basket/' + account.bid).set(bearer(account.token))
    assert.equal(basket.status, 200)
    const products = basket.body?.data?.Products
    assert.ok(products == null || products.length === 0)

    const pdfsBefore = orderPdfNames()
    const ordersBefore = await countOrders()
    const { effects, outcome } = await placeCheckout(app, account, account.bid)
    assertNoOrderSideEffects(effects)
    assert.equal(outcome.status, 400, outcome.text)
    assert.deepEqual(orderPdfNames(), pdfsBefore)
    assert.equal(await countOrders(), ordersBefore)
  })

  void it('rejects repeated empty checkouts without growing stored orders or the public ftp listing', async () => {
    const account = await openAccount(app)
    const pdfsBefore = orderPdfNames()
    const ordersBefore = await countOrders()
    const listingBefore = await request(app).get('/ftp')
    assert.equal(listingBefore.status, 200)

    let writes = 0
    let inserts = 0
    const statuses: number[] = []
    for (let i = 0; i < 12; i++) {
      const { effects, outcome } = await placeCheckout(app, account, account.bid)
      writes += effects.orderPdfWrites.length
      inserts += effects.orderInserts
      statuses.push(outcome.status)
    }

    const listingAfter = await request(app).get('/ftp')
    const tracked = await request(app).get('/rest/track-order/not-a-real-order').set(jsonHeader)
    const orderGrowth = (await countOrders()) - ordersBefore
    const listedGrowth = orderPdfCount(listingAfter.text) - orderPdfCount(listingBefore.text)
    const diskGrowth = orderPdfNames().length - pdfsBefore.length
    assert.equal(listingAfter.status, 200)
    assert.equal(tracked.status, 200)
    assert.deepEqual({ writes, inserts, statuses, listedGrowth, diskGrowth, orderGrowth }, {
      writes: 0,
      inserts: 0,
      statuses: [400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400],
      listedGrowth: 0,
      diskGrowth: 0,
      orderGrowth: 0
    })
  })

  for (const quantity of [0, -1]) {
    void it('rejects checkout when the only basket quantity is ' + quantity + ' before any order write', async () => {
      const account = await openAccount(app)
      await addProduct(app, account, quantity)
      const basket = await request(app).get('/rest/basket/' + account.bid).set(bearer(account.token))
      assert.equal(basket.status, 200)
      const products = basket.body.data.Products
      assert.ok(Array.isArray(products) && products.length > 0)
      assert.ok(products.every((product: { BasketItem?: { quantity?: number } }) => (product.BasketItem?.quantity ?? 0) <= 0))

      const ordersBefore = await countOrders()
      const pdfsBefore = orderPdfNames()
      const { effects, outcome } = await placeCheckout(app, account, account.bid)
      assertNoOrderSideEffects(effects)
      assert.equal(outcome.status, 400, outcome.text)
      assert.deepEqual(orderPdfNames(), pdfsBefore)
      assert.equal(await countOrders(), ordersBefore)
    })
  }

  void it('rejects checkout of a basket that is not the basket authorized for the session', async () => {
    const owner = await openAccount(app)
    const other = await openAccount(app)
    await addProduct(app, owner, 1)

    const ordersBefore = await countOrders()
    const pdfsBefore = orderPdfNames()
    const { effects, outcome } = await placeCheckout(app, other, owner.bid)
    assertNoOrderSideEffects(effects)
    assert.equal(outcome.status, 403, outcome.text)
    assert.deepEqual(orderPdfNames(), pdfsBefore)
    assert.equal(await countOrders(), ordersBefore)

    const ownerBasket = await request(app).get('/rest/basket/' + owner.bid).set(bearer(owner.token))
    assert.equal(ownerBasket.status, 200)
    assert.ok(ownerBasket.body.data.Products.length > 0)
  })

  void it('places one order when the caller basket has a positive quantity', async () => {
    const account = await openAccount(app)
    await addProduct(app, account, 1)
    const ordersBefore = await countOrders()
    const pdfsBefore = orderPdfNames()

    const { effects, outcome } = await placeCheckout(app, account, account.bid)
    const listing = await request(app).get('/ftp')
    assert.equal(outcome.status, 200, outcome.text)
    assert.equal(typeof outcome.body.orderConfirmation, 'string')
    assert.equal(effects.orderInserts, 1)
    assert.equal(await countOrders(), ordersBefore + 1)
    assert.equal(listing.status, 200)
    assert.deepEqual(effects.orderPdfDeletes, [])
    assert.equal(listing.text.includes(String(outcome.body.orderConfirmation)), false)
    assert.deepEqual(effects.orderPdfWrites, [])
    assert.deepEqual(orderPdfNames(), pdfsBefore)
  })

  void it('stops checkout writes after five orders for the same authenticated user', async () => {
    const limited = await createTestApp()
    const buyer = await openAccount(limited.app)
    await placeSuccessfulOrders(limited.app, buyer, MAX_SUCCESSFUL_CHECKOUTS)

    await addProduct(limited.app, buyer, 1)
    const overLimit = await placeCheckout(limited.app, buyer, buyer.bid)
    assertNoOrderSideEffects(overLimit.effects)
    assert.equal(overLimit.outcome.status, 429, overLimit.outcome.text)
  }, { timeout: 180000 })

  void it('does not give a new checkout allowance when X-Forwarded-For changes', async () => {
    const limited = await createTestApp()
    const buyer = await openAccount(limited.app)
    await placeSuccessfulOrders(limited.app, buyer, MAX_SUCCESSFUL_CHECKOUTS)

    await addProduct(limited.app, buyer, 1)
    const spoofedForwarding = await placeCheckout(limited.app, buyer, buyer.bid, { 'X-Forwarded-For': '198.51.100.23' })
    assertNoOrderSideEffects(spoofedForwarding.effects)
    assert.equal(spoofedForwarding.outcome.status, 429, spoofedForwarding.outcome.text)
  }, { timeout: 180000 })

  void it('stops a second account on the same client address after the address limit', async () => {
    const limited = await createTestApp()
    const buyer = await openAccount(limited.app)
    await placeSuccessfulOrders(limited.app, buyer, MAX_SUCCESSFUL_CHECKOUTS)

    const secondAccount = await openAccount(limited.app)
    await addProduct(limited.app, secondAccount, 1)
    const sameAddress = await placeCheckout(limited.app, secondAccount, secondAccount.bid)
    assertNoOrderSideEffects(sameAddress.effects)
    assert.equal(sameAddress.outcome.status, 429, sameAddress.outcome.text)
  }, { timeout: 180000 })
})

async function placeSuccessfulOrders (target: Express, account: Account, count: number) {
  for (let i = 0; i < count; i++) {
    await addProduct(target, account, 1)
    const { effects, outcome } = await placeCheckout(target, account, account.bid)
    assert.equal(outcome.status, 200, outcome.text)
    assert.equal(effects.orderInserts, 1)
  }
}

function orderPdfCount (listing: string) {
  return (listing.match(/order_[^"<\s]*\.pdf/g) ?? []).length
}
