/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const placeholderPassword = 'placeholder-password'
const ownerEmail = 'track-owner@example.test'
const otherEmail = 'track-other@example.test'
const placeholderCardNumber = 1000000000000000

interface Session {
  token: string
  bid: number
  email: string
}

interface PlacedOrder {
  orderId: string
  email: string
  maskedEmail: string
  addressId: number
  paymentId: number
  productId: number
  quantity: number
  deliveryPrice: number
  pdfName: string
}

let app: Express
let owner: Session
let other: Session
let ownerOrder: PlacedOrder
let otherOrder: PlacedOrder

before(async () => {
  const result = await createTestApp()
  app = result.app
  owner = await openSession(ownerEmail)
  other = await openSession(otherEmail)
  const catalog = await request(app).get('/api/Products')
  assert.equal(catalog.status, 200)
  const products = catalog.body.data as Array<{ id: number }>
  assert.ok(products.length >= 2)
  const deliveries = await request(app).get('/api/Deliverys')
  assert.equal(deliveries.status, 200)
  const priced = (deliveries.body.data as Array<{ id: number, price: number }>).find((method) => method.price > 0)
  assert.ok(priced)
  ownerOrder = await placeOrder(owner, products[0].id, 5, priced.id, priced.price)
  otherOrder = await placeOrder(other, products[1].id, 4, priced.id, priced.price)
}, { timeout: 60000 })

after(async () => {
  for (const placed of [ownerOrder, otherOrder]) {
    if (placed?.pdfName) {
      await fs.unlink(path.join('ftp', placed.pdfName)).catch(() => {})
    }
  }
})

void describe('order tracking by id', () => {
  void it('does not return another customer purchase to an anonymous caller of the order-completion and track-result request', async () => {
    const discoveredId = await orderIdFromPublicListing()
    const ids = discoveredId != null && discoveredId !== ownerOrder.orderId
      ? [discoveredId, ownerOrder.orderId]
      : [ownerOrder.orderId]

    for (const id of ids) {
      const res = await request(app).get('/rest/track-order/' + encodeURIComponent(id))
      assert.equal(disclosesPurchase(res.body, ownerOrder), false)
      assert.equal(disclosesPurchase(res.body, otherOrder), false)
    }
  })

  void it('returns a session only the order that belongs to that session', async () => {
    const asOther = await request(app)
      .get('/rest/track-order/' + encodeURIComponent(ownerOrder.orderId))
      .set('Authorization', 'Bearer ' + other.token)
    assert.equal(disclosesPurchase(asOther.body, ownerOrder), false)

    const own = await request(app)
      .get('/rest/track-order/' + encodeURIComponent(otherOrder.orderId))
      .set('Authorization', 'Bearer ' + other.token)
    assert.equal(disclosesPurchase(own.body, otherOrder), true)
    assert.equal(disclosesPurchase(own.body, ownerOrder), false)

    const asOwner = await request(app)
      .get('/rest/track-order/' + encodeURIComponent(ownerOrder.orderId))
      .set('Authorization', 'Bearer ' + owner.token)
    assert.equal(disclosesPurchase(asOwner.body, ownerOrder), true)
    assert.equal(disclosesPurchase(asOwner.body, otherOrder), false)
  })
})

void describe('order confirmation files under /ftp', () => {
  void it('does not list an order id to an anonymous caller', async () => {
    const res = await request(app).get('/ftp').set('Accept', 'text/html')
    if (res.status === 401 || res.status === 403) {
      return
    }
    assert.equal(res.status, 200)
    const listing = res.text ?? ''
    assert.equal(listing.includes(ownerOrder.orderId), false)
    assert.equal(listing.includes(otherOrder.orderId), false)
  })

  void it('does not serve the confirmation pdf to an anonymous caller', async () => {
    for (const placed of [ownerOrder, otherOrder]) {
      const res = await request(app).get('/ftp/order_' + placed.orderId + '.pdf')
      assert.notEqual(res.status, 200)
      assert.equal(responseText(res).includes(placed.email), false)
    }
  })
})

async function openSession (email: string): Promise<Session> {
  await register(app, { email, password: placeholderPassword })
  const authentication = await login(app, { email, password: placeholderPassword })
  assert.equal(typeof authentication.token, 'string')
  assert.equal(typeof authentication.bid, 'number')
  return { token: authentication.token, bid: authentication.bid, email }
}

async function placeOrder (session: Session, productId: number, quantity: number, deliveryMethodId: number, deliveryPrice: number): Promise<PlacedOrder> {
  const headers = {
    Authorization: 'Bearer ' + session.token,
    'content-type': 'application/json'
  }
  const address = await request(app).post('/api/Addresss').set(headers).send({
    fullName: 'Track Customer',
    mobileNum: 1000000,
    zipCode: '00000',
    streetAddress: '1 Test Street',
    city: 'Test City',
    state: 'TS',
    country: 'Testland'
  })
  assert.equal(address.status, 201)
  const card = await request(app).post('/api/Cards').set(headers).send({
    fullName: 'Track Customer',
    cardNum: placeholderCardNumber,
    expMonth: 1,
    expYear: 2080
  })
  assert.equal(card.status, 201)
  const item = await request(app).post('/api/BasketItems').set(headers).send({
    BasketId: session.bid,
    ProductId: productId,
    quantity
  })
  assert.equal(item.status, 200)
  const checkout = await request(app)
    .post('/rest/basket/' + session.bid + '/checkout')
    .set(headers)
    .send({
      orderDetails: {
        paymentId: createdId(card.body),
        addressId: createdId(address.body),
        deliveryMethodId
      }
    })
  assert.equal(checkout.status, 200)
  const orderId = checkout.body.orderConfirmation
  assert.equal(typeof orderId, 'string')
  assert.match(orderId, /^[0-9a-f]{4}-[0-9a-f]{16}$/)
  return {
    orderId,
    email: session.email,
    maskedEmail: session.email.replace(/[aeiou]/gi, '*'),
    addressId: createdId(address.body),
    paymentId: createdId(card.body),
    productId,
    quantity,
    deliveryPrice,
    pdfName: 'order_' + orderId + '.pdf'
  }
}

function createdId (body: { data?: { id?: unknown }, id?: unknown }): number {
  const raw = body.data?.id ?? body.id
  const id = Number(raw)
  assert.equal(Number.isInteger(id), true)
  return id
}

async function orderIdFromPublicListing (): Promise<string | null> {
  const res = await request(app).get('/ftp').set('Accept', 'text/html')
  if (res.status === 401 || res.status === 403) {
    return null
  }
  const match = (res.text ?? '').match(/order_([0-9a-f]{4}-[0-9a-f]{16})\.pdf/i)
  return match ? match[1] : null
}

function disclosesPurchase (body: unknown, placed: PlacedOrder): boolean {
  return containsRecord(body, (record) => {
    return sameId(record.addressId, placed.addressId) ||
      sameId(record.paymentId, placed.paymentId) ||
      record.email === placed.maskedEmail ||
      record.email === placed.email ||
      (record.quantity === placed.quantity && sameId(record.id, placed.productId))
  })
}

function sameId (actual: unknown, expected: number): boolean {
  return actual === expected || actual === String(expected)
}

function containsRecord (value: unknown, matches: (record: Record<string, unknown>) => boolean): boolean {
  if (Array.isArray(value)) {
    return value.some((entry) => containsRecord(entry, matches))
  }
  if (value != null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    if (matches(record)) {
      return true
    }
    return Object.values(record).some((entry) => containsRecord(entry, matches))
  }
  return false
}

function responseText (res: request.Response): string {
  if (typeof res.text === 'string' && res.text.length > 0) {
    return res.text
  }
  if (Buffer.isBuffer(res.body)) {
    return res.body.toString('utf8')
  }
  return ''
}
