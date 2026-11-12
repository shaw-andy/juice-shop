/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { TestContext } from 'node:test'
import { createTestApp } from './helpers/setup'
import { register, login } from './helpers/auth'
import { QuantityModel } from '../../models/quantity'

const placeholderPassword = 'placeholder-password'
const placeholderCardNumber = 1000000000000000

// Same campaign days the checkout route stores. The timestamp is GMT+0100
// midnight of that calendar day, which is what the payment page derives from
// the machine's local date.
const campaigns = {
  WMNSDY2019: { validOn: new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime(), discount: 75 },
  ORANGE2022: { validOn: new Date('May 04, 2022 00:00:00 GMT+0100').getTime(), discount: 40 }
}

let app: Express
let product: { id: number, price: number }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const res = await request(app).get('/api/Products')
  assert.equal(res.status, 200)
  const products = res.body.data as Array<{ id: number, price: string | number, deletedAt?: string | null }>
  const match = products.find((item) => item.deletedAt == null && Number(item.price) === 1000)
  assert.ok(match, 'expected a product priced at 1000 so the wallet balance stays an integer')
  product = { id: match.id, price: Number(match.price) }
  await QuantityModel.update({ quantity: 100 }, { where: { ProductId: product.id } })
}, { timeout: 60000 })

void describe('seasonal campaign checkout', { concurrency: 1 }, () => {
  void it('does not replay a past 75 percent campaign when the server date is not that day', async () => {
    const session = await openShopper()
    const order = await checkout(session, campaignCoupon('WMNSDY2019', campaigns.WMNSDY2019.validOn))
    assertCharged(order, 0, await walletBalance(session))
  })

  void it('does not replay a past 40 percent campaign when checkout is not paid from the wallet', async () => {
    const session = await openShopper()
    const order = await checkout(session, campaignCoupon('ORANGE2022', campaigns.ORANGE2022.validOn), { fundWallet: false })
    assertCharged(order, 0)
  })

  void it('applies the 75 percent campaign from the server clock when the client timestamp does not match', async (t) => {
    const session = await openShopper()
    freezeOnCampaignDay(t, campaigns.WMNSDY2019.validOn)
    const order = await checkout(session, campaignCoupon('WMNSDY2019', 0))
    assertCharged(order, campaigns.WMNSDY2019.discount, await walletBalance(session))
  })

  void it('applies the 40 percent campaign from the server clock when the client sends another campaign timestamp', async (t) => {
    const session = await openShopper()
    freezeOnCampaignDay(t, campaigns.ORANGE2022.validOn)
    const order = await checkout(session, campaignCoupon('ORANGE2022', campaigns.WMNSDY2019.validOn), { fundWallet: false })
    assertCharged(order, campaigns.ORANGE2022.discount)
  })

  void it('does not apply a different historical campaign on a day when another campaign is valid', async (t) => {
    const session = await openShopper()
    freezeOnCampaignDay(t, campaigns.ORANGE2022.validOn)
    const order = await checkout(session, campaignCoupon('WMNSDY2019', campaigns.WMNSDY2019.validOn), { fundWallet: false })
    assertCharged(order, 0)
  })
})

interface Session {
  header: { Authorization: string, 'content-type': string }
  basketId: number
}

interface PlacedOrder {
  totalPrice: number
  promotionalAmount: string | number
  receipt: string
}

function campaignCoupon (code: string, timestamp: number) {
  return Buffer.from(`${code}-${timestamp}`).toString('base64')
}

function serverCampaignDayStamp (now: Date) {
  const day = new Date(now.getTime())
  const offsetTimeZone = (day.getTimezoneOffset() + 60) * 60 * 1000
  day.setHours(0, 0, 0, 0)
  return day.getTime() - offsetTimeZone
}

function noonOnCampaignDay (validOn: number) {
  // validOn is 00:00 GMT+0100. Local noon on that same calendar date keeps
  // the UTC date and the GMT+0100 date on the campaign day.
  return validOn + (60 * 60 * 1000) + (12 * 60 * 60 * 1000)
}

function freezeOnCampaignDay (t: TestContext, validOn: number) {
  const now = noonOnCampaignDay(validOn)
  t.mock.timers.enable({ apis: ['Date'], now })
  assert.equal(serverCampaignDayStamp(new Date()), validOn)
}

function merchandiseDiscount (discountPercent: number) {
  if (discountPercent <= 0) {
    return 0
  }
  return Number((product.price * (discountPercent / 100)).toFixed(2))
}

function expectedTotal (discountPercent: number) {
  return product.price - merchandiseDiscount(discountPercent)
}

function expectedWalletBalance (discountPercent: number) {
  const bonus = Math.round(product.price / 10)
  return product.price - expectedTotal(discountPercent) + bonus
}

function assertCharged (order: PlacedOrder, discountPercent: number, wallet?: number) {
  const total = expectedTotal(discountPercent)
  const discountAmount = merchandiseDiscount(discountPercent)
  const actual = {
    totalPrice: order.totalPrice,
    promotionalAmount: Number(order.promotionalAmount),
    receiptTotal: order.receipt.includes(`Total Price: ${total.toFixed(2)}`),
    receiptDiscount: discountPercent > 0
      ? order.receipt.includes(`${discountPercent}% discount from coupon: -${discountAmount.toFixed(2)}`)
      : !order.receipt.includes('discount from coupon'),
    wallet
  }
  const expected = {
    totalPrice: total,
    promotionalAmount: discountAmount,
    receiptTotal: true,
    receiptDiscount: true,
    wallet: wallet === undefined ? undefined : expectedWalletBalance(discountPercent)
  }
  assert.deepEqual(actual, expected)
}

async function openShopper (): Promise<Session> {
  const email = `seasonal-${Math.random().toString(16).slice(2)}@example.test`
  await register(app, { email, password: placeholderPassword })
  const { token, bid } = await login(app, { email, password: placeholderPassword })
  const header = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  const added = await request(app)
    .post('/api/BasketItems')
    .set(header)
    .send({ BasketId: bid, ProductId: product.id, quantity: 1 })
  assert.equal(added.status, 200)
  return { header, basketId: bid }
}

async function checkout (session: Session, couponData: string, options: { fundWallet?: boolean } = {}) {
  const fundWallet = options.fundWallet !== false
  if (fundWallet) {
    const basket = await request(app).get(`/rest/basket/${session.basketId}`).set(session.header)
    assert.equal(basket.status, 200)
    const card = await request(app)
      .post('/api/Cards')
      .set(session.header)
      .send({
        UserId: basket.body.data.UserId,
        fullName: 'Seasonal Coupon Shopper',
        cardNum: placeholderCardNumber,
        expMonth: 1,
        expYear: 2080
      })
    assert.equal(card.status, 201)
    const funded = await request(app)
      .put('/rest/wallet/balance')
      .set(session.header)
      .send({ balance: product.price, paymentId: card.body.data.id })
    assert.equal(funded.status, 200)
  }

  const res = await request(app)
    .post(`/rest/basket/${session.basketId}/checkout`)
    .set(session.header)
    .send({
      couponData,
      orderDetails: { paymentId: fundWallet ? 'wallet' : 'card' }
    })
  assert.equal(res.status, 200, res.text)
  const orderId = res.body.orderConfirmation as string
  assert.equal(typeof orderId, 'string')

  const tracked = await request(app).get('/rest/track-order/' + encodeURIComponent(orderId))
  assert.equal(tracked.status, 200)
  const stored = tracked.body.data[0]
  assert.equal(stored.orderId, orderId)
  const receipt = readReceipt(orderId)
  return {
    totalPrice: stored.totalPrice as number,
    promotionalAmount: stored.promotionalAmount as string | number,
    receipt
  }
}

function readReceipt (orderId: string) {
  // pdfkit 0.11 writes WinAnsi character codes as hex inside TJ arrays, then
  // Flate-compresses the page stream. Join those hex strings in order.
  const pdf = fs.readFileSync(path.join('ftp', `order_${orderId}.pdf`))
  const source = pdf.toString('latin1')
  let text = ''
  for (const match of source.matchAll(/stream\r?\n([\s\S]*?)\r?\nendstream/g)) {
    const raw = Buffer.from(match[1], 'latin1')
    let inflated: Buffer
    try {
      inflated = zlib.inflateSync(raw)
    } catch {
      inflated = raw
    }
    const content = inflated.toString('latin1')
    for (const hex of content.matchAll(/<([0-9A-Fa-f]+)>/g)) {
      text += Buffer.from(hex[1], 'hex').toString('latin1')
    }
  }
  return text
}

async function walletBalance (session: Session) {
  const res = await request(app).get('/rest/wallet/balance').set(session.header)
  assert.equal(res.status, 200)
  return res.body.data as number
}
