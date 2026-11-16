/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { QueryTypes, type Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { loadStaticUserData } from '../../data/staticData'

const placeholderPassword = 'placeholder-password'
const firstHolder = 'Placeholder Cardholder'
const secondHolder = 'Second Placeholder Cardholder'
const firstCardNumber = '4242424242424242'
const secondCardNumber = '4000000000000002'
const firstExpiry = { expMonth: 8, expYear: 2094 }
const secondExpiry = { expMonth: 7, expYear: 2093 }
const unsafeCardDigits = '9007199254740993'
const precisionHolder = 'Precision Placeholder'

// Nine columns, matching Products, and short enough for the 200 character search cutoff.
const cardSearchQuery = "')) union select id,'2','3',cardNum,expYear,fullName,expMonth,'8','9' from Cards--"

let app: Express
let sequelize: Sequelize
let firstAuth: { Authorization: string, 'content-type': string }
let secondAuth: { Authorization: string, 'content-type': string }
let firstCardId: number | undefined

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize

  await register(app, { email: 'placeholder-cardholder@example.com', password: placeholderPassword })
  await register(app, { email: 'placeholder-other@example.com', password: placeholderPassword })
  const firstLogin = await login(app, { email: 'placeholder-cardholder@example.com', password: placeholderPassword })
  const secondLogin = await login(app, { email: 'placeholder-other@example.com', password: placeholderPassword })
  firstAuth = { Authorization: 'Bearer ' + firstLogin.token, 'content-type': 'application/json' }
  secondAuth = { Authorization: 'Bearer ' + secondLogin.token, 'content-type': 'application/json' }

  const firstCard = await request(app).post('/api/Cards').set(firstAuth).send({
    fullName: firstHolder,
    cardNum: Number(firstCardNumber),
    expMonth: firstExpiry.expMonth,
    expYear: firstExpiry.expYear
  })
  const secondCard = await request(app).post('/api/Cards').set(secondAuth).send({
    fullName: secondHolder,
    cardNum: Number(secondCardNumber),
    expMonth: secondExpiry.expMonth,
    expYear: secondExpiry.expYear
  })
  assert.equal(firstCard.status, 201)
  assert.equal(secondCard.status, 201)
  firstCardId = firstCard.body?.data?.id
}, { timeout: 60000 })

async function storedCardNumbers (): Promise<string[]> {
  const rows = await sequelize.query<{ cardNum: string }>('SELECT CAST(cardNum AS TEXT) AS cardNum FROM Cards', { type: QueryTypes.SELECT })
  return rows.map((row) => row.cardNum)
}

function responseText (res: { body: unknown, text?: string }): string {
  return `${JSON.stringify(res.body)}\n${res.text ?? ''}`
}

function cardLeak (res: { body: { data?: unknown }, text?: string }, includeSecondCard: boolean): string {
  const text = responseText(res)
  const rows = Array.isArray(res.body?.data) ? res.body.data : []
  const leaked: string[] = []
  if (text.includes(firstCardNumber) || (includeSecondCard && text.includes(secondCardNumber))) {
    leaked.push('number')
  }
  if (text.includes(firstHolder) || (includeSecondCard && text.includes(secondHolder))) {
    leaked.push('name')
  }
  const expiryRevealed = rows.some((row: { deluxePrice?: unknown, image?: unknown, createdAt?: unknown }) => {
    return (String(row.image) === firstHolder && String(row.deluxePrice) === String(firstExpiry.expYear) && String(row.createdAt) === String(firstExpiry.expMonth)) ||
      (includeSecondCard && String(row.image) === secondHolder && String(row.deluxePrice) === String(secondExpiry.expYear) && String(row.createdAt) === String(secondExpiry.expMonth))
  })
  if (expiryRevealed) {
    leaked.push('expiry')
  }
  return leaked.join(',')
}

function decodedJwtPayload (token: unknown): string {
  if (typeof token !== 'string') {
    return ''
  }
  const segment = token.split('.')[1]
  if (segment == null || segment === '') {
    return ''
  }
  return Buffer.from(segment, 'base64url').toString('utf8')
}

void describe('saved payment cards', () => {
  void it('are not stored as the raw card number', async () => {
    const stored = await storedCardNumbers()
    assert.equal(stored.includes(firstCardNumber), false, 'Cards stored a raw card number')
    assert.equal(stored.includes(secondCardNumber), false, 'Cards stored a raw card number')
  })

  void it('startup card rows are not stored as raw card numbers', async () => {
    const users = await loadStaticUserData()
    const startupNumbers = users.flatMap((user) => user.card ?? []).map((card) => String(card.cardNum))
    assert.ok(startupNumbers.length > 0)
    const stored = new Set(await storedCardNumbers())
    assert.equal(startupNumbers.some((cardNumber) => stored.has(cardNumber)), false, 'startup data left a raw card number in Cards')
  })

  void it('create response does not echo the raw card number', async () => {
    const res = await request(app).post('/api/Cards').set(firstAuth).send({
      fullName: firstHolder,
      cardNum: Number(firstCardNumber),
      expMonth: firstExpiry.expMonth,
      expYear: firstExpiry.expYear
    })
    if (res.status >= 200 && res.status < 300) {
      assert.equal(responseText(res).includes(firstCardNumber), false, 'card create response echoed the raw card number')
    } else {
      assert.ok(res.status >= 400)
    }
    assert.equal((await storedCardNumbers()).includes(firstCardNumber), false, 'card create stored a raw card number')
  })

  void it('list and detail responses do not include the raw card number', async () => {
    const list = await request(app).get('/api/Cards').set(firstAuth)
    assert.equal(list.status, 200)
    assert.equal(responseText(list).includes(firstCardNumber), false, 'card list included a raw card number')

    assert.ok(firstCardId != null)
    const detail = await request(app).get('/api/Cards/' + String(firstCardId)).set(firstAuth)
    assert.equal(detail.status, 200)
    assert.equal(responseText(detail).includes(firstCardNumber), false, 'card detail included a raw card number')
  })

  void it('keeps the submitted digits when the card number is above the safe integer limit', async () => {
    const res = await request(app)
      .post('/api/Cards')
      .set(firstAuth)
      .send(`{"fullName":"${precisionHolder}","cardNum":${unsafeCardDigits},"expMonth":3,"expYear":2082}`)
    const rows = await sequelize.query<{ cardNum: string }>(
      'SELECT CAST(cardNum AS TEXT) AS cardNum FROM Cards WHERE fullName = :fullName',
      { replacements: { fullName: precisionHolder }, type: QueryTypes.SELECT }
    )
    if (res.status >= 200 && res.status < 300) {
      assert.equal(rows.length, 1)
      assert.equal(rows[0]?.cardNum, unsafeCardDigits, 'card number was stored as a different integer')
    } else {
      assert.ok(res.status >= 400)
      assert.equal(rows.length, 0, 'card row was written before the request was refused')
    }
  })

  void it('does not store a raw card number submitted as a string', async () => {
    const holder = 'Precision String Placeholder'
    const res = await request(app)
      .post('/api/Cards')
      .set(firstAuth)
      .send(`{"fullName":"${holder}","cardNum":"${unsafeCardDigits}","expMonth":4,"expYear":2083}`)
    const rows = await sequelize.query<{ cardNum: string }>(
      'SELECT CAST(cardNum AS TEXT) AS cardNum FROM Cards WHERE fullName = :fullName',
      { replacements: { fullName: holder }, type: QueryTypes.SELECT }
    )
    if (res.status >= 200 && res.status < 300) {
      assert.equal(rows.some((row) => row.cardNum === unsafeCardDigits), false, 'string card number was stored in cleartext')
    } else {
      assert.ok(res.status >= 400)
      assert.equal(rows.length, 0, 'card row was written before the request was refused')
    }
  })

  void it('unauthenticated product search does not return saved card number, name, or expiry', async () => {
    assert.ok(cardSearchQuery.length <= 200)
    const res = await request(app).get('/rest/products/search').query({ q: cardSearchQuery })
    assert.equal(cardLeak(res, true), '', 'unauthenticated search returned saved card details')
  })

  void it('another signed-in customer cannot read saved card details through product search', async () => {
    assert.ok(cardSearchQuery.length <= 200)
    const res = await request(app).get('/rest/products/search').query({ q: cardSearchQuery }).set(secondAuth)
    assert.equal(cardLeak(res, false), '', 'product search returned another customer card details')
  })

  void it('login query does not return saved card details', async () => {
    const email = "' union select cardNum,fullName,cardNum,'x','customer','','0.0.0.0','/assets/public/images/uploads/default.svg','',1,createdAt,updatedAt,null from Cards--"
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email, password: placeholderPassword })
    const token = res.body?.authentication?.token
    const text = `${responseText(res)}\n${decodedJwtPayload(token)}`
    assert.equal(text.includes(firstCardNumber), false, 'login returned a saved card number')
    assert.equal(text.includes(secondCardNumber), false, 'login returned a saved card number')
    assert.equal(text.includes(firstHolder), false, 'login returned a cardholder name')
    assert.equal(text.includes(secondHolder), false, 'login returned a cardholder name')
  })
})
