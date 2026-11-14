/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const protoCookie = { Cookie: 'language=__proto__' }
const localeFile = path.resolve('i18n', '__proto__.json')

const placeholderPassword = 'placeholder-password'
const registeredEmail = 'proto-cookie@juice-sh.op'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let basketId: number
let prototypeBefore: Set<string>
let orderPdfsBefore: Set<string>
let markerSeq = 0

function marker (label: string) {
  markerSeq += 1
  return `zz${label}${markerSeq}q`
}

function removeLocaleArtifacts () {
  for (const suffix of ['', '.tmp', '.invalid']) {
    const file = localeFile + suffix
    if (fs.existsSync(file)) fs.unlinkSync(file)
  }
}

function restorePrototype () {
  for (const key of Object.getOwnPropertyNames(Object.prototype)) {
    if (!prototypeBefore.has(key)) delete Object.prototype[key]
  }
}

function removeOrderPdfs () {
  for (const name of fs.readdirSync('ftp')) {
    if (name.startsWith('order_') && name.endsWith('.pdf') && !orderPdfsBefore.has(name)) {
      fs.unlinkSync(path.join('ftp', name))
    }
  }
}

function assertPhraseStaysOffPrototype (phrase: string) {
  const fresh: Record<string, unknown> = {}
  const walked: string[] = []
  for (const key in fresh) walked.push(key)
  assert.equal(Object.hasOwn(Object.prototype, phrase), false)
  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, phrase)?.enumerable, undefined)
  assert.equal(Object.hasOwn(fresh, phrase), false)
  assert.equal(phrase in fresh, false)
  assert.equal(fresh[phrase], undefined)
  assert.equal(walked.includes(phrase), false)
  assert.equal(fs.existsSync(localeFile), false)
  assert.equal(fs.existsSync(localeFile + '.tmp'), false)
}

async function renameProduct (id: number, name: string, description: string) {
  const res = await request(app)
    .put('/api/Products/' + id)
    .set(jsonHeader)
    .send({ name, description })
  assert.equal(res.status, 200)
  assert.equal(res.body.data.name, name)
  assert.equal(res.body.data.description, description)
  return res
}

before(async () => {
  prototypeBefore = new Set(Object.getOwnPropertyNames(Object.prototype))
  orderPdfsBefore = new Set(fs.readdirSync('ftp').filter((name) => name.startsWith('order_') && name.endsWith('.pdf')))
  removeLocaleArtifacts()
  const result = await createTestApp()
  app = result.app
  await register(app, { email: registeredEmail, password: placeholderPassword })
  const authentication = await login(app, { email: registeredEmail, password: placeholderPassword })
  authHeader = { Authorization: 'Bearer ' + authentication.token, 'content-type': 'application/json' }
  basketId = authentication.bid
}, { timeout: 60000 })

afterEach(() => {
  restorePrototype()
  removeLocaleArtifacts()
  removeOrderPdfs()
})

void describe('language cookie __proto__', { concurrency: 1 }, () => {
  void it('product search does not copy an updated name or description onto every object', async () => {
    const name = marker('searchName')
    const description = marker('searchDesc')
    await renameProduct(1, name, description)

    const res = await request(app)
      .get('/rest/products/search')
      .query({ q: name })
      .set(protoCookie)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].name, name)
    assert.equal(res.body.data[0].description, description)
    assertPhraseStaysOffPrototype(name)
    assertPhraseStaysOffPrototype(description)

    const later = await request(app)
      .get('/rest/products/search')
      .query({ q: 'nomatcheswhatsoever' })
    assert.equal(later.status, 200)
    assertPhraseStaysOffPrototype(name)
    assertPhraseStaysOffPrototype(description)
  })

  void it('product list does not copy an updated name or description onto every object', async () => {
    const name = marker('listName')
    const description = marker('listDesc')
    await renameProduct(2, name, description)

    const res = await request(app)
      .get('/api/Products')
      .set(protoCookie)
    assert.equal(res.status, 200)
    const product = res.body.data.find((item: { id: number }) => item.id === 2)
    assert.equal(product.name, name)
    assert.equal(product.description, description)
    assertPhraseStaysOffPrototype(name)
    assertPhraseStaysOffPrototype(description)
  })

  void it('product read does not copy an updated name or description onto every object', async () => {
    const name = marker('readName')
    const description = marker('readDesc')
    await renameProduct(6, name, description)

    const res = await request(app)
      .get('/api/Products/6')
      .set(protoCookie)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.name, name)
    assert.equal(res.body.data.description, description)
    assertPhraseStaysOffPrototype(name)
    assertPhraseStaysOffPrototype(description)
  })

  void it('basket retrieval does not copy an updated product name onto every object', async () => {
    const name = marker('basketName')
    const description = marker('basketDesc')
    await renameProduct(3, name, description)
    const added = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: basketId, ProductId: 3, quantity: 1 })
    assert.equal(added.status, 200)

    const res = await request(app)
      .get('/rest/basket/' + basketId)
      .set(authHeader)
      .set(protoCookie)
    assert.equal(res.status, 200)
    const product = res.body.data.Products.find((item: { id: number }) => item.id === 3)
    assert.equal(product.name, name)
    assertPhraseStaysOffPrototype(name)
  })

  void it('checkout does not copy order phrases or an updated product name onto every object', async () => {
    const name = marker('orderName')
    const description = marker('orderDesc')
    await renameProduct(4, name, description)
    const added = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: basketId, ProductId: 4, quantity: 1 })
    assert.equal(added.status, 200)

    const res = await request(app)
      .post('/rest/basket/' + basketId + '/checkout')
      .set(authHeader)
      .set(protoCookie)
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.orderConfirmation, 'string')
    assertPhraseStaysOffPrototype(name)
    for (const phrase of [
      'Order Confirmation',
      'Customer',
      'Order',
      'Date',
      'ea.',
      'Delivery Price',
      'Total Price',
      'Bonus Points Earned',
      'The bonus points from this order will be added 1:1 to your wallet ¤-fund for future purchases!',
      'Thank you for your order!'
    ]) {
      assertPhraseStaysOffPrototype(phrase)
    }
  })

  void it('challenge list does not copy a challenge description onto every object', async () => {
    const res = await request(app)
      .get('/api/Challenges')
      .set(protoCookie)
    assert.equal(res.status, 200)
    const challenge = res.body.data.find((item: { description?: string }) => {
      return typeof item.description === 'string' && !item.description.includes('<em>(This challenge is <strong>')
    })
    assert.equal(typeof challenge.description, 'string')
    assertPhraseStaysOffPrototype(challenge.description)
  })

  void it('security question list does not copy a question onto every object', async () => {
    const res = await request(app)
      .get('/api/SecurityQuestions')
      .set(protoCookie)
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.data[0].question, 'string')
    assertPhraseStaysOffPrototype(res.body.data[0].question)
  })

  void it('hint list does not copy an updated hint onto every object', async () => {
    const text = marker('hintText')
    const update = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ text })
    assert.equal(update.status, 200)
    assert.equal(update.body.data.text, text)

    const res = await request(app)
      .get('/api/Hints')
      .set(protoCookie)
    assert.equal(res.status, 200)
    const hint = res.body.data.find((item: { id: number }) => item.id === 1)
    assert.equal(hint.text, text)
    assertPhraseStaysOffPrototype(text)
  })
})
