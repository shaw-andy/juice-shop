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
import { UserModel } from '../../models/user'
import { AddressModel } from '../../models/address'
import { CardModel } from '../../models/card'
import { MemoryModel } from '../../models/memory'
import { PrivacyRequestModel } from '../../models/privacyRequests'
import { ordersCollection, reviewsCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'

const PASSWORD = 'placeholder-password'
const PROCESSED_MESSAGE = 'Your erasure request will be processed shortly.'
const LAYOUT_MARKER = 'juice-shop'

let app: Express
const orderPdfs: string[] = []

interface Customer {
  email: string
  answer: string
  userId: number
  token: string
  street: string
  cardNum: number
  caption: string
  review: string
  orderId: string
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

afterEach(() => {
  for (const orderId of orderPdfs.splice(0)) {
    removeOrderPdf(orderId)
  }
})

void describe('account data erasure', { concurrency: false }, () => {
  void it('rejects a non-matching security answer without reporting success or removing personal data', async () => {
    const customer = await provisionCustomer('erasure-wrong-answer@example.test', 'placeholder-answer-subject')
    const privacyRequestsBefore = await PrivacyRequestModel.count({ where: { UserId: customer.userId } })

    const res = await postErasure(customer, {
      email: customer.email,
      securityAnswer: 'placeholder-answer-wrong'
    })

    await assertPersonalDataPresent(customer)
    await assertCanLogin(customer)
    assert.deepEqual(await refusalProblems(res, customer.userId, privacyRequestsBefore), [])
  })

  void it('does not erase another account when the submitted answer matches that account instead of the session', async () => {
    const sessionUser = await provisionCustomer('erasure-session@example.test', 'placeholder-answer-session')
    const otherUser = await provisionCustomer('erasure-other@example.test', 'placeholder-answer-other')
    const sessionRequestsBefore = await PrivacyRequestModel.count({ where: { UserId: sessionUser.userId } })
    const otherRequestsBefore = await PrivacyRequestModel.count({ where: { UserId: otherUser.userId } })

    const res = await postErasure(sessionUser, {
      email: otherUser.email,
      securityAnswer: otherUser.answer
    })

    await assertPersonalDataPresent(sessionUser)
    await assertPersonalDataPresent(otherUser)
    await assertCanLogin(sessionUser)
    await assertCanLogin(otherUser)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: otherUser.userId } }), otherRequestsBefore)
    assert.deepEqual(await refusalProblems(res, sessionUser.userId, sessionRequestsBefore), [])
  })

  void it('does not erase the confirmed account when the answer matches only the session user', async () => {
    const sessionUser = await provisionCustomer('erasure-session-match@example.test', 'placeholder-answer-session-match')
    const otherUser = await provisionCustomer('erasure-confirmed-other@example.test', 'placeholder-answer-confirmed-other')
    const otherRequestsBefore = await PrivacyRequestModel.count({ where: { UserId: otherUser.userId } })

    const res = await postErasure(sessionUser, {
      email: otherUser.email,
      securityAnswer: sessionUser.answer
    })

    await assertPersonalDataPresent(otherUser)
    await assertCanLogin(otherUser)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: otherUser.userId } }), otherRequestsBefore)

    if (res.text.includes(PROCESSED_MESSAGE)) {
      assert.deepEqual(await personalDataStillPresent(sessionUser), [])
    } else {
      await assertPersonalDataPresent(sessionUser)
      await assertCanLogin(sessionUser)
      assert.deepEqual(await refusalProblems(res, sessionUser.userId, 0), [])
    }
  })

  void it('does not read a layout file when the security answer does not match', async () => {
    const customer = await provisionCustomer('erasure-layout@example.test', 'placeholder-answer-layout')
    const privacyRequestsBefore = await PrivacyRequestModel.count({ where: { UserId: customer.userId } })

    const res = await postErasure(customer, {
      email: customer.email,
      securityAnswer: 'placeholder-answer-wrong',
      layout: '../package.json'
    })

    await assertPersonalDataPresent(customer)
    await assertCanLogin(customer)
    assert.deepEqual(await refusalProblems(res, customer.userId, privacyRequestsBefore, true), [])
  })

  void it('removes the signed-in account and related personal data before reporting that the erasure will be processed', async () => {
    const bystander = await provisionCustomer('erasure-bystander@example.test', 'placeholder-answer-bystander')
    const customer = await provisionCustomer('erasure-subject@example.test', 'placeholder-answer-subject')

    const res = await postErasure(customer, {
      email: customer.email,
      securityAnswer: customer.answer
    })

    await assertPersonalDataPresent(bystander)
    await assertCanLogin(bystander)
    assert.equal(res.status, 200)
    assert.equal(res.text.includes(PROCESSED_MESSAGE), true)
    assert.deepEqual(await personalDataStillPresent(customer), [])
  })
})

async function provisionCustomer (email: string, answer: string): Promise<Customer> {
  const registered = await register(app, { email, password: PASSWORD })
  const userId = registered.body.data.id as number
  const { token, bid } = await login(app, { email, password: PASSWORD })
  const auth = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

  const answerRes = await request(app)
    .post('/api/SecurityAnswers')
    .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
    .send({ UserId: userId, SecurityQuestionId: 1, answer })
  assert.equal(answerRes.status, 201)

  const street = `Erasure Lane ${userId}`
  const addressRes = await request(app).post('/api/Addresss').set(auth).send({
    fullName: `Customer ${userId}`,
    mobileNum: 5550100000 + userId,
    zipCode: '10115',
    streetAddress: street,
    city: 'Berlin',
    state: 'BE',
    country: 'DE'
  })
  assert.equal(addressRes.status, 201)

  const cardNum = 4000000000000000 + userId
  const cardRes = await request(app).post('/api/Cards').set(auth).send({
    fullName: `Customer ${userId}`,
    cardNum,
    expMonth: 1,
    expYear: 2085
  })
  assert.equal(cardRes.status, 201)

  const caption = `erasure-memory-${userId}`
  const memoryRes = await request(app)
    .post('/rest/memories')
    .set('Authorization', 'Bearer ' + token)
    .attach('image', path.resolve(__dirname, '../files/validProfileImage.jpg'), 'memory.jpg')
    .field('caption', caption)
  assert.equal(memoryRes.status, 200)

  const review = `erasure-review-${userId}`
  const reviewRes = await request(app)
    .put('/rest/products/1/reviews')
    .send({ message: review, author: email })
  assert.equal(reviewRes.status, 201)

  const itemRes = await request(app)
    .post('/api/BasketItems')
    .set(auth)
    .send({ BasketId: bid, ProductId: 1, quantity: 1 })
  assert.equal(itemRes.status, 200)

  const orderRes = await request(app)
    .post('/rest/basket/' + bid + '/checkout')
    .set(auth)
  assert.equal(orderRes.status, 200)
  const orderId = orderRes.body.orderConfirmation as string
  assert.equal(typeof orderId, 'string')
  orderPdfs.push(orderId)

  const history = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: 'Bearer ' + token })
  assert.equal(history.status, 200)
  assert.equal(JSON.stringify(history.body).includes(orderId), true)

  const customer = { email, answer, userId, token, street, cardNum, caption, review, orderId }
  await assertPersonalDataPresent(customer)
  return customer
}

async function postErasure (customer: Customer, body: { email: string, securityAnswer: string, layout?: string }) {
  const form = await request(app)
    .get('/dataerasure/')
    .set({ Cookie: 'token=' + customer.token })
  assert.equal(form.status, 200)
  assert.equal(form.text.includes(customer.email), true)

  return await request(app)
    .post('/dataerasure/')
    .set({ Cookie: 'token=' + customer.token })
    .type('form')
    .send(body)
}

async function refusalProblems (res: { text: string, headers: Record<string, string | string[] | undefined> }, userId: number, privacyRequestsBefore: number, forbidLayout = false): Promise<string[]> {
  const problems: string[] = []
  if (res.text.includes(PROCESSED_MESSAGE)) problems.push('reports that the erasure will be processed')
  if (forbidLayout && res.text.includes(LAYOUT_MARKER)) problems.push('returns local file contents')
  if (setsTokenCookie(res)) problems.push('clears the session cookie')
  const privacyRequestsAfter = await PrivacyRequestModel.count({ where: { UserId: userId } })
  if (privacyRequestsAfter !== privacyRequestsBefore) problems.push('stores a privacy request')
  return problems
}

function setsTokenCookie (res: { headers: Record<string, string | string[] | undefined> }): boolean {
  const header = res.headers['set-cookie']
  const values = header == null ? [] : (Array.isArray(header) ? header : [header])
  return values.some(value => /^token=/i.test(value))
}

async function assertCanLogin (customer: Customer) {
  const res = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email: customer.email, password: PASSWORD })
  assert.equal(res.status, 200)
}

async function assertPersonalDataPresent (customer: Customer) {
  const user = await UserModel.findOne({ where: { email: customer.email }, paranoid: false })
  assert.ok(user)
  assert.equal(user.id, customer.userId)

  const address = await AddressModel.findOne({ where: { streetAddress: customer.street } })
  assert.ok(address)
  assert.equal(address.UserId, customer.userId)

  const card = await CardModel.findOne({ where: { cardNum: customer.cardNum } })
  assert.ok(card)
  assert.equal(card.UserId, customer.userId)

  const memory = await MemoryModel.findOne({ where: { caption: customer.caption } })
  assert.ok(memory)
  assert.equal(memory.UserId, customer.userId)
  const memories = await request(app).get('/rest/memories')
  assert.equal(memories.status, 200)
  assert.equal(JSON.stringify(memories.body).includes(customer.caption), true)

  const reviews = await matchingDocuments(reviewsCollection, { author: customer.email, message: customer.review })
  assert.ok(reviews.length > 0)
  const reviewList = await request(app).get('/rest/products/1/reviews')
  assert.equal(reviewList.status, 200)
  assert.equal(JSON.stringify(reviewList.body).includes(customer.review), true)

  const orders = await matchingDocuments(ordersCollection, { orderId: customer.orderId })
  assert.equal(orders.length, 1)
  const storedOrderEmail = customer.email.replace(/[aeiou]/gi, '*')
  assert.equal(orderEmail(orders[0]), storedOrderEmail)
}

async function personalDataStillPresent (customer: Customer): Promise<string[]> {
  const present: string[] = []
  const user = await UserModel.findOne({ where: { email: customer.email }, paranoid: false })
  if (user != null) present.push('user')

  const address = await AddressModel.findOne({ where: { streetAddress: customer.street } })
  if (address != null) present.push('address')

  const card = await CardModel.findOne({ where: { cardNum: customer.cardNum } })
  if (card != null) present.push('card')

  const memory = await MemoryModel.findOne({ where: { caption: customer.caption } })
  if (memory != null) present.push('memory')
  const memories = await request(app).get('/rest/memories')
  if (JSON.stringify(memories.body).includes(customer.caption)) present.push('photo-wall')

  const reviews = await matchingDocuments(reviewsCollection, { message: customer.review })
  const authored = await matchingDocuments(reviewsCollection, { author: customer.email })
  const reviewList = await request(app).get('/rest/products/1/reviews')
  if (reviews.length > 0 || authored.length > 0 || JSON.stringify(reviewList.body).includes(customer.review)) present.push('review')

  const orders = await matchingDocuments(ordersCollection, { orderId: customer.orderId })
  const storedOrderEmail = customer.email.replace(/[aeiou]/gi, '*')
  const identified = await matchingDocuments(ordersCollection, { email: storedOrderEmail })
  if (orders.length > 0 || identified.length > 0) present.push('order')

  const loginRes = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email: customer.email, password: PASSWORD })
  if (loginRes.status === 200) present.push('login')
  return present
}

function orderEmail (order: unknown): string | undefined {
  if (order != null && typeof order === 'object' && 'email' in order && typeof order.email === 'string') {
    return order.email
  }
  return undefined
}

async function matchingDocuments (collection: { find: (query: Record<string, string>) => Promise<unknown> | { toArray?: () => Promise<unknown> } }, query: Record<string, string>): Promise<unknown[]> {
  const found = await collection.find(query)
  if (Array.isArray(found)) {
    return found
  }
  if (found != null && typeof found === 'object' && 'toArray' in found && typeof found.toArray === 'function') {
    const docs = await found.toArray()
    return Array.isArray(docs) ? docs : []
  }
  return []
}

function removeOrderPdf (orderId: string) {
  const pdf = path.resolve('ftp', `order_${orderId}.pdf`)
  if (fs.existsSync(pdf)) {
    fs.unlinkSync(pdf)
  }
}
