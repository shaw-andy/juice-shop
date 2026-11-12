/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { Op } from 'sequelize'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { BasketItemModel } from '../../models/basketitem'
import { ComplaintModel } from '../../models/complaint'
import { ProductModel } from '../../models/product'
import { RecycleModel } from '../../models/recycle'
import { PrivacyRequestModel } from '../../models/privacyRequests'
import { FeedbackModel } from '../../models/feedback'

const PLACEHOLDER_PASSWORD = 'placeholder-password'
const MARKER = 'placeholder-interim-gate'

let app: Express
let interimToken = ''
let interimUserId = 0
let sessionToken = ''

function bearer (token: string) {
  return {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
}

function orderPdfs () {
  return fs.readdirSync(path.resolve('ftp')).filter((name) => name.startsWith('order_') && name.endsWith('.pdf'))
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const seeded = await UserModel.findOne({
    where: {
      totpSecret: { [Op.ne]: '' }
    }
  })
  assert.ok(seeded, 'expected a seeded account with two-factor turned on')
  assert.equal(seeded.role, 'admin')
  seeded.password = PLACEHOLDER_PASSWORD
  await seeded.save()
  interimUserId = seeded.id

  const loginRes = await request(app)
    .post('/rest/user/login')
    .set('content-type', 'application/json')
    .send({ email: seeded.email, password: PLACEHOLDER_PASSWORD })

  assert.equal(loginRes.status, 401)
  assert.equal(loginRes.body.status, 'totp_token_required')
  assert.equal(typeof loginRes.body.data?.tmpToken, 'string')
  interimToken = loginRes.body.data.tmpToken
  assert.equal(security.authenticatedUsers.get(interimToken), undefined)

  const email = 'placeholder-session@example.test'
  await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const session = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  sessionToken = session.token
  assert.equal(typeof sessionToken, 'string')
  assert.ok(security.authenticatedUsers.get(sessionToken))
}, { timeout: 60000 })

void describe('password-only two-factor token', () => {
  void it('is not a stored session', () => {
    assert.equal(security.authenticatedUsers.get(interimToken), undefined)
  })

  void it('still lets a completed login read /api/Users', async () => {
    const res = await request(app)
      .get('/api/Users')
      .set(bearer(sessionToken))

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length > 0)
  })

  void it('GET /api/Users refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/Users')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.notEqual(res.body?.status, 'success')
    assert.equal(res.body?.data, undefined)
  })

  void it('GET /api/Users/:id refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/Users/' + interimUserId)
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.notEqual(res.body?.status, 'success')
    assert.equal(res.body?.data, undefined)
  })

  void it('GET /api/BasketItems refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/BasketItems')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.notEqual(res.body?.status, 'success')
    assert.equal(res.body?.data, undefined)
  })

  void it('GET /api/BasketItems/:id refuses the interim token', async () => {
    const item = await BasketItemModel.findOne()
    assert.ok(item)

    const res = await request(app)
      .get('/api/BasketItems/' + item.id)
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.notEqual(res.body?.status, 'success')
    assert.equal(res.body?.data, undefined)
  })

  void it('DELETE /api/BasketItems/:id does not remove a basket line', async () => {
    const item = await BasketItemModel.findOne()
    assert.ok(item)
    const id = item.id

    const res = await request(app)
      .delete('/api/BasketItems/' + id)
      .set(bearer(interimToken))

    assert.ok(await BasketItemModel.findByPk(id))
    assert.equal(res.status, 401)
  })

  void it('POST /api/BasketItems does not add a basket line', async () => {
    const before = await BasketItemModel.count()

    const res = await request(app)
      .post('/api/BasketItems')
      .set(bearer(interimToken))
      .send({ BasketId: 1, ProductId: 1, quantity: 1 })

    assert.equal(await BasketItemModel.count(), before)
    assert.equal(res.status, 401)
  })

  void it('PUT /api/BasketItems/:id does not change a basket line', async () => {
    const item = await BasketItemModel.findOne()
    assert.ok(item)
    const quantity = item.quantity

    const res = await request(app)
      .put('/api/BasketItems/' + item.id)
      .set(bearer(interimToken))
      .send({ quantity: quantity + 1 })

    const again = await BasketItemModel.findByPk(item.id)
    assert.ok(again)
    assert.equal(again.quantity, quantity)
    assert.equal(res.status, 401)
  })

  void it('GET /api/Complaints refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.notEqual(res.body?.status, 'success')
    assert.equal(res.body?.data, undefined)
  })

  void it('POST /api/Complaints does not store a complaint', async () => {
    const before = await ComplaintModel.count()

    const res = await request(app)
      .post('/api/Complaints')
      .set(bearer(interimToken))
      .send({ message: MARKER + '-complaint', UserId: interimUserId })

    assert.equal(await ComplaintModel.count(), before)
    assert.equal(await ComplaintModel.count({ where: { message: MARKER + '-complaint' } }), 0)
    assert.equal(res.status, 401)
  })

  void it('GET /rest/user/authentication-details refuses the interim token', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.notEqual(res.body?.status, 'success')
    assert.equal(res.body?.data, undefined)
  })

  void it('POST /b2b/v2/orders does not process the order body', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(bearer(interimToken))
      .send({ cid: MARKER + '-order' })

    assert.equal(res.body?.orderNo, undefined)
    assert.equal(res.body?.cid, undefined)
    assert.equal(res.body?.paymentDue, undefined)
    assert.equal(res.status, 401)
  })

  void it('POST /api/Products does not create a product', async () => {
    const before = await ProductModel.count()

    const res = await request(app)
      .post('/api/Products')
      .set(bearer(interimToken))
      .send({
        name: MARKER + '-product',
        description: 'placeholder',
        price: 1,
        image: 'placeholder.jpg'
      })

    assert.equal(await ProductModel.count(), before)
    assert.equal(await ProductModel.count({ where: { name: MARKER + '-product' } }), 0)
    assert.equal(res.status, 401)
  })

  void it('POST /api/Recycles does not create a recycle request', async () => {
    const before = await RecycleModel.count()

    const res = await request(app)
      .post('/api/Recycles')
      .set(bearer(interimToken))
      .send({
        quantity: 1,
        AddressId: 1,
        isPickup: true,
        date: '2017-05-31'
      })

    assert.equal(await RecycleModel.count(), before)
    assert.equal(res.status, 401)
  })

  void it('POST /api/PrivacyRequests does not create a privacy request', async () => {
    const before = await PrivacyRequestModel.count()

    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(bearer(interimToken))
      .send({ UserId: interimUserId, deletionRequested: true })

    assert.equal(await PrivacyRequestModel.count(), before)
    assert.equal(res.status, 401)
  })

  void it('GET /api/PrivacyRequests refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.equal(res.body?.data, undefined)
  })

  void it('GET /api/Feedbacks/:id refuses the interim token', async () => {
    const feedback = await FeedbackModel.findOne()
    assert.ok(feedback)

    const res = await request(app)
      .get('/api/Feedbacks/' + feedback.id)
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.equal(res.body?.data, undefined)
  })

  void it('PUT /api/Feedbacks/:id does not change feedback', async () => {
    const feedback = await FeedbackModel.findOne()
    assert.ok(feedback)
    const comment = feedback.comment

    const res = await request(app)
      .put('/api/Feedbacks/' + feedback.id)
      .set(bearer(interimToken))
      .send({ comment: MARKER + '-feedback', rating: 1 })

    const again = await FeedbackModel.findByPk(feedback.id)
    assert.ok(again)
    assert.equal(again.comment, comment)
    assert.equal(res.status, 401)
  })

  void it('DELETE /api/Feedbacks/:id does not delete feedback', async () => {
    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)

    const created = await request(app)
      .post('/api/Feedbacks')
      .set('content-type', 'application/json')
      .send({
        comment: MARKER + '-feedback-delete',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(created.status, 201)
    const id = created.body.data.id

    const res = await request(app)
      .delete('/api/Feedbacks/' + id)
      .set(bearer(interimToken))

    assert.ok(await FeedbackModel.findByPk(id))
    assert.equal(res.status, 401)
  })

  void it('PATCH /rest/products/reviews does not change a review', async () => {
    const before = await request(app).get('/rest/products/1/reviews')
    assert.equal(before.status, 200)
    const review = before.body.data[0]
    assert.ok(review)
    const original = review.message

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(bearer(interimToken))
      .send({ id: review._id, message: MARKER + '-review' })

    const after = await request(app).get('/rest/products/1/reviews')
    const same = after.body.data.find((entry: { _id: string }) => entry._id === review._id)
    assert.ok(same)
    assert.equal(same.message, original)
    assert.equal(res.status, 401)
  })

  void it('POST /rest/products/reviews does not like a review', async () => {
    const before = await request(app).get('/rest/products/1/reviews')
    const review = before.body.data[0]
    assert.ok(review)

    const res = await request(app)
      .post('/rest/products/reviews')
      .set(bearer(interimToken))
      .send({ id: review._id })

    const after = await request(app).get('/rest/products/1/reviews')
    const same = after.body.data.find((entry: { _id: string }) => entry._id === review._id)
    assert.ok(same)
    assert.equal(same.likesCount, review.likesCount)
    assert.equal(res.status, 401)
  })

  void it('GET /rest/basket/:id refuses the interim token', async () => {
    const res = await request(app)
      .get('/rest/basket/1')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.equal(res.body?.Products, undefined)
  })

  void it('POST /rest/basket/:id/checkout does not write an order file', async () => {
    const before = new Set(orderPdfs())

    const res = await request(app)
      .post('/rest/basket/1/checkout')
      .set(bearer(interimToken))
      .send({})

    const created = orderPdfs().filter((name) => !before.has(name))
    assert.deepEqual(created, [])
    assert.equal(res.status, 401)
  })

  void it('POST /rest/basket/:id/order does not process an order', async () => {
    const res = await request(app)
      .post('/rest/basket/1/order')
      .set(bearer(interimToken))
      .send({})

    assert.equal(res.status, 401)
    assert.equal(res.body?.orderConfirmation, undefined)
  })

  void it('GET /rest/2fa/status refuses the interim token', async () => {
    const res = await request(app)
      .get('/rest/2fa/status')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
  })

  void it('POST /rest/2fa/setup does not change the two-factor secret', async () => {
    const before = await UserModel.findByPk(interimUserId)
    assert.ok(before)
    const unchanged = before.totpSecret

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set(bearer(interimToken))
      .send({ password: PLACEHOLDER_PASSWORD })

    assert.equal(res.status, 401)
    const after = await UserModel.findByPk(interimUserId)
    assert.ok(after)
    assert.ok(after.totpSecret === unchanged)
    assert.ok(after.totpSecret !== '')
  })

  void it('POST /rest/2fa/disable does not clear the two-factor secret', async () => {
    const before = await UserModel.findByPk(interimUserId)
    assert.ok(before)
    const unchanged = before.totpSecret

    const res = await request(app)
      .post('/rest/2fa/disable')
      .set(bearer(interimToken))
      .send({ password: PLACEHOLDER_PASSWORD })

    assert.equal(res.status, 401)
    const after = await UserModel.findByPk(interimUserId)
    assert.ok(after)
    assert.ok(after.totpSecret === unchanged)
    assert.ok(after.totpSecret !== '')
  })

  void it('GET /api/Cards refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/Cards')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.equal(res.body?.data, undefined)
  })

  void it('GET /api/Addresss refuses the interim token', async () => {
    const res = await request(app)
      .get('/api/Addresss')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
    assert.equal(res.body?.data, undefined)
  })

  void it('GET /rest/wallet/balance refuses the interim token', async () => {
    const res = await request(app)
      .get('/rest/wallet/balance')
      .set(bearer(interimToken))

    assert.equal(res.status, 401)
  })

  void it('is still absent from the session map after those calls', () => {
    assert.equal(security.authenticatedUsers.get(interimToken), undefined)
  })
})
