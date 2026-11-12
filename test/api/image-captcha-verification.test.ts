/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import crypto from 'node:crypto'
import request, { type Response } from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { ImageCaptchaModel } from '../../models/imageCaptcha'
import { UserModel } from '../../models/user'
import { ordersCollection } from '../../data/mongodb'

const PLACEHOLDER_PASSWORD = 'placeholder-password'
const CAPTCHA_WINDOW_MS = 300000

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('image CAPTCHA on data export', { concurrency: 1 }, () => {
  void it('does not reveal the answer and rejects an export that submits the creation response', async () => {
    const account = await registerAndLogin(uniqueEmail('leak'))
    const orderId = uniqueOrderId()
    await insertMarkedOrder(account.email, orderId)

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(account.authHeader)

    const exportRes = await request(app)
      .post('/rest/user/data-export')
      .set(account.authHeader)
      .send({ answer: captchaRes.body.answer, format: '1' })

    const stored = await latestCaptcha(account.userId)
    const problems: string[] = []
    if (captchaRes.status !== 200 || typeof captchaRes.body.image !== 'string' || !captchaRes.body.image.includes('<svg')) {
      problems.push('CAPTCHA image was not issued')
    }
    if (Object.prototype.hasOwnProperty.call(captchaRes.body, 'answer') || captchaRes.body.answer === stored.answer) {
      problems.push('creation response included the stored answer')
    }
    for (const [key, value] of Object.entries(captchaRes.body)) {
      if (key === 'image') {
        if (String(value).includes('>' + stored.answer + '<')) problems.push('image contained the answer text')
      } else if (value === stored.answer) {
        problems.push('response field ' + key + ' was the stored answer')
      }
    }
    if (!(exportRes.status >= 400 && exportRes.status < 500) || exportBodyLeaks(exportRes, orderId)) {
      problems.push('export that submitted the creation response was not refused: ' + String(exportRes.status))
    }
    assertNoExportFile(orderId)
    assert.deepEqual(problems, [])
  })

  void it('rejects repeated exports when the caller has no CAPTCHA, including masked-email orders', async () => {
    const account = await registerAndLogin(uniqueEmail('missing'))
    const orderId = uniqueOrderId()
    await insertMarkedOrder(account.email, orderId)

    const first = await exportData(account.authHeader, {})
    const second = await exportData(account.authHeader, { answer: '', format: '1' })

    assertNoExportFile(orderId)
    assertExportClosed(first, orderId)
    assertNoExportFile(orderId)
    assertExportClosed(second, orderId)
  })

  void it('accepts the stored answer once, then rejects a repeat and a concurrent second check', async () => {
    const account = await registerAndLogin(uniqueEmail('once'))
    const orderId = uniqueOrderId()
    await insertMarkedOrder(account.email, orderId)
    const stored = await issueCaptcha(account)

    const first = await exportData(account.authHeader, { answer: stored.answer, format: '1' })
    assertExportReturnedOrder(first, orderId, account.email)

    const repeat = await exportData(account.authHeader, { answer: stored.answer, format: '1' })
    assertNoExportFile(orderId)
    assertExportClosed(repeat, orderId)
  })

  void it('lets only one of two overlapping checks consume the same CAPTCHA', async () => {
    const account = await registerAndLogin(uniqueEmail('race'))
    const orderId = uniqueOrderId()
    await insertMarkedOrder(account.email, orderId)
    const stored = await issueCaptcha(account)

    const raced = await Promise.all([
      exportData(account.authHeader, { answer: stored.answer, format: '1' }),
      exportData(account.authHeader, { answer: stored.answer, format: '1' })
    ])
    const successes = raced.filter(res => res.status === 200)
    assert.equal(successes.length, 1, 'overlapping checks returned ' + raced.map(res => String(res.status)).join(' and '))
    assertExportReturnedOrder(successes[0], orderId, account.email)
    for (const res of raced) {
      if (res.status !== 200) {
        assertNoExportFile(orderId)
        assertExportClosed(res, orderId)
      }
    }
  })

  void it('rejects a correct answer after one failed check has consumed the CAPTCHA', async () => {
    const account = await registerAndLogin(uniqueEmail('consume'))
    const orderId = uniqueOrderId()
    await insertMarkedOrder(account.email, orderId)
    const stored = await issueCaptcha(account)

    const wrong = await exportData(account.authHeader, { answer: 'not-the-captcha', format: '1' })
    assertExportClosed(wrong, orderId)

    const later = await exportData(account.authHeader, { answer: stored.answer, format: '1' })
    assertNoExportFile(orderId)
    assertExportClosed(later, orderId)
  })

  void it('rejects an expired CAPTCHA even when the posted answer matches the old row', async () => {
    const account = await registerAndLogin(uniqueEmail('expired'))
    const orderId = uniqueOrderId()
    await insertMarkedOrder(account.email, orderId)
    const stored = await issueCaptcha(account)
    const expiredAt = new Date(Date.now() - CAPTCHA_WINDOW_MS - 5000)
    await ageCaptcha(stored, expiredAt)
    assert.equal(stored.createdAt.getTime() <= Date.now() - CAPTCHA_WINDOW_MS, true)

    const withAnswer = await exportData(account.authHeader, { answer: stored.answer, format: '1' })
    const withoutAnswer = await exportData(account.authHeader, { format: '1' })

    assertNoExportFile(orderId)
    assertExportClosed(withAnswer, orderId)
    assertExportClosed(withoutAnswer, orderId)
  })

  void it('does not authorize an export with another user CAPTCHA answer', async () => {
    const caller = await registerAndLogin(uniqueEmail('caller'))
    const other = await registerAndLogin(uniqueEmail('other'))
    const callerOrderId = uniqueOrderId()
    const otherOrderId = uniqueOrderId()
    await insertMarkedOrder(caller.email, callerOrderId)
    await insertMarkedOrder(other.email, otherOrderId)
    const callerCaptcha = await issueCaptcha(caller)
    const otherCaptcha = await issueCaptcha(other)

    const ownAnswer = await exportData(caller.authHeader, { answer: callerCaptcha.answer, format: '1' })
    assertExportReturnedOrder(ownAnswer, callerOrderId, caller.email)
    assert.equal(ownAnswer.body.userData.includes(otherOrderId), false)

    const swapped = await exportData(caller.authHeader, {
      answer: otherCaptcha.answer,
      UserId: other.userId,
      format: '1'
    })
    assertNoExportFile(callerOrderId)
    assertExportClosed(swapped, callerOrderId)
    assert.equal(exportBodyLeaks(swapped, otherOrderId), false)

    const stranger = await registerAndLogin(uniqueEmail('stranger'))
    const strangerOrderId = uniqueOrderId()
    await insertMarkedOrder(stranger.email, strangerOrderId)
    const usingOtherAnswer = await exportData(stranger.authHeader, { answer: otherCaptcha.answer, format: '1' })
    assertNoExportFile(strangerOrderId)
    assertExportClosed(usingOtherAnswer, strangerOrderId)
  })
})

async function registerAndLogin (email: string) {
  const created = await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({
      email,
      password: PLACEHOLDER_PASSWORD,
      passwordRepeat: PLACEHOLDER_PASSWORD
    })
  assert.equal(created.status, 201)

  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)

  return {
    email,
    userId: user.id,
    authHeader: { Authorization: 'Bearer ' + authentication.token, 'content-type': 'application/json' }
  }
}

async function issueCaptcha (account: { authHeader: Record<string, string>, userId: number }) {
  const captchaRes = await request(app)
    .get('/rest/image-captcha')
    .set(account.authHeader)
  assert.equal(captchaRes.status, 200)
  return await latestCaptcha(account.userId)
}

async function ageCaptcha (captcha: InstanceType<typeof ImageCaptchaModel>, createdAt: Date) {
  const model = captcha.constructor as typeof ImageCaptchaModel & { _readOnlyAttributes: Set<string> }
  model._readOnlyAttributes.delete('createdAt')
  try {
    await captcha.update({ createdAt })
  } finally {
    model._readOnlyAttributes.add('createdAt')
  }
  await captcha.reload()
}

async function latestCaptcha (userId: number) {
  const stored = await ImageCaptchaModel.findOne({
    where: { UserId: userId },
    order: [['createdAt', 'DESC']]
  })
  assert.ok(stored)
  assert.equal(typeof stored.answer, 'string')
  assert.equal(stored.answer.length > 0, true)
  return stored
}

async function insertMarkedOrder (email: string, orderId: string) {
  await ordersCollection.insert({
    orderId,
    email: email.replace(/[aeiou]/gi, '*'),
    totalPrice: 1,
    products: [],
    bonus: 0,
    eta: '5',
    delivered: false
  })
}

function exportData (authHeader: Record<string, string>, body: Record<string, unknown>) {
  return request(app)
    .post('/rest/user/data-export')
    .set(authHeader)
    .send(body)
}

function exportBodyLeaks (res: Response, orderId: string) {
  const userData = typeof res.body?.userData === 'string' ? res.body.userData : ''
  return userData.includes(orderId) || res.text.includes(orderId)
}

function assertExportClosed (res: Response, orderId: string) {
  const leakNote = exportBodyLeaks(res, orderId) ? ' and the response included the masked-email order' : ''
  assert.equal(res.status >= 400 && res.status < 500, true, 'expected the export to be refused, got ' + String(res.status) + leakNote)
  assert.equal(exportBodyLeaks(res, orderId), false)
  assert.equal(res.body?.confirmation, undefined)
  assert.equal(res.body?.userData, undefined)
}

function assertExportReturnedOrder (res: Response, orderId: string, email: string) {
  assert.equal(res.status, 200)
  assert.equal(typeof res.body.userData, 'string')
  const parsed = JSON.parse(res.body.userData) as {
    email?: string
    orders?: Array<{ orderId?: string }>
  }
  assert.equal(parsed.email, email)
  assert.equal(parsed.orders?.some(order => order.orderId === orderId), true)
}

function assertNoExportFile (orderId: string) {
  const created = fs.readdirSync('ftp').filter(name => name.includes(orderId))
  assert.deepEqual(created, [])
}

function uniqueEmail (label: string) {
  return 'captcha-' + label + '-' + crypto.randomBytes(8).toString('hex') + '@example.test'
}

function uniqueOrderId () {
  return 'order-marker-' + crypto.randomBytes(8).toString('hex')
}
