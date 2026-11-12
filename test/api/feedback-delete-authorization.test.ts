/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'

interface FeedbackRow {
  id: number
  comment: string | null
  rating: number
  UserId: number | null
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function listFeedback (): Promise<FeedbackRow[]> {
  const res = await request(app).get('/api/Feedbacks')
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

async function registerCustomer (label: string) {
  const email = `${label}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`
  const registered = await register(app, { email, password: placeholderPassword })
  assert.equal(registered.body?.data?.role, 'customer')
  assert.equal(typeof registered.body.data.id, 'number')
  const authentication = await login(app, { email, password: placeholderPassword })
  assert.equal(typeof authentication.token, 'string')
  assert.ok(authentication.token.length > 0)
  return { id: registered.body.data.id as number, token: authentication.token as string }
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function captchaFields () {
  const captchaRes = await request(app).get('/rest/captcha')
  assert.equal(captchaRes.status, 200)
  return { captchaId: captchaRes.body.captchaId, captcha: captchaRes.body.answer }
}

async function createFeedback (userId: number, comment: string): Promise<FeedbackRow> {
  const captcha = await captchaFields()
  const res = await request(app)
    .post('/api/Feedbacks')
    .set(jsonHeader)
    .send({
      comment,
      rating: 1,
      UserId: userId,
      captchaId: captcha.captchaId,
      captcha: captcha.captcha
    })
  assert.equal(res.status, 201)
  assert.equal(res.body.data.UserId, userId)
  assert.equal(res.body.data.comment, comment)
  return res.body.data
}

function assertSameFeedback (actual: FeedbackRow | undefined, expected: FeedbackRow) {
  assert.ok(actual)
  assert.equal(actual.id, expected.id)
  assert.equal(actual.comment, expected.comment)
  assert.equal(actual.rating, expected.rating)
  assert.equal(actual.UserId, expected.UserId)
}

function assertRejected (status: number) {
  assert.equal(status === 401 || status === 403, true, `status ${status}`)
}

void describe('feedback delete authorization', { concurrency: 1 }, () => {
  void it('a signed-in customer cannot delete feedback ids from the public list', async () => {
    const before = await listFeedback()
    assert.ok(before.length > 1)
    assert.ok(before.some(row => row.UserId === null))
    assert.ok(before.some(row => row.UserId !== null))

    const customer = await registerCustomer('feedback-reader')
    assert.ok(before.every(row => row.UserId !== customer.id))

    for (const row of before) {
      const del = await request(app)
        .delete('/api/Feedbacks/' + row.id)
        .set(bearer(customer.token))

      const byId = await request(app)
        .get('/api/Feedbacks/' + row.id)
        .set(bearer(customer.token))
      assert.equal(byId.status, 200)
      assertSameFeedback(byId.body.data, row)
      assertRejected(del.status)
    }

    const after = await listFeedback()
    for (const row of before) {
      assertSameFeedback(after.find(candidate => candidate.id === row.id), row)
    }
  })

  void it('a customer cannot delete another customer row when the body and query name the caller row', async () => {
    const victim = await registerCustomer('feedback-victim')
    const attacker = await registerCustomer('feedback-attacker')
    const victimRow = await createFeedback(victim.id, 'victim feedback must stay')
    const attackerRow = await createFeedback(attacker.id, 'attacker feedback is a different row')
    assert.notEqual(victimRow.id, attackerRow.id)

    const del = await request(app)
      .delete('/api/Feedbacks/' + victimRow.id)
      .query({ id: attackerRow.id })
      .set(bearer(attacker.token))
      .send({ id: attackerRow.id })

    const after = await listFeedback()
    assertSameFeedback(after.find(row => row.id === victimRow.id), victimRow)
    assertSameFeedback(after.find(row => row.id === attackerRow.id), attackerRow)
    assertRejected(del.status)
  })

  void it('deleting the caller own id does not remove a different id named in the body or query', async () => {
    const victim = await registerCustomer('feedback-other')
    const attacker = await registerCustomer('feedback-owner')
    const victimRow = await createFeedback(victim.id, 'other customer feedback stays')
    const attackerRow = await createFeedback(attacker.id, 'caller own feedback')

    const del = await request(app)
      .delete('/api/Feedbacks/' + attackerRow.id)
      .query({ id: victimRow.id })
      .set(bearer(attacker.token))
      .send({ id: victimRow.id })

    const after = await listFeedback()
    assertSameFeedback(after.find(row => row.id === victimRow.id), victimRow)
    assertSameFeedback(after.find(row => row.id === attackerRow.id), attackerRow)
    assertRejected(del.status)
  })

  void it('PATCH and collection DELETE do not remove a feedback row', async () => {
    const owner = await registerCustomer('feedback-patch')
    const row = await createFeedback(owner.id, 'patch must not remove this')
    const customer = await registerCustomer('feedback-patch-caller')

    const patched = await request(app)
      .patch('/api/Feedbacks/' + row.id)
      .set(bearer(customer.token))
      .send({ id: row.id, comment: 'replaced', rating: 1 })
    assert.ok(patched.status >= 400, `status ${patched.status}`)

    const collection = await request(app)
      .delete('/api/Feedbacks')
      .set(bearer(customer.token))
      .send({ id: row.id })
    assert.ok(collection.status >= 400, `status ${collection.status}`)

    const after = await listFeedback()
    assertSameFeedback(after.find(candidate => candidate.id === row.id), row)
  })
})
