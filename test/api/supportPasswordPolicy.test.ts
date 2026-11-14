/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { loadStaticUserData } from '../../data/staticData'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const jsonHeader = { 'content-type': 'application/json' }

const oneCharacter = 'a'
const fiveCharacters = 'aaaaa'
const missingCharacterClass = 'Placeholder1'
const compliantPassword = 'Placeholder1!'
const customerPassword = 'customer-placeholder'
const tooLong = 'A'.repeat(12) + 'a1!' + 'b'.repeat(20)

let app: Express
let supportEmail = ''
let supportPassword = ''
let supportAnswer = ''

before(async () => {
  const result = await createTestApp()
  app = result.app
  const seeded = await loadStaticUserData()
  const support = seeded.find((user) => user.key === 'support')
  if (support?.password == null || support.securityQuestion?.answer == null) {
    throw new Error('Seeded support account is missing from data/static/users.yml')
  }
  const domain = config.get<string>('application.domain')
  supportEmail = support.customDomain === true ? support.email : `${support.email}@${domain}`
  supportPassword = support.password
  supportAnswer = support.securityQuestion.answer
  const row = await UserModel.findOne({ where: { email: supportEmail } })
  assert.ok(row)
  assert.equal(row.role, 'admin')
}, { timeout: 120000 })

beforeEach(async () => {
  const row = await UserModel.findOne({ where: { email: supportEmail } })
  assert.ok(row)
  await row.update({ password: supportPassword })
})

async function loginStatus (email: string, password: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  return res.status
}

async function passwordHash (email: string) {
  const row = await UserModel.findOne({ where: { email } })
  assert.ok(row)
  return row.password
}

async function changeSupportPassword (token: string, query: Record<string, string>) {
  return await request(app)
    .get('/rest/user/change-password')
    .query(query)
    .set({ Authorization: 'Bearer ' + token })
}

void describe('support administrator password policy', () => {
  void it('rejects a one-character password submitted with only the bearer token', async () => {
    const { token, umail } = await login(app, { email: supportEmail, password: supportPassword })
    assert.equal(umail, supportEmail)
    const before = await passwordHash(supportEmail)
    const decoyEmail = 'decoy-policy@juice-sh.op'
    await register(app, { email: decoyEmail, password: customerPassword })
    const decoyBefore = await passwordHash(decoyEmail)

    const res = await changeSupportPassword(token, {
      new: oneCharacter,
      repeat: oneCharacter,
      email: decoyEmail
    })

    assert.ok(res.status >= 400 && res.status < 500)
    assert.equal(await passwordHash(supportEmail), before)
    assert.equal(await passwordHash(decoyEmail), decoyBefore)
    assert.equal(await loginStatus(supportEmail, supportPassword), 200)
    assert.equal(await loginStatus(supportEmail, oneCharacter), 401)
    assert.equal(await loginStatus(decoyEmail, customerPassword), 200)
    assert.equal(await loginStatus(decoyEmail, oneCharacter), 401)
  })

  void it('rejects a five-character password submitted with the current password', async () => {
    const { token } = await login(app, { email: supportEmail, password: supportPassword })
    const before = await passwordHash(supportEmail)

    const res = await changeSupportPassword(token, {
      current: supportPassword,
      new: fiveCharacters,
      repeat: fiveCharacters
    })

    assert.ok(res.status >= 400 && res.status < 500)
    assert.equal(await passwordHash(supportEmail), before)
    assert.equal(await loginStatus(supportEmail, supportPassword), 200)
    assert.equal(await loginStatus(supportEmail, fiveCharacters), 401)
  })

  void it('rejects a password that misses a required character class', async () => {
    const { token } = await login(app, { email: supportEmail, password: supportPassword })
    const before = await passwordHash(supportEmail)

    const res = await changeSupportPassword(token, {
      current: supportPassword,
      new: missingCharacterClass,
      repeat: missingCharacterClass
    })

    assert.ok(res.status >= 400 && res.status < 500)
    assert.equal(await passwordHash(supportEmail), before)
    assert.equal(await loginStatus(supportEmail, supportPassword), 200)
    assert.equal(await loginStatus(supportEmail, missingCharacterClass), 401)
  })

  void it('rejects a password longer than the privileged policy', async () => {
    const { token } = await login(app, { email: supportEmail, password: supportPassword })
    const before = await passwordHash(supportEmail)

    const res = await changeSupportPassword(token, {
      current: supportPassword,
      new: tooLong,
      repeat: tooLong
    })

    assert.ok(res.status >= 400 && res.status < 500)
    assert.equal(await passwordHash(supportEmail), before)
    assert.notEqual(security.hash(tooLong), before)
    assert.equal(await loginStatus(supportEmail, supportPassword), 200)
    assert.equal(await loginStatus(supportEmail, tooLong), 401)
  })

  void it('stores a password that meets the privileged policy', async () => {
    const { token } = await login(app, { email: supportEmail, password: supportPassword })

    const res = await changeSupportPassword(token, {
      current: supportPassword,
      new: compliantPassword,
      repeat: compliantPassword
    })

    assert.equal(res.status, 200)
    assert.equal(await passwordHash(supportEmail), security.hash(compliantPassword))
    assert.equal(await loginStatus(supportEmail, compliantPassword), 200)
    assert.equal(await loginStatus(supportEmail, supportPassword), 401)
  })

  void it('rejects a one-character password when the support account is reset', async () => {
    const compliantReset = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: supportEmail,
        answer: supportAnswer,
        new: compliantPassword,
        repeat: compliantPassword
      })
    assert.equal(compliantReset.status, 200)
    assert.equal(await loginStatus(supportEmail, compliantPassword), 200)

    const row = await UserModel.findOne({ where: { email: supportEmail } })
    assert.ok(row)
    await row.update({ password: supportPassword })
    const before = await passwordHash(supportEmail)

    const weakReset = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: supportEmail,
        answer: supportAnswer,
        new: oneCharacter,
        repeat: oneCharacter
      })

    assert.ok(weakReset.status >= 400 && weakReset.status < 500)
    assert.equal(await passwordHash(supportEmail), before)
    assert.equal(await loginStatus(supportEmail, supportPassword), 200)
    assert.equal(await loginStatus(supportEmail, oneCharacter), 401)
  })
})
