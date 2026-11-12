/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import { QueryTypes, type Sequelize } from 'sequelize'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const sharedPassword = 'placeholder-password'
const rotatedPassword = 'placeholder-password-rotated'
const securityAnswer = 'placeholder-answer'
const jsonHeader = { 'content-type': 'application/json' }

let app: Express
let sequelize: Sequelize

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

function unsaltedMd5 (password: string): string {
  return crypto.createHash('md5').update(password).digest('hex')
}

function assertNotUnsaltedMd5 (stored: string, password: string) {
  assert.equal(typeof stored, 'string')
  assert.ok(stored.length > 0)
  assert.notEqual(stored, password)
  assert.notEqual(stored, unsaltedMd5(password))
}

async function storedPassword (email: string): Promise<string> {
  const rows = await sequelize.query<{ password: string }>(
    'SELECT password FROM Users WHERE email = ? AND deletedAt IS NULL',
    { replacements: [email], type: QueryTypes.SELECT }
  )
  assert.equal(rows.length, 1)
  return rows[0].password
}

async function passwordFromProductSearch (email: string): Promise<string> {
  const q = `')) union select id,'2','3',email,password,'6','7','8','9' from Users where email='${email}'--`
  assert.ok(q.length <= 200)
  const res = await request(app)
    .get('/rest/products/search?q=' + encodeURIComponent(q))
  assert.equal(res.status, 200)
  const row = res.body.data.find((item: { price?: string }) => item.price === email)
  assert.ok(row, 'product search did not return the user row')
  return String(row.deluxePrice)
}

async function registerUser (email: string, password: string): Promise<number> {
  const res = await request(app)
    .post('/api/Users/')
    .set(jsonHeader)
    .send({ email, password, passwordRepeat: password })
  assert.equal(res.status, 201)
  assert.equal(typeof res.body.data.id, 'number')
  return res.body.data.id
}

async function loginStatus (email: string, password: string): Promise<number> {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  return res.status
}

async function insertLegacyMd5User (email: string, password: string): Promise<string> {
  const digest = unsaltedMd5(password)
  await sequelize.query(
    `INSERT INTO Users (username, email, password, role, deluxeToken, lastLoginIp, profileImage, totpSecret, isActive, createdAt, updatedAt)
     VALUES ('', ?, ?, 'customer', '', '0.0.0.0', '/assets/public/images/uploads/default.svg', '', 1, datetime('now'), datetime('now'))`,
    { replacements: [email, digest] }
  )
  return digest
}

void describe('password storage', () => {
  void it('registration stores a password that is not an unsalted MD5 digest, and product search returns that stored value', async () => {
    const email = 'pwspec-register@example.test'
    await registerUser(email, sharedPassword)

    assert.equal(await loginStatus(email, sharedPassword), 200)
    assert.equal(await loginStatus(email, sharedPassword + '-wrong'), 401)

    const stored = await storedPassword(email)
    const leaked = await passwordFromProductSearch(email)
    assert.equal(leaked, stored)
    assertNotUnsaltedMd5(stored, sharedPassword)
  })

  void it('two registrations of the same password do not share one stored digest', async () => {
    const emailA = 'pwspec-salt-a@example.test'
    const emailB = 'pwspec-salt-b@example.test'
    await registerUser(emailA, sharedPassword)
    await registerUser(emailB, sharedPassword)

    const storedA = await storedPassword(emailA)
    const storedB = await storedPassword(emailB)
    assert.equal(await passwordFromProductSearch(emailA), storedA)
    assert.equal(await passwordFromProductSearch(emailB), storedB)
    assert.notEqual(storedA, storedB)
    assertNotUnsaltedMd5(storedA, sharedPassword)
    assertNotUnsaltedMd5(storedB, sharedPassword)
  })

  void it('User model creation stores distinct non-MD5 digests for the same password', async () => {
    const emailA = 'pwspec-model-a@example.test'
    const emailB = 'pwspec-model-b@example.test'
    await UserModel.create({ email: emailA, password: sharedPassword })
    await UserModel.create({ email: emailB, password: sharedPassword })

    assert.equal(await loginStatus(emailA, sharedPassword), 200)
    assert.equal(await loginStatus(emailB, sharedPassword), 200)

    const storedA = await storedPassword(emailA)
    const storedB = await storedPassword(emailB)
    assert.equal(await passwordFromProductSearch(emailA), storedA)
    assert.equal(await passwordFromProductSearch(emailB), storedB)
    assert.notEqual(storedA, storedB)
    assertNotUnsaltedMd5(storedA, sharedPassword)
    assertNotUnsaltedMd5(storedB, sharedPassword)
  })

  void it('change password keeps the new password usable and does not store an unsalted MD5 digest', async () => {
    const emailA = 'pwspec-change-a@example.test'
    const emailB = 'pwspec-change-b@example.test'
    await registerUser(emailA, sharedPassword)
    await registerUser(emailB, sharedPassword)

    for (const email of [emailA, emailB]) {
      const loginRes = await request(app)
        .post('/rest/user/login')
        .set(jsonHeader)
        .send({ email, password: sharedPassword })
      assert.equal(loginRes.status, 200)
      const token = loginRes.body.authentication.token

      const rejected = await request(app)
        .get('/rest/user/change-password')
        .query({ current: sharedPassword + '-wrong', new: rotatedPassword, repeat: rotatedPassword })
        .set({ Authorization: 'Bearer ' + token })
      assert.equal(rejected.status, 401)

      const changed = await request(app)
        .get('/rest/user/change-password')
        .query({ current: sharedPassword, new: rotatedPassword, repeat: rotatedPassword })
        .set({ Authorization: 'Bearer ' + token })
      assert.equal(changed.status, 200)
    }

    assert.equal(await loginStatus(emailA, rotatedPassword), 200)
    assert.equal(await loginStatus(emailB, rotatedPassword), 200)
    assert.equal(await loginStatus(emailA, sharedPassword), 401)

    const storedA = await storedPassword(emailA)
    const storedB = await storedPassword(emailB)
    assert.equal(await passwordFromProductSearch(emailA), storedA)
    assert.equal(await passwordFromProductSearch(emailB), storedB)
    assert.notEqual(storedA, storedB)
    assertNotUnsaltedMd5(storedA, rotatedPassword)
    assertNotUnsaltedMd5(storedB, rotatedPassword)
  })

  void it('reset password keeps the new password usable and does not store an unsalted MD5 digest', async () => {
    const emailA = 'pwspec-reset-a@example.test'
    const emailB = 'pwspec-reset-b@example.test'
    const idA = await registerUser(emailA, sharedPassword)
    const idB = await registerUser(emailB, sharedPassword)
    const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

    for (const userId of [idA, idB]) {
      const answer = await request(app)
        .post('/api/SecurityAnswers')
        .set(authHeader)
        .send({ UserId: userId, SecurityQuestionId: 1, answer: securityAnswer })
      assert.equal(answer.status, 201)
    }

    for (const email of [emailA, emailB]) {
      const rejected = await request(app)
        .post('/rest/user/reset-password')
        .set(jsonHeader)
        .send({ email, answer: securityAnswer + '-wrong', new: rotatedPassword, repeat: rotatedPassword })
      assert.equal(rejected.status, 401)

      const reset = await request(app)
        .post('/rest/user/reset-password')
        .set(jsonHeader)
        .send({ email, answer: securityAnswer, new: rotatedPassword, repeat: rotatedPassword })
      assert.equal(reset.status, 200)
    }

    assert.equal(await loginStatus(emailA, rotatedPassword), 200)
    assert.equal(await loginStatus(emailB, rotatedPassword), 200)
    assert.equal(await loginStatus(emailA, sharedPassword), 401)

    const storedA = await storedPassword(emailA)
    const storedB = await storedPassword(emailB)
    assert.equal(await passwordFromProductSearch(emailA), storedA)
    assert.equal(await passwordFromProductSearch(emailB), storedB)
    assert.notEqual(storedA, storedB)
    assertNotUnsaltedMd5(storedA, rotatedPassword)
    assertNotUnsaltedMd5(storedB, rotatedPassword)
  })

  void it('two-factor setup and disable accept the real password while the stored digest is not unsalted MD5', async () => {
    const email = 'pwspec-2fa@example.test'
    const secret = generateSecret()
    await registerUser(email, sharedPassword)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: sharedPassword })
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const wrongSetup = await request(app)
      .post('/rest/2fa/setup')
      .set(authHeader)
      .send({
        password: sharedPassword + '-wrong',
        setupToken: security.authorize({ secret, type: 'totp_setup_secret' }),
        initialToken: generateSync({ secret })
      })
    assert.equal(wrongSetup.status, 401)

    const setup = await request(app)
      .post('/rest/2fa/setup')
      .set(authHeader)
      .send({
        password: sharedPassword,
        setupToken: security.authorize({ secret, type: 'totp_setup_secret' }),
        initialToken: generateSync({ secret })
      })
    assert.equal(setup.status, 200)

    const wrongDisable = await request(app)
      .post('/rest/2fa/disable')
      .set(authHeader)
      .send({ password: sharedPassword + '-wrong' })
    assert.equal(wrongDisable.status, 401)

    const disable = await request(app)
      .post('/rest/2fa/disable')
      .set(authHeader)
      .send({ password: sharedPassword })
    assert.equal(disable.status, 200)

    const stored = await storedPassword(email)
    assert.equal(await passwordFromProductSearch(email), stored)
    assertNotUnsaltedMd5(stored, sharedPassword)
  })

  void it('replaces an existing unsalted MD5 digest on the next successful login', async () => {
    const emailA = 'pwspec-legacy-a@example.test'
    const emailB = 'pwspec-legacy-b@example.test'
    const digest = await insertLegacyMd5User(emailA, sharedPassword)
    assert.equal(await insertLegacyMd5User(emailB, sharedPassword), digest)

    assert.equal(await passwordFromProductSearch(emailA), digest)
    assert.equal(await passwordFromProductSearch(emailB), digest)
    assert.equal(await loginStatus(emailA, sharedPassword), 200)
    assert.equal(await loginStatus(emailB, sharedPassword), 200)
    assert.equal(await loginStatus(emailA, sharedPassword + '-wrong'), 401)

    const storedA = await storedPassword(emailA)
    const storedB = await storedPassword(emailB)
    assert.equal(await passwordFromProductSearch(emailA), storedA)
    assert.equal(await passwordFromProductSearch(emailB), storedB)
    assert.notEqual(storedA, digest)
    assert.notEqual(storedB, digest)
    assert.notEqual(storedA, storedB)
    assertNotUnsaltedMd5(storedA, sharedPassword)
    assertNotUnsaltedMd5(storedB, sharedPassword)
    assert.equal(await loginStatus(emailA, sharedPassword), 200)
    assert.equal(await loginStatus(emailB, sharedPassword), 200)
  })
})
