/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'

let app: Express

const PLACEHOLDER_PASSWORD = 'PLACEHOLDER_PASSWORD'
const PLACEHOLDER_NEW_PASSWORD = 'PLACEHOLDER_NEW_PASSWORD'
const PLACEHOLDER_ANSWER = 'PLACEHOLDER_ANSWER'
const PLACEHOLDER_OTHER_ANSWER = 'PLACEHOLDER_OTHER_ANSWER'
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function accountEmail (user: StaticUser) {
  return user.customDomain === true ? user.email : `${user.email}@${config.get<string>('application.domain')}`
}

async function seedAccount (key: string) {
  const users = await loadStaticUserData()
  const user = users.find((candidate) => candidate.key === key)
  if (user?.securityQuestion == null) {
    throw new Error(`Seed user ${key} has no security question in data/static/users.yml`)
  }
  return {
    email: accountEmail(user),
    password: user.password,
    answer: user.securityQuestion.answer
  }
}

async function loginStatus (email: string, password: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  return res.status
}

async function registerWithAnswer (email: string, answer: string) {
  const userRes = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email,
      password: PLACEHOLDER_PASSWORD,
      passwordRepeat: PLACEHOLDER_PASSWORD
    })
  assert.equal(userRes.status, 201)
  assert.equal(typeof userRes.body.data.id, 'number')

  const answerRes = await request(app)
    .post('/api/SecurityAnswers')
    .set(jsonHeader)
    .send({
      UserId: userRes.body.data.id,
      SecurityQuestionId: 1,
      answer
    })
  assert.equal(answerRes.status, 201)

  return {
    email,
    password: PLACEHOLDER_PASSWORD,
    answer
  }
}

async function submitReset (email: string, answer: string, token?: string) {
  const call = request(app)
    .post('/rest/user/reset-password')
    .set(jsonHeader)
  if (token !== undefined) {
    call.set({ Authorization: 'Bearer ' + token })
  }
  return await call.send({
    email,
    answer,
    new: PLACEHOLDER_NEW_PASSWORD,
    repeat: PLACEHOLDER_NEW_PASSWORD
  })
}

async function passwordWasReplaced (email: string, originalPassword: string) {
  const withNewPassword = await loginStatus(email, PLACEHOLDER_NEW_PASSWORD)
  const withOriginalPassword = await loginStatus(email, originalPassword)
  return withNewPassword === 200 || withOriginalPassword !== 200
}

void describe('anonymous security question lookup', () => {
  void it('does not return the security question for seeded privileged accounts or a newly registered account', async () => {
    const registered = await registerWithAnswer('disclosure-user@te.st', PLACEHOLDER_ANSWER)
    const admin = await seedAccount('admin')
    const accountant = await seedAccount('accountant')
    const disclosed: string[] = []

    for (const email of [admin.email, accountant.email, registered.email]) {
      const res = await request(app)
        .get('/rest/user/security-question')
        .query({ email })
      if (res.body?.question != null) {
        disclosed.push(email)
      }
    }

    assert.deepEqual(disclosed, [])
  })
})

void describe('password reset via security answer', () => {
  void it('does not let an anonymous caller replace the seeded admin or accounting password', async () => {
    const replaced: string[] = []

    for (const key of ['admin', 'accountant']) {
      const account = await seedAccount(key)
      const before = await loginStatus(account.email, account.password)
      assert.equal(before, 200, `seeded ${key} account did not accept its original password before reset`)

      await submitReset(account.email, account.answer)
      if (await passwordWasReplaced(account.email, account.password)) {
        replaced.push(key)
      }
    }

    assert.deepEqual(replaced, [])
  })

  void it('does not let an anonymous caller replace a password chosen after startup', async () => {
    const account = await registerWithAnswer('later-user@te.st', PLACEHOLDER_ANSWER)
    const before = await loginStatus(account.email, account.password)
    assert.equal(before, 200)

    await submitReset(account.email, account.answer)

    assert.equal(await passwordWasReplaced(account.email, account.password), false)
  })

  void it('does not change the victim when the caller is authenticated as a different user', async () => {
    const victim = await registerWithAnswer('victim-user@te.st', PLACEHOLDER_ANSWER)
    const attacker = await registerWithAnswer('attacker-user@te.st', PLACEHOLDER_OTHER_ANSWER)
    assert.equal(await loginStatus(victim.email, victim.password), 200)
    assert.equal(await loginStatus(attacker.email, attacker.password), 200)
    const session = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: attacker.email, password: attacker.password })
    assert.equal(session.status, 200)

    await submitReset(victim.email, victim.answer, session.body.authentication.token)

    assert.equal(await passwordWasReplaced(victim.email, victim.password), false)
    assert.equal(await passwordWasReplaced(attacker.email, attacker.password), false)
  })
})
