/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express
let userSequence = 0

const currentPassword = 'placeholder-current'
const nextPassword = 'placeholder-next'
const followupPassword = 'placeholder-followup'
const wrongPassword = 'placeholder-wrong'
const securityAnswer = 'placeholder-answer'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('sessions issued before a password change', () => {
  void it('rejects every token issued before a successful password change', async () => {
    const account = await registerAndLogin(currentPassword)
    const older = account.token
    const newer = (await login(app, { email: account.email, password: currentPassword })).token as string

    await assertSessionAccepted(older, account)
    await assertSessionAccepted(newer, account)

    const change = await changePassword(older, currentPassword, nextPassword)
    assert.equal(change.status, 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 200)
    assert.equal((await loginStatus(account.email, currentPassword)), 401)

    await assertSessionRejected(older, account)
    await assertSessionRejected(newer, account)

    const overwritten = await changePassword(older, nextPassword, followupPassword)
    assert.notEqual(overwritten.status, 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 200)
    assert.equal((await loginStatus(account.email, followupPassword)), 401)
    assert.equal((await loginStatus(account.email, currentPassword)), 401)
  })

  void it('does not accept a pre-change token again after it leaves the session map', async () => {
    const account = await registerAndLogin(currentPassword)
    const second = (await login(app, { email: account.email, password: currentPassword })).token as string

    const change = await changePassword(account.token, currentPassword, nextPassword)
    assert.equal(change.status, 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 200)

    dropSession(account.token)
    dropSession(second)
    await assertSessionRejected(account.token, account)
    await assertSessionRejected(second, account)
    await new Promise((resolve) => setTimeout(resolve, 50))
    await assertSessionRejected(account.token, account)
    await assertSessionRejected(second, account)
    assert.equal(security.authenticatedUsers.get(account.token), undefined)
    assert.equal(security.authenticatedUsers.get(second), undefined)
  })

  void it('keeps the current token when the password change is refused', async () => {
    const account = await registerAndLogin(currentPassword)

    const change = await changePassword(account.token, wrongPassword, nextPassword)
    assert.equal(change.status, 401)
    await assertSessionAccepted(account.token, account)
    assert.equal((await loginStatus(account.email, currentPassword)), 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 401)
  })

  void it('accepts a token issued by login after the password change', async () => {
    const account = await registerAndLogin(currentPassword)
    const stale = account.token

    const change = await changePassword(stale, currentPassword, nextPassword)
    assert.equal(change.status, 200)

    const fresh = await login(app, { email: account.email, password: nextPassword })
    await assertSessionAccepted(fresh.token as string, { ...account, bid: fresh.bid as number })
    await assertSessionRejected(stale, account)
  })
})

void describe('sessions issued before a password reset', () => {
  void it('rejects every token issued before a successful password reset', async () => {
    const account = await registerAndLogin(currentPassword, true)
    const older = account.token
    const newer = (await login(app, { email: account.email, password: currentPassword })).token as string

    await assertSessionAccepted(older, account)
    await assertSessionAccepted(newer, account)

    const reset = await resetPassword(account.email, securityAnswer, nextPassword)
    assert.equal(reset.status, 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 200)
    assert.equal((await loginStatus(account.email, currentPassword)), 401)

    await assertSessionRejected(older, account)
    await assertSessionRejected(newer, account)

    assert.equal((await loginStatus(account.email, nextPassword)), 200)
    assert.equal((await loginStatus(account.email, currentPassword)), 401)
  })

  void it('does not accept a pre-reset token again after it leaves the session map', async () => {
    const account = await registerAndLogin(currentPassword, true)
    const second = (await login(app, { email: account.email, password: currentPassword })).token as string

    const reset = await resetPassword(account.email, securityAnswer, nextPassword)
    assert.equal(reset.status, 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 200)

    dropSession(account.token)
    dropSession(second)
    await assertSessionRejected(account.token, account)
    await assertSessionRejected(second, account)
    await new Promise((resolve) => setTimeout(resolve, 50))
    await assertSessionRejected(account.token, account)
    await assertSessionRejected(second, account)
    assert.equal(security.authenticatedUsers.get(account.token), undefined)
    assert.equal(security.authenticatedUsers.get(second), undefined)
  })

  void it('keeps the current token when the security answer is refused', async () => {
    const account = await registerAndLogin(currentPassword, true)

    const reset = await resetPassword(account.email, wrongPassword, nextPassword)
    assert.equal(reset.status, 401)
    await assertSessionAccepted(account.token, account)
    assert.equal((await loginStatus(account.email, currentPassword)), 200)
    assert.equal((await loginStatus(account.email, nextPassword)), 401)
  })
})

interface Account {
  email: string
  userId: number
  token: string
  bid: number
}

async function registerAndLogin (password: string, withSecurityAnswer = false): Promise<Account> {
  userSequence += 1
  const email = `session-invalidation-${userSequence}-${Date.now()}@example.test`
  const userRes = await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({ email, password, passwordRepeat: password })
  assert.equal(userRes.status, 201)
  const userId = userRes.body.data?.id ?? userRes.body.id
  assert.equal(typeof userId, 'number')

  if (withSecurityAnswer) {
    const answerRes = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({ UserId: userId, SecurityQuestionId: 1, answer: securityAnswer })
    assert.equal(answerRes.status, 201)
  }

  const authentication = await login(app, { email, password })
  return { email, userId, token: authentication.token as string, bid: authentication.bid as number }
}

function changePassword (token: string, current: string, next: string) {
  return request(app)
    .get('/rest/user/change-password')
    .query({ current, new: next, repeat: next })
    .set({ Authorization: 'Bearer ' + token })
}

function resetPassword (email: string, answer: string, next: string) {
  return request(app)
    .post('/rest/user/reset-password')
    .set({ 'content-type': 'application/json' })
    .send({ email, answer, new: next, repeat: next })
}

async function loginStatus (email: string, password: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email, password })
  return res.status
}

function dropSession (token: string) {
  const session = security.authenticatedUsers.get(token)
  delete security.authenticatedUsers.tokenMap[token]
  const userId = session?.data?.id
  if (userId != null && security.authenticatedUsers.idMap[userId] === token) {
    delete security.authenticatedUsers.idMap[userId]
  }
}

async function assertSessionAccepted (token: string, account: { email: string, userId: number, bid: number }) {
  const probed = await probe(token, account.bid)
  assert.equal(probed.basket.status, 200)
  assert.equal(probed.basket.body?.data?.id, account.bid)
  assert.equal(probed.profile.status, 200)
  assert.ok(probed.profile.text.includes(`value="${account.email}"`))
  assert.equal(probed.whoami.status, 200)
  assert.equal(probed.whoami.body?.user?.id, account.userId)
  assert.equal(probed.wallet.status, 200)
}

async function assertSessionRejected (token: string, account: { email: string, userId: number, bid: number }) {
  const presentBefore = security.authenticatedUsers.get(token) !== undefined
  const probed = await probe(token, account.bid)
  const presentAfter = security.authenticatedUsers.get(token) !== undefined
  const problems: string[] = []
  if (probed.basket.status !== 401) problems.push(`basket status ${probed.basket.status}`)
  if (probed.profile.status === 200) problems.push('profile status 200')
  if (probed.profile.text.includes(`value="${account.email}"`)) problems.push('profile shows the account email')
  if (probed.whoami.body?.user?.id === account.userId) problems.push('whoami returned the account')
  if (probed.wallet.status !== 401) problems.push(`wallet status ${probed.wallet.status}`)
  if (problems.length > 0) problems.push(`map before=${presentBefore} after=${presentAfter}`)
  assert.deepEqual(problems, [])
}

function probe (token: string, basketId: number) {
  return Promise.all([
    request(app).get('/rest/basket/' + basketId).set({ Authorization: 'Bearer ' + token }),
    request(app).get('/profile').set('Cookie', 'token=' + token),
    request(app).get('/rest/user/whoami').set('Cookie', 'token=' + token),
    request(app).get('/rest/wallet/balance').set({ Authorization: 'Bearer ' + token })
  ]).then(([basket, profile, whoami, wallet]: Response[]) => ({ basket, profile, whoami, wallet }))
}
