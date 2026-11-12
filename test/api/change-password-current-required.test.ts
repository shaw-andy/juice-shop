/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const currentPassword = 'placeholder-current'
const nextPassword = 'placeholder-next'
const rotatedPassword = 'placeholder-rotated'
const otherPassword = 'placeholder-other'
const jsonHeader = { 'content-type': 'application/json' }

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function register (email: string, password: string) {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password, passwordRepeat: password })
  assert.equal(res.status, 201)
}

async function storedPassword (email: string) {
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  return { id: user.id, password: user.password }
}

function matches (actual: string, plain: string) {
  return actual === security.hash(plain)
}

async function changePassword (token: string, query: Record<string, string>) {
  return await request(app)
    .get('/rest/user/change-password?' + new URLSearchParams(query).toString())
    .set({ Authorization: 'Bearer ' + token })
}

void describe('GET /rest/user/change-password', () => {
  void it('rejects a change that omits current and keeps the stored password', async () => {
    const email = 'omit-current@example.test'
    await register(email, currentPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const before = await storedPassword(email)

    const res = await changePassword(token, { new: nextPassword, repeat: nextPassword })

    const after = await storedPassword(email)
    assert.equal(matches(after.password, currentPassword), true)
    assert.equal(after.password === before.password, true)
    assert.equal(res.status, 401)
    await login(app, { email, password: currentPassword })
    await assert.rejects(() => login(app, { email, password: nextPassword }))
  })

  void it('rejects an empty current password and keeps the stored password', async () => {
    const email = 'empty-current@example.test'
    await register(email, currentPassword)
    const { token } = await login(app, { email, password: currentPassword })

    const res = await changePassword(token, { current: '', new: nextPassword, repeat: nextPassword })

    const after = await storedPassword(email)
    assert.equal(matches(after.password, currentPassword), true)
    assert.equal(res.status, 401)
    await login(app, { email, password: currentPassword })
    await assert.rejects(() => login(app, { email, password: nextPassword }))
  })

  void it('rejects a blank current password and keeps the stored password', async () => {
    const email = 'blank-current@example.test'
    await register(email, currentPassword)
    const { token } = await login(app, { email, password: currentPassword })

    const res = await changePassword(token, { current: '   ', new: nextPassword, repeat: nextPassword })

    const after = await storedPassword(email)
    assert.equal(matches(after.password, currentPassword), true)
    assert.equal(res.status, 401)
  })

  void it('rejects a current password that matches only the login-time copy', async () => {
    const email = 'stale-current@example.test'
    await register(email, currentPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const account = await UserModel.findOne({ where: { email } })
    assert.ok(account)
    await account.update({ password: rotatedPassword })

    const res = await changePassword(token, {
      current: currentPassword,
      new: nextPassword,
      repeat: nextPassword
    })

    const after = await storedPassword(email)
    assert.equal(matches(after.password, rotatedPassword), true)
    assert.equal(res.status, 401)
    await login(app, { email, password: rotatedPassword })
    await assert.rejects(() => login(app, { email, password: nextPassword }))
    await assert.rejects(() => login(app, { email, password: currentPassword }))
  })

  void it('accepts a current password that matches the stored row and not the login-time copy', async () => {
    const email = 'fresh-current@example.test'
    await register(email, currentPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const account = await UserModel.findOne({ where: { email } })
    assert.ok(account)
    await account.update({ password: rotatedPassword })

    const res = await changePassword(token, {
      current: rotatedPassword,
      new: nextPassword,
      repeat: nextPassword
    })

    const after = await storedPassword(email)
    assert.equal(matches(after.password, nextPassword), true)
    assert.equal(res.status, 200)
    await login(app, { email, password: nextPassword })
    await assert.rejects(() => login(app, { email, password: rotatedPassword }))
  })

  void it('does not update a row loaded for a different id than the authenticated user', async () => {
    const email = 'lookup-account@example.test'
    const otherEmail = 'lookup-other@example.test'
    await register(email, currentPassword)
    await register(otherEmail, otherPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const account = await storedPassword(email)
    const other = await storedPassword(otherEmail)
    let lookupsOfAccount = 0
    const hookName = 'change-password-redirect-authenticated-lookup'
    UserModel.addHook('beforeFind', hookName, (options: { where?: { id?: number } }) => {
      if (options.where?.id === account.id) {
        lookupsOfAccount += 1
        options.where.id = other.id
      }
    })

    try {
      const res = await changePassword(token, {
        current: currentPassword,
        new: nextPassword,
        repeat: nextPassword
      })
      const afterAccount = await storedPassword(email)
      const afterOther = await storedPassword(otherEmail)
      assert.equal(lookupsOfAccount > 0, true)
      assert.equal(matches(afterOther.password, otherPassword), true)
      assert.equal(matches(afterAccount.password, currentPassword), true)
      assert.equal(res.status, 401)
    } finally {
      UserModel.removeHook('beforeFind', hookName)
    }
  })

  void it('does not apply a later lookup to a different user than the one whose password matched', async () => {
    const email = 'second-lookup-account@example.test'
    const otherEmail = 'second-lookup-other@example.test'
    await register(email, currentPassword)
    await register(otherEmail, otherPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const account = await storedPassword(email)
    const other = await storedPassword(otherEmail)
    let lookupsOfAccount = 0
    const hookName = 'change-password-redirect-second-lookup'
    UserModel.addHook('beforeFind', hookName, (options: { where?: { id?: number } }) => {
      if (options.where?.id === account.id) {
        lookupsOfAccount += 1
        if (lookupsOfAccount > 1) {
          options.where.id = other.id
        }
      }
    })

    try {
      const res = await changePassword(token, {
        current: currentPassword,
        new: nextPassword,
        repeat: nextPassword
      })
      const afterAccount = await storedPassword(email)
      const afterOther = await storedPassword(otherEmail)
      assert.equal(lookupsOfAccount > 0, true)
      assert.equal(matches(afterOther.password, otherPassword), true)
      assert.equal(matches(afterAccount.password, nextPassword), true)
      assert.equal(res.status, 200)
      await login(app, { email, password: nextPassword })
    } finally {
      UserModel.removeHook('beforeFind', hookName)
    }
  })

  void it('changes only the authenticated user when the request names another user', async () => {
    const email = 'named-account@example.test'
    const otherEmail = 'named-other@example.test'
    await register(email, currentPassword)
    await register(otherEmail, otherPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const other = await storedPassword(otherEmail)

    const res = await request(app)
      .get('/rest/user/change-password')
      .query({
        current: currentPassword,
        new: nextPassword,
        repeat: nextPassword,
        id: String(other.id),
        UserId: String(other.id),
        email: otherEmail
      })
      .set({ Authorization: 'Bearer ' + token })

    const afterAccount = await storedPassword(email)
    const afterOther = await storedPassword(otherEmail)
    assert.equal(matches(afterOther.password, otherPassword), true)
    assert.equal(matches(afterAccount.password, nextPassword), true)
    assert.equal(res.status, 200)
  })

  void it('does not change another user when current is omitted and the request names that user', async () => {
    const email = 'omitted-named-account@example.test'
    const otherEmail = 'omitted-named-other@example.test'
    await register(email, currentPassword)
    await register(otherEmail, otherPassword)
    const { token } = await login(app, { email, password: currentPassword })
    const other = await storedPassword(otherEmail)

    const res = await request(app)
      .get('/rest/user/change-password')
      .query({
        new: nextPassword,
        repeat: nextPassword,
        id: String(other.id),
        UserId: String(other.id),
        email: otherEmail
      })
      .set({ Authorization: 'Bearer ' + token })

    const afterAccount = await storedPassword(email)
    const afterOther = await storedPassword(otherEmail)
    assert.equal(matches(afterOther.password, otherPassword), true)
    assert.equal(matches(afterAccount.password, currentPassword), true)
    assert.equal(res.status, 401)
    await login(app, { email, password: currentPassword })
    await login(app, { email: otherEmail, password: otherPassword })
  })
})
