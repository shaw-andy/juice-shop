/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { ServerResponse } from 'node:http'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import * as security from '../../lib/insecurity'

// The registration handler can write a refusal and then keep going. A second
// write throws after the account is already saved; ignore that write so the
// assertions below can see the saved account.
const originalSetHeader = ServerResponse.prototype.setHeader
const originalEnd = ServerResponse.prototype.end
const finishedResponses = new WeakSet<ServerResponse>()
ServerResponse.prototype.setHeader = function (name: string, value: number | string | readonly string[]) {
  if (finishedResponses.has(this)) {
    return this
  }
  return originalSetHeader.call(this, name, value)
}
ServerResponse.prototype.end = function (...args: any[]) {
  if (finishedResponses.has(this)) {
    return this
  }
  finishedResponses.add(this)
  return originalEnd.apply(this, args as [])
}

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const emptyPassword = ''
const spaces = '   '
const fiveSpaces = '     '

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function register (email: string, password: string | undefined, passwordRepeat?: string) {
  const body: { email: string, password?: string, passwordRepeat?: string } = { email }
  if (password !== undefined) {
    body.password = password
  }
  if (passwordRepeat !== undefined) {
    body.passwordRepeat = passwordRepeat
  }
  return await request(app).post('/api/Users').set(jsonHeader).send(body)
}

async function login (email: string, password?: string) {
  const body: { email: string, password?: string } = { email }
  if (password !== undefined) {
    body.password = password
  }
  return await request(app).post('/rest/user/login').set(jsonHeader).send(body)
}

async function customerSurfaces (loginRes: Response) {
  const token = loginRes.body?.authentication?.token as string | undefined
  const bid = loginRes.body?.authentication?.bid as number | undefined
  if (token === undefined) {
    return { wallet: 401, basket: 401 }
  }
  const wallet = await request(app)
    .get('/rest/wallet/balance')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
  const basket = bid === undefined
    ? { status: 401 }
    : await request(app).get('/rest/basket/' + String(bid)).set('Authorization', 'Bearer ' + token)
  return { wallet: wallet.status, basket: basket.status }
}

void describe('blank password registration and login', () => {
  void it('does not save a spaces-only password or open a customer session for it', async () => {
    const email = 'spaces-repeat@juice-sh.op'
    const registered = await register(email, fiveSpaces, fiveSpaces)
    const created = await UserModel.findOne({ where: { email } })
    const wallet = created === null ? null : await WalletModel.findOne({ where: { UserId: created.id } })
    const loggedIn = await login(email, emptyPassword)
    const surfaces = await customerSurfaces(loggedIn)
    const storedEmptyHash = created !== null && created.getDataValue('password') === security.hash(emptyPassword)

    const problems = []
    if (registered.status < 400) problems.push('registration accepted')
    if (created?.id !== undefined) problems.push('account created')
    if (created?.role === 'customer') problems.push('role is customer')
    if (storedEmptyHash) problems.push('stored empty password hash')
    if (wallet !== null) problems.push('wallet created')
    if (loggedIn.status === 200) problems.push('blank login accepted')
    if (surfaces.wallet === 200) problems.push('wallet session accepted')
    if (surfaces.basket === 200) problems.push('basket session accepted')
    assert.deepEqual(problems, [])
  })

  void it('does not save a spaces-only password when the repeat field differs', async () => {
    const email = 'spaces-mismatch@juice-sh.op'
    const registered = await register(email, spaces, 'different')
    const created = await UserModel.findOne({ where: { email } })
    const storedEmptyHash = created !== null && created.getDataValue('password') === security.hash(emptyPassword)
    const loggedIn = await login(email, emptyPassword)

    const problems = []
    if (registered.status < 400) problems.push('registration accepted')
    if (created?.id !== undefined) problems.push('account created')
    if (storedEmptyHash) problems.push('stored empty password hash')
    if (loggedIn.status === 200) problems.push('blank login accepted')
    assert.deepEqual(problems, [])
  })

  void it('does not save a spaces-only password when repeat is omitted', async () => {
    const email = 'spaces-norepeat@juice-sh.op'
    const registered = await register(email, spaces)
    const created = await UserModel.findOne({ where: { email } })
    const loggedIn = await login(email, emptyPassword)
    const spacesLogin = await login(email, spaces)

    const problems = []
    if (registered.status < 400) problems.push('registration accepted')
    if (created?.id !== undefined) problems.push('account created')
    if (loggedIn.status === 200) problems.push('blank login accepted')
    if (spacesLogin.status === 200) problems.push('spaces login accepted')
    assert.deepEqual(problems, [])
  })

  void it('does not save an empty password when repeat is empty', async () => {
    const email = 'empty-repeat@juice-sh.op'
    const registered = await register(email, emptyPassword, emptyPassword)
    const created = await UserModel.findOne({ where: { email } })
    const wallet = created === null ? null : await WalletModel.findOne({ where: { UserId: created.id } })
    const storedEmptyHash = created !== null && created.getDataValue('password') === security.hash(emptyPassword)
    const loggedIn = await login(email, emptyPassword)
    const surfaces = await customerSurfaces(loggedIn)

    const problems = []
    if (created?.id !== undefined) problems.push('account created')
    if (storedEmptyHash) problems.push('stored empty password hash')
    if (wallet !== null) problems.push('wallet created')
    if (loggedIn.status === 200) problems.push('blank login accepted')
    if (surfaces.wallet === 200) problems.push('wallet session accepted')
    if (surfaces.basket === 200) problems.push('basket session accepted')
    if (registered.status < 400 || registered.status >= 500) problems.push('registration status ' + String(registered.status))
    assert.deepEqual(problems, [])
  })

  void it('does not save an empty password when repeat is omitted', async () => {
    const email = 'empty-norepeat@juice-sh.op'
    const registered = await register(email, emptyPassword)
    const created = await UserModel.findOne({ where: { email } })
    const storedEmptyHash = created !== null && created.getDataValue('password') === security.hash(emptyPassword)
    const loggedIn = await login(email, emptyPassword)

    const problems = []
    if (registered.status < 400) problems.push('registration accepted')
    if (created?.id !== undefined) problems.push('account created')
    if (storedEmptyHash) problems.push('stored empty password hash')
    if (loggedIn.status === 200) problems.push('blank login accepted')
    assert.deepEqual(problems, [])
  })

  void it('does not save an empty email and empty password', async () => {
    const registered = await register(emptyPassword, emptyPassword, emptyPassword)
    const created = await UserModel.findOne({ where: { email: emptyPassword } })
    const storedEmptyHash = created !== null && created.getDataValue('password') === security.hash(emptyPassword)
    const loggedIn = await login(emptyPassword, emptyPassword)
    const surfaces = await customerSurfaces(loggedIn)

    const problems = []
    if (created?.id !== undefined) problems.push('account created')
    if (storedEmptyHash) problems.push('stored empty password hash')
    if (loggedIn.status === 200) problems.push('blank login accepted')
    if (surfaces.basket === 200) problems.push('basket session accepted')
    if (registered.status < 400 || registered.status >= 500) problems.push('registration status ' + String(registered.status))
    assert.deepEqual(problems, [])
  })

  void it('rejects a blank login for an account that already stores the empty password hash', async () => {
    const email = 'seed-blank@juice-sh.op'
    const user = await UserModel.create({ email, password: emptyPassword, role: 'customer' })
    assert.equal(user.role, 'customer')
    assert.equal(user.getDataValue('password'), security.hash(emptyPassword))

    const blank = await login(email, emptyPassword)
    const omitted = await login(email)
    const whitespace = await login(email, spaces)
    const blankSurfaces = await customerSurfaces(blank)
    const whitespaceSurfaces = await customerSurfaces(whitespace)

    const problems = []
    if (blank.status === 200) problems.push('blank login accepted')
    if (omitted.status === 200) problems.push('omitted password login accepted')
    if (whitespace.status === 200) problems.push('whitespace login accepted')
    if (blankSurfaces.basket === 200) problems.push('basket session accepted')
    if (blankSurfaces.wallet === 200) problems.push('wallet session accepted')
    if (whitespaceSurfaces.basket === 200) problems.push('whitespace basket session accepted')
    assert.deepEqual(problems, [])
  })
})
