/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-password'
const membershipPrice = 49

let app: Express
let sequelize: Sequelize
let emailCounter = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

afterEach(() => {
  WalletModel.removeHook('beforeCreate', 'holdWalletInsert')
  WalletModel.removeHook('beforeCreate', 'failWalletInsert')
  sequelize.removeHook('beforeQuery', 'dropWalletBeforeCharge')
})

void describe('deluxe wallet payment', { concurrency: false }, () => {
  void it('does not grant deluxe while registration has not finished inserting the wallet', async () => {
    let releaseInsert: () => void = () => {}
    const insertHeld = new Promise<void>((resolve) => {
      releaseInsert = resolve
    })
    WalletModel.addHook('beforeCreate', 'holdWalletInsert', async () => {
      await insertHeld
    })

    try {
      const { userId, token } = await registerAndLogin()
      const balance = await request(app)
        .get('/rest/wallet/balance')
        .set(authHeader(token))
      assert.equal(balance.status, 404)

      const upgrade = await payWithWallet(token)
      await assertStillCustomer(userId, upgrade.body?.data?.token)
    } finally {
      releaseInsert()
      WalletModel.removeHook('beforeCreate', 'holdWalletInsert')
    }
  })

  void it('does not grant deluxe when wallet creation failed during registration', async () => {
    WalletModel.addHook('beforeCreate', 'failWalletInsert', () => {
      throw new Error('wallet insert failed')
    })

    try {
      const { userId, token } = await registerAndLogin()
      const balance = await request(app)
        .get('/rest/wallet/balance')
        .set(authHeader(token))
      assert.equal(balance.status, 404)

      const upgrade = await payWithWallet(token)
      await assertStillCustomer(userId, upgrade.body?.data?.token)

      const retry = await payWithWallet(token)
      await assertStillCustomer(userId, retry.body?.data?.token)
    } finally {
      WalletModel.removeHook('beforeCreate', 'failWalletInsert')
    }
  })

  void it('does not grant deluxe when the wallet row is gone before the balance update', async () => {
    const { userId, token } = await registerAndLogin()
    const wallet = await waitForWallet(userId)
    await wallet.update({ balance: membershipPrice + 50 })

    let dropped = false
    sequelize.addHook('beforeQuery', 'dropWalletBeforeCharge', async (options: { type?: string, model?: { name?: string } }, query: { connection?: { run: Function } }) => {
      if (dropped || options.type !== 'UPDATE' || options.model?.name !== 'Wallet') return
      dropped = true
      await runOnConnection(query.connection, 'DELETE FROM `Wallets` WHERE `UserId` = ?', [userId])
    })

    try {
      const upgrade = await payWithWallet(token)
      assert.equal(dropped, true)
      const remaining = await WalletModel.findOne({ where: { UserId: userId } })
      assert.equal(remaining, null)
      await assertStillCustomer(userId, upgrade.body?.data?.token)
    } finally {
      sequelize.removeHook('beforeQuery', 'dropWalletBeforeCharge')
    }
  })

  void it('rejects a wallet payment that would leave the balance short and does not change the role', async () => {
    const { userId, token } = await registerAndLogin()
    const wallet = await waitForWallet(userId)
    await wallet.update({ balance: membershipPrice - 1 })

    const upgrade = await payWithWallet(token)
    assert.equal(upgrade.status, 400)
    assert.notEqual(upgrade.body.status, 'success')
    await assertStillCustomer(userId, upgrade.body?.data?.token)

    const balance = await request(app)
      .get('/rest/wallet/balance')
      .set(authHeader(token))
    assert.equal(balance.status, 200)
    assert.equal(balance.body.data, membershipPrice - 1)
  })

  void it('grants deluxe only after the wallet balance decreases by the membership price', async () => {
    const { userId, token } = await registerAndLogin()
    const wallet = await waitForWallet(userId)
    const startingBalance = membershipPrice + 7
    await wallet.update({ balance: startingBalance })

    const upgrade = await payWithWallet(token)
    assert.equal(upgrade.status, 200)
    assert.equal(upgrade.body.status, 'success')

    const charged = await WalletModel.findOne({ where: { UserId: userId } })
    assert.equal(charged?.balance, startingBalance - membershipPrice)

    const user = await UserModel.findByPk(userId)
    assert.equal(user?.role, 'deluxe')
    const deluxeToken = upgrade.body?.data?.token
    assert.equal(typeof deluxeToken, 'string')
    await assertDeluxePrices(deluxeToken)
  })
})

async function registerAndLogin () {
  emailCounter += 1
  const email = `wallet-payment-${emailCounter}@juice-sh.op`
  const registered = await request(app)
    .post('/api/Users/')
    .set(jsonHeader)
    .send({
      email,
      password: placeholderPassword,
      passwordRepeat: placeholderPassword
    })
  assert.equal(registered.status, 201)
  const userId = registered.body.data.id as number
  const { token } = await login(app, { email, password: placeholderPassword })
  return { userId, token, email }
}

async function payWithWallet (token: string) {
  return await request(app)
    .post('/rest/deluxe-membership')
    .set(authHeader(token))
    .send({ paymentMode: 'wallet' })
}

function authHeader (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function waitForWallet (userId: number) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const wallet = await WalletModel.findOne({ where: { UserId: userId } })
    if (wallet != null) return wallet
    await new Promise((resolve) => { setTimeout(resolve, 20) })
  }
  throw new Error(`Wallet for user ${userId} was not created`)
}

async function assertStillCustomer (userId: number, upgradedToken?: string) {
  const user = await UserModel.findByPk(userId)
  assert.equal(user?.role, 'customer')
  assert.equal(user?.deluxeToken ?? '', '')

  const session = upgradedToken
  if (session) {
    const membership = await request(app)
      .get('/rest/deluxe-membership')
      .set(authHeader(session))
    assert.notEqual(membership.body.error, 'You are already a deluxe member!')
    await assertCustomerPrices(session)
  }
}

async function assertCustomerPrices (token: string) {
  const oneDay = await oneDayDeliveryPrice(token)
  assert.equal(oneDay, 0.99)
}

async function assertDeluxePrices (token: string) {
  const oneDay = await oneDayDeliveryPrice(token)
  assert.equal(oneDay, 0.5)
}

async function oneDayDeliveryPrice (token: string) {
  const res = await request(app)
    .get('/api/Deliverys')
    .set(authHeader(token))
  assert.equal(res.status, 200)
  const method = res.body.data.find((entry: { name: string }) => entry.name === 'One Day Delivery')
  assert.ok(method)
  return method.price as number
}

function runOnConnection (connection: { run: Function } | undefined, sql: string, params: unknown[]) {
  assert.ok(connection)
  return new Promise<void>((resolve, reject) => {
    connection.run(sql, params, (err: Error | null) => {
      if (err != null) reject(err)
      else resolve()
    })
  })
}
