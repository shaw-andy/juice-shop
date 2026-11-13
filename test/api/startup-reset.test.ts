/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import { createApp, start, close } from '../../server'
import { loadStaticUserData } from '../../data/staticData'
import { QuantityModel } from '../../models/quantity'
import type { Sequelize } from 'sequelize'

const replacementPassword = 'replacement-password-placeholder'
const keptEmail = 'kept-after-restart@example.com'
const keptStreet = 'Kept After Restart Lane'
const keptCardName = 'Kept After Restart'
const walletTopUp = 2500
const jsonHeader = { 'content-type': 'application/json' }

interface SeededAdmin {
  email: string
  password: string
}

async function seededAdmin (): Promise<SeededAdmin> {
  const users = await loadStaticUserData()
  const admin = users.find(user => user.key === 'admin')
  if (admin == null) {
    throw new Error('static user seed has no admin key')
  }
  const domain = config.get<string>('application.domain')
  const email = admin.customDomain === true ? admin.email : `${admin.email}@${domain}`
  return { email, password: admin.password }
}

function bearer (token: string): { Authorization: string, 'content-type': string } {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

interface ShopChanges {
  email: string
  walletBalance: number
}

async function changeShopData (app: Express): Promise<ShopChanges> {
  const admin = await seededAdmin()
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: admin.email, password: admin.password })
  assert.equal(loginRes.status, 200)
  const token = loginRes.body.authentication.token as string

  const changed = await request(app)
    .get('/rest/user/change-password')
    .query({ current: admin.password, new: replacementPassword, repeat: replacementPassword })
    .set(bearer(token))
  assert.equal(changed.status, 200)

  const replacementLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: admin.email, password: replacementPassword })
  assert.equal(replacementLogin.status, 200)
  const replacementToken = replacementLogin.body.authentication.token as string

  const seededAgain = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: admin.email, password: admin.password })
  assert.equal(seededAgain.status, 401)

  const registered = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email: keptEmail,
      password: replacementPassword,
      passwordRepeat: replacementPassword
    })
  assert.equal(registered.status, 201)

  const customerLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: keptEmail, password: replacementPassword })
  assert.equal(customerLogin.status, 200)
  const customerToken = customerLogin.body.authentication.token as string

  const address = await request(app)
    .post('/api/Addresss')
    .set(bearer(replacementToken))
    .send({
      fullName: 'Kept Customer',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: keptStreet,
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
  assert.equal(address.status, 201)

  const card = await request(app)
    .post('/api/Cards')
    .set(bearer(replacementToken))
    .send({
      fullName: keptCardName,
      cardNum: 1234567887654321,
      expMonth: 1,
      expYear: 2085
    })
  assert.equal(card.status, 201)
  const cardId = card.body.data.id as number

  const balanceBefore = await request(app)
    .get('/rest/wallet/balance')
    .set(bearer(replacementToken))
  assert.equal(balanceBefore.status, 200)
  const toppedUp = await request(app)
    .put('/rest/wallet/balance')
    .set(bearer(replacementToken))
    .send({ balance: walletTopUp, paymentId: cardId })
  assert.equal(toppedUp.status, 200)
  const balanceAfter = await request(app)
    .get('/rest/wallet/balance')
    .set(bearer(replacementToken))
  assert.equal(balanceAfter.status, 200)
  const walletBalance = balanceBefore.body.data + walletTopUp
  assert.equal(balanceAfter.body.data, walletBalance)

  const customerStillThere = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: keptEmail, password: replacementPassword })
  assert.equal(customerStillThere.status, 200)
  assert.equal(customerToken.length > 0, true)

  return { email: admin.email, walletBalance }
}

async function assertShopDataKept (app: Express, changes: ShopChanges): Promise<void> {
  const admin = await seededAdmin()
  const replacementLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: changes.email, password: replacementPassword })
  assert.equal(replacementLogin.status, 200)
  const token = replacementLogin.body.authentication.token as string

  const seededLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: changes.email, password: admin.password })
  assert.equal(seededLogin.status, 401)

  const customerLogin = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: keptEmail, password: replacementPassword })
  assert.equal(customerLogin.status, 200)

  const addresses = await request(app)
    .get('/api/Addresss')
    .set(bearer(token))
  assert.equal(addresses.status, 200)
  assert.equal(JSON.stringify(addresses.body).includes(keptStreet), true)

  const cards = await request(app)
    .get('/api/Cards')
    .set(bearer(token))
  assert.equal(cards.status, 200)
  assert.equal(JSON.stringify(cards.body).includes(keptCardName), true)

  const balance = await request(app)
    .get('/rest/wallet/balance')
    .set(bearer(token))
  assert.equal(balance.status, 200)
  assert.equal(balance.body.data, changes.walletBalance)
}

function orderPdfNames (): string[] {
  return fs.readdirSync('ftp').filter(name => name.startsWith('order_') && name.endsWith('.pdf'))
}

function orderPdfDescriptors (): string[] {
  const found: string[] = []
  for (const entry of fs.readdirSync('/proc/self/fd')) {
    try {
      const target = fs.readlinkSync(path.join('/proc/self/fd', entry))
      if (target.includes('ftp/order_')) {
        found.push(target)
      }
    } catch {
      // The descriptor can close between readdir and readlink.
    }
  }
  return found
}

async function quantitiesByProduct (): Promise<Map<number, number>> {
  const rows = await QuantityModel.findAll()
  return new Map(rows.map(row => [row.ProductId, row.quantity]))
}

async function failedWalletCheckout (app: Express): Promise<request.Response> {
  const admin = await seededAdmin()
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email: admin.email, password: admin.password })
  assert.equal(loginRes.status, 200)
  const token = loginRes.body.authentication.token as string
  const basketId = loginRes.body.authentication.bid as number
  return await request(app)
    .post('/rest/basket/' + String(basketId) + '/checkout')
    .set(bearer(token))
    .send({ UserId: loginRes.body.authentication.umail, orderDetails: { paymentId: 'wallet' } })
}

void describe('server startup keeps shop data', () => {
  void it('createApp does not drop changed accounts, addresses, cards, or wallet balances', async () => {
    const first = await createApp()
    const changes = await changeShopData(first.app)
    const second = await createApp()
    await assertShopDataKept(second.app, changes)
  })

  void it('start does not drop changed accounts, addresses, cards, or wallet balances', async () => {
    const first = await createApp()
    const changes = await changeShopData(first.app)
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { reject(new Error('server start did not become ready')) }, 20000)
      start(() => {
        clearTimeout(timer)
        resolve()
      }).catch(reject)
    })
    await assertShopDataKept(first.app, changes)
  })

  after(() => {
    close(undefined)
  })
})

void describe('failed wallet checkout releases the order file', () => {
  void it('insufficient balance does not write an order pdf, leak a descriptor, or change stock', async () => {
    const { app } = await createApp({ inMemoryDb: true })
    const beforeNames = new Set(orderPdfNames())
    const beforeQuantities = await quantitiesByProduct()
    const created: string[] = []
    const watcher = fs.watch('ftp', (_event, filename) => {
      if (filename != null && filename.startsWith('order_') && filename.endsWith('.pdf')) {
        created.push(filename)
      }
    })

    const res = await failedWalletCheckout(app)
    await new Promise(resolve => setTimeout(resolve, 50))
    watcher.close()

    assert.equal(res.status, 500)
    assert.equal(new Set(created).size, 0)
    const newNames = orderPdfNames().filter(name => !beforeNames.has(name))
    assert.deepEqual(newNames, [])
    assert.deepEqual(orderPdfDescriptors(), [])
    assert.deepEqual(await quantitiesByProduct(), beforeQuantities)
  })

  void it('a quantity lookup failure does not leave the order pdf open', async () => {
    const started = await createApp({ inMemoryDb: true })
    const app = started.app
    const seq: Sequelize = started.sequelize
    await seq.query('DROP TABLE Quantities')
    const beforeNames = new Set(orderPdfNames())
    const created: string[] = []
    const watcher = fs.watch('ftp', (_event, filename) => {
      if (filename != null && filename.startsWith('order_') && filename.endsWith('.pdf')) {
        created.push(filename)
      }
    })

    const res = await failedWalletCheckout(app)
    await new Promise(resolve => setTimeout(resolve, 50))
    watcher.close()

    assert.equal(res.status, 500)
    assert.equal(new Set(created).size, 0)
    const newNames = orderPdfNames().filter(name => !beforeNames.has(name))
    assert.deepEqual(newNames, [])
    assert.deepEqual(orderPdfDescriptors(), [])
  })

  void it('repeated insufficient wallet checkouts do not accumulate order file descriptors', async () => {
    const { app } = await createApp({ inMemoryDb: true })
    const beforeNames = new Set(orderPdfNames())
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await failedWalletCheckout(app)
      assert.equal(res.status, 500)
    }
    const newNames = orderPdfNames().filter(name => !beforeNames.has(name))
    assert.deepEqual(newNames, [])
    assert.deepEqual(orderPdfDescriptors(), [])
  })

  after(() => {
    for (const name of orderPdfNames()) {
      fs.rmSync(path.join('ftp', name), { force: true })
    }
  })
})
