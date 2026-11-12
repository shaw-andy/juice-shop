/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'

const PLACEHOLDER_PASSWORD = 'PLACEHOLDER_PASSWORD'
const CLIENT_BALANCE = 100000

let app: Express

interface Customer {
  email: string
  id: number
  bid: number
  authHeader: { Authorization: string, 'content-type': string }
  balance: number
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('client-supplied wallet credit', { concurrency: 1 }, () => {
  void it('does not credit a balance supplied with a newly saved card', async () => {
    const customer = await registerCustomer()
    const victim = await registerCustomer()
    const cardId = await saveCard(customer)

    await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: CLIENT_BALANCE, paymentId: cardId, UserId: victim.id })

    assert.equal(await currentBalance(customer), customer.balance)
    assert.equal(await currentBalance(victim), victim.balance)
  })

  void it('does not credit a numeric string supplied as the balance', async () => {
    const customer = await registerCustomer()
    const cardId = await saveCard(customer)

    await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: String(CLIENT_BALANCE), paymentId: cardId })

    assert.equal(await currentBalance(customer), customer.balance)
  })

  void it('does not repeat a client-supplied credit when the same card is submitted again', async () => {
    const customer = await registerCustomer()
    const cardId = await saveCard(customer)

    await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: CLIENT_BALANCE, paymentId: cardId })
    await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: CLIENT_BALANCE, paymentId: cardId })

    assert.equal(await currentBalance(customer), customer.balance)
  })

  void it('does not record an order paid from a client-supplied wallet credit', async () => {
    const customer = await registerCustomer()
    const victim = await registerCustomer()
    const cardId = await saveCard(customer)
    const product = await paidProduct()

    await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: CLIENT_BALANCE, paymentId: cardId })

    const basketItem = await request(app)
      .post('/api/BasketItems')
      .set(customer.authHeader)
      .send({ BasketId: customer.bid, ProductId: product.id, quantity: 1 })
    assert.equal(basketItem.status, 200)

    const checkout = await request(app)
      .post('/rest/basket/' + customer.bid + '/checkout')
      .set(customer.authHeader)
      .send({
        UserId: victim.id,
        orderDetails: { paymentId: 'wallet' }
      })
    const orderId = checkout.body?.orderConfirmation
    try {
      const history = await request(app)
        .get('/rest/order-history')
        .set(customer.authHeader)
      assert.equal(history.status, 200)
      const walletOrders = (history.body.data ?? []).filter((order: { paymentId?: string }) => order.paymentId === 'wallet')
      assert.deepEqual(walletOrders.map((order: { paymentId?: string }) => order.paymentId), [])
      assert.equal(orderId, undefined)
      assert.equal(await currentBalance(customer), customer.balance)
      assert.equal(await currentBalance(victim), victim.balance)
    } finally {
      if (typeof orderId === 'string') {
        fs.rmSync(path.join('ftp', `order_${orderId}.pdf`), { force: true })
      }
    }
  })

  void it('does not grant deluxe membership from a client-supplied wallet credit', async () => {
    const customer = await registerCustomer()
    const cardId = await saveCard(customer)

    await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: CLIENT_BALANCE, paymentId: cardId })

    const upgrade = await request(app)
      .post('/rest/deluxe-membership')
      .set(customer.authHeader)
      .send({ paymentMode: 'wallet', paymentId: cardId })

    const user = await UserModel.findOne({ where: { id: customer.id } })
    assert.equal(user?.role, 'customer')
    assert.equal(user?.deluxeToken, '')
    assert.notEqual(upgrade.status, 200)
    assert.notEqual(upgrade.body?.status, 'success')
    assert.equal(await currentBalance(customer), customer.balance)
  })
})

async function registerCustomer (): Promise<Customer> {
  const email = `wallet-credit-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  const registration = await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const id = registration.body.data.id
  const { token, bid } = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  const customer = { email, id, bid, authHeader, balance: 0 }
  customer.balance = await waitForWallet(customer)
  return customer
}

async function waitForWallet (customer: Customer): Promise<number> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const res = await request(app)
      .get('/rest/wallet/balance')
      .set(customer.authHeader)
    if (res.status === 200) {
      return res.body.data
    }
    await new Promise(resolve => { setTimeout(resolve, 20) })
  }
  throw new Error('wallet was not created for the registered customer')
}

async function currentBalance (customer: Customer): Promise<number> {
  const res = await request(app)
    .get('/rest/wallet/balance')
    .set(customer.authHeader)
  assert.equal(res.status, 200)
  return res.body.data
}

async function saveCard (customer: Customer): Promise<number> {
  const res = await request(app)
    .post('/api/Cards')
    .set(customer.authHeader)
    .send({
      fullName: 'Test Customer',
      cardNum: 4111111111111111,
      expMonth: 12,
      expYear: 2090
    })
  assert.equal(res.status, 201)
  assert.equal(typeof res.body.data.id, 'number')
  return res.body.data.id
}

async function paidProduct (): Promise<{ id: number, price: number }> {
  const res = await request(app).get('/api/Products')
  assert.equal(res.status, 200)
  const product = res.body.data.find((item: { name: string, price: number }) => {
    return item.name === 'Apple Juice (1000ml)' && item.price > 0
  })
  assert.ok(product)
  return product
}
