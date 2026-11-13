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
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { WalletModel } from '../../models/wallet'
import * as security from '../../lib/insecurity'

const placeholderPassword = 'placeholder-not-a-secret'
const startingBalance = 500

let app: Express

interface Customer {
  email: string
  token: string
  bid: number
  userId: number
  header: { Authorization: string, 'content-type': string }
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function customer (label: string): Promise<Customer> {
  const email = `${label}-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  const registered = await register(app, { email, password: placeholderPassword })
  const authentication = await login(app, { email, password: placeholderPassword })
  const userId = registered.body.data.id
  await WalletModel.update({ balance: startingBalance }, { where: { UserId: userId } })
  return {
    email,
    token: authentication.token,
    bid: authentication.bid,
    userId,
    header: {
      Authorization: 'Bearer ' + authentication.token,
      'content-type': 'application/json'
    }
  }
}

async function productId (name: string): Promise<number> {
  const product = await ProductModel.findOne({ where: { name } })
  assert.ok(product, `missing product ${name}`)
  return product.id
}

async function walletBalance (customer: Customer): Promise<number> {
  const res = await request(app).get('/rest/wallet/balance').set(customer.header)
  assert.equal(res.status, 200)
  return Number(res.body.data)
}

async function basketProductIds (customer: Customer, basketId: number): Promise<number[]> {
  const res = await request(app).get('/rest/basket/' + basketId).set(customer.header)
  assert.equal(res.status, 200)
  const products = res.body.data?.Products ?? []
  return products.map((product: { id: number }) => product.id)
}

function removeOrderPdf (orderId: unknown) {
  if (typeof orderId !== 'string' || orderId.length === 0) return
  const file = path.join('ftp', `order_${orderId}.pdf`)
  if (fs.existsSync(file)) fs.unlinkSync(file)
}

void describe('basket line ownership', { concurrency: 1 }, () => {
  void it('a line created without a basket cannot be assigned to another customer or charged at checkout', async () => {
    const attacker = await customer('no-basket')
    const victim = await customer('no-basket-victim')
    const id = await productId('Orange Juice (1000ml)')
    const before = await walletBalance(victim)

    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(attacker.header)
      .send({ ProductId: id, quantity: 1 })

    let updateRes: request.Response | undefined
    if (createRes.status < 400 && createRes.body?.data?.id != null) {
      updateRes = await request(app)
        .put('/api/BasketItems/' + createRes.body.data.id)
        .set(attacker.header)
        .send({ BasketId: victim.bid })
    }

    const victimProducts = await basketProductIds(victim, victim.bid)
    const checkout = await request(app)
      .post('/rest/basket/' + victim.bid + '/checkout')
      .set(victim.header)
      .send({ orderDetails: { paymentId: 'wallet' } })
    const after = await walletBalance(victim)
    removeOrderPdf(checkout.body?.orderConfirmation)

    const storedBasketId = createRes.body?.data?.BasketId
    const failures: string[] = []
    if (createRes.status < 400 && Number(storedBasketId) !== attacker.bid) {
      failures.push(`create stored BasketId ${String(storedBasketId)} instead of the signed-in basket ${attacker.bid}`)
    }
    if (updateRes != null && updateRes.status < 400 && Number(updateRes.body?.data?.BasketId) === victim.bid) {
      failures.push(`update set BasketId to the other customer's basket ${victim.bid}`)
    }
    if (victimProducts.includes(id)) {
      failures.push(`other customer's basket ${victim.bid} contains product ${id}`)
    }
    if (checkout.status !== 200) {
      failures.push(`checkout status ${checkout.status}`)
    }
    if (after !== before) {
      failures.push(`wallet balance changed from ${before} to ${after}`)
    }
    assert.deepEqual(failures, [])
  })

  void it('a line created with a null basket cannot be assigned to another customer or charged at checkout', async () => {
    const attacker = await customer('null-basket')
    const victim = await customer('null-basket-victim')
    const id = await productId('Lemon Juice (500ml)')
    const before = await walletBalance(victim)

    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(attacker.header)
      .send({ ProductId: id, quantity: 1, BasketId: null })

    let updateRes: request.Response | undefined
    if (createRes.status < 400 && createRes.body?.data?.id != null) {
      updateRes = await request(app)
        .put('/api/BasketItems/' + createRes.body.data.id)
        .set(attacker.header)
        .send({ BasketId: victim.bid })
    }

    const victimProducts = await basketProductIds(victim, victim.bid)
    const checkout = await request(app)
      .post('/rest/basket/' + victim.bid + '/checkout')
      .set(victim.header)
      .send({ orderDetails: { paymentId: 'wallet' } })
    const after = await walletBalance(victim)
    removeOrderPdf(checkout.body?.orderConfirmation)

    const storedBasketId = createRes.body?.data?.BasketId
    const failures: string[] = []
    if (createRes.status < 400 && Number(storedBasketId) !== attacker.bid) {
      failures.push(`create stored BasketId ${String(storedBasketId)} instead of the signed-in basket ${attacker.bid}`)
    }
    if (updateRes != null && updateRes.status < 400 && Number(updateRes.body?.data?.BasketId) === victim.bid) {
      failures.push(`update set BasketId to the other customer's basket ${victim.bid}`)
    }
    if (victimProducts.includes(id)) {
      failures.push(`other customer's basket ${victim.bid} contains product ${id}`)
    }
    if (checkout.status !== 200) {
      failures.push(`checkout status ${checkout.status}`)
    }
    if (after !== before) {
      failures.push(`wallet balance changed from ${before} to ${after}`)
    }
    assert.deepEqual(failures, [])
  })

  void it('the basket id that is checked is the basket id that is stored', async () => {
    const attacker = await customer('duplicate-basket')
    const victim = await customer('duplicate-basket-victim')
    const id = await productId('Eggfruit Juice (500ml)')
    const before = await walletBalance(victim)
    const raw = `{"BasketId":${attacker.bid},"ProductId":${id},"quantity":1,"BasketId":${victim.bid}}`

    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(attacker.header)
      .send(raw)

    const victimProducts = await basketProductIds(victim, victim.bid)
    const checkout = await request(app)
      .post('/rest/basket/' + victim.bid + '/checkout')
      .set(victim.header)
      .send({ orderDetails: { paymentId: 'wallet' } })
    const after = await walletBalance(victim)
    removeOrderPdf(checkout.body?.orderConfirmation)

    const storedBasketId = createRes.body?.data?.BasketId
    const failures: string[] = []
    if (createRes.status < 400 && Number(storedBasketId) !== attacker.bid) {
      failures.push(`create stored BasketId ${String(storedBasketId)} instead of the signed-in basket ${attacker.bid}`)
    }
    if (victimProducts.includes(id)) {
      failures.push(`other customer's basket ${victim.bid} contains product ${id}`)
    }
    if (checkout.status !== 200) {
      failures.push(`checkout status ${checkout.status}`)
    }
    if (after !== before) {
      failures.push(`wallet balance changed from ${before} to ${after}`)
    }
    assert.deepEqual(failures, [])
  })

  void it('a signed-in session without a basket id cannot insert a line for any basket', async () => {
    const attacker = await customer('no-bid')
    const victim = await customer('no-bid-victim')
    const id = await productId('Banana Juice (1000ml)')
    const session = security.authenticatedUsers.get(attacker.token)
    assert.ok(session)
    delete session.bid
    const before = await walletBalance(victim)

    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(attacker.header)
      .send({ ProductId: id, quantity: 1 })

    let updateRes: request.Response | undefined
    if (createRes.status < 400 && createRes.body?.data?.id != null) {
      updateRes = await request(app)
        .put('/api/BasketItems/' + createRes.body.data.id)
        .set(attacker.header)
        .send({ BasketId: victim.bid })
    }

    const victimProducts = await basketProductIds(victim, victim.bid)
    const checkout = await request(app)
      .post('/rest/basket/' + victim.bid + '/checkout')
      .set(victim.header)
      .send({ orderDetails: { paymentId: 'wallet' } })
    const after = await walletBalance(victim)
    removeOrderPdf(checkout.body?.orderConfirmation)

    const failures: string[] = []
    if (createRes.status < 400) {
      failures.push(`create was accepted with status ${createRes.status} and BasketId ${String(createRes.body?.data?.BasketId)}`)
    }
    if (updateRes != null && updateRes.status < 400 && Number(updateRes.body?.data?.BasketId) === victim.bid) {
      failures.push(`update set BasketId to the other customer's basket ${victim.bid}`)
    }
    if (victimProducts.includes(id)) {
      failures.push(`other customer's basket ${victim.bid} contains product ${id}`)
    }
    if (checkout.status !== 200) {
      failures.push(`checkout status ${checkout.status}`)
    }
    if (after !== before) {
      failures.push(`wallet balance changed from ${before} to ${after}`)
    }
    assert.deepEqual(failures, [])
  })

  void it('a null product id cannot be replaced on an existing line', async () => {
    const attacker = await customer('null-product')
    const id = await productId('Raspberry Juice (1000ml)')
    const created = await BasketItemModel.create({
      BasketId: attacker.bid,
      quantity: 1,
      ProductId: undefined as unknown as number
    })

    const updateRes = await request(app)
      .put('/api/BasketItems/' + created.id)
      .set(attacker.header)
      .send({ ProductId: id })

    const stored = await BasketItemModel.findByPk(created.id)
    const failures: string[] = []
    if (updateRes.status < 400 && Number(updateRes.body?.data?.ProductId) === id) {
      failures.push(`update set ProductId to ${id}`)
    }
    if (stored != null && Number(stored.ProductId) === id) {
      failures.push(`stored ProductId is ${stored.ProductId}`)
    }
    assert.deepEqual(failures, [])
  })
})
