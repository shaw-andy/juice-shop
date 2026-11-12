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
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import { ProductModel } from '../../models/product'
import { DeliveryModel } from '../../models/delivery'
import { QuantityModel } from '../../models/quantity'
import * as security from '../../lib/insecurity'

const PLACEHOLDER_PASSWORD = 'placeholder-password'
const MEMBERSHIP_PRICE = 49

let app: Express
let sequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function registerCustomer (label: string) {
  sequence += 1
  const email = `${label}.${sequence}@example.test`
  const registered = await request(app)
    .post('/api/Users/')
    .set({ 'content-type': 'application/json' })
    .send({
      email,
      password: PLACEHOLDER_PASSWORD,
      passwordRepeat: PLACEHOLDER_PASSWORD
    })
  assert.equal(registered.status, 201)
  const userId = registered.body.data.id as number
  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  const wallet = await waitForWallet(userId)
  const user = await UserModel.findByPk(userId)
  assert.ok(user)
  return {
    email,
    userId,
    token: authentication.token as string,
    bid: authentication.bid as number,
    balance: wallet.balance,
    role: user.role,
    deluxeToken: user.deluxeToken
  }
}

async function waitForWallet (userId: number) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const wallet = await WalletModel.findOne({ where: { UserId: userId } })
    if (wallet != null) {
      return wallet
    }
    await new Promise(resolve => { setTimeout(resolve, 20) })
  }
  throw new Error('Wallet was not created for user ' + String(userId))
}

async function resetFraudFlag () {
  challenges.freeDeluxeChallenge.solved = false
  await challenges.freeDeluxeChallenge.save()
}

async function postUpgrade (token: string, body: Record<string, unknown>) {
  await resetFraudFlag()
  return await request(app)
    .post('/rest/deluxe-membership')
    .set(bearer(token))
    .send(body)
}

async function assertUnchangedCustomer (customer: {
  userId: number
  balance: number
  role: string
  deluxeToken: string
}) {
  const user = await UserModel.findByPk(customer.userId)
  assert.ok(user)
  assert.equal(user.role, customer.role)
  assert.equal(user.deluxeToken, customer.deluxeToken)
  const wallet = await WalletModel.findOne({ where: { UserId: customer.userId } })
  assert.ok(wallet)
  assert.equal(wallet.balance, customer.balance)
  assert.equal(challenges.freeDeluxeChallenge.solved, false)
}

function requestFor (token: string) {
  return { headers: { authorization: 'Bearer ' + token } } as Parameters<typeof security.isDeluxe>[0]
}

async function regularPrices () {
  const product = await ProductModel.findOne({ where: { name: 'Apple Juice (1000ml)' } })
  const delivery = await DeliveryModel.findOne({ where: { name: 'Fast Delivery' } })
  const quantity = await QuantityModel.findOne({ where: { ProductId: product?.id } })
  assert.ok(product)
  assert.ok(delivery)
  assert.ok(quantity)
  assert.notEqual(Number(product.price), Number(product.deluxePrice))
  assert.notEqual(Number(delivery.price), Number(delivery.deluxePrice))
  assert.ok(quantity.limitPerUser != null && quantity.limitPerUser > 0)
  assert.ok(quantity.quantity > quantity.limitPerUser)
  return { product, delivery, quantity }
}

async function quotedDeliveryPrice (token: string, deliveryId: number) {
  const res = await request(app)
    .get('/api/Deliverys/' + String(deliveryId))
    .set(bearer(token))
  assert.equal(res.status, 200)
  return Number(res.body.data.price)
}

async function placePricedOrder (token: string, bid: number, productId: number, deliveryId: number) {
  const added = await request(app)
    .post('/api/BasketItems')
    .set(bearer(token))
    .send({ BasketId: bid, ProductId: productId, quantity: 1 })
  assert.equal(added.status, 200)
  const checkout = await request(app)
    .post('/rest/basket/' + String(bid) + '/checkout')
    .set(bearer(token))
    .send({ orderDetails: { deliveryMethodId: deliveryId } })
  assert.equal(checkout.status, 200)
  const tracked = await request(app).get('/rest/track-order/' + checkout.body.orderConfirmation)
  assert.equal(tracked.status, 200)
  const order = tracked.body.data[0]
  assert.ok(order)
  return order
}

void describe('deluxe membership requires a collected membership charge', () => {
  void it('rejects payment modes other than wallet and card without upgrading or charging', async () => {
    const modes: Array<Record<string, unknown>> = [
      {},
      { paymentMode: null },
      { paymentMode: '' },
      { paymentMode: 'invoice' },
      { paymentMode: 'Wallet' },
      { paymentMode: ' wallet' },
      { paymentMode: 'card ' },
      { paymentMode: ['wallet'] },
      { paymentMode: { type: 'wallet' } }
    ]

    const failures: string[] = []
    for (const body of modes) {
      const customer = await registerCustomer('unpaid')
      await WalletModel.update({ balance: 100 }, { where: { UserId: customer.userId } })
      customer.balance = 100
      const victim = await registerCustomer('bystander')
      await WalletModel.update({ balance: 100 }, { where: { UserId: victim.userId } })
      victim.balance = 100

      const res = await postUpgrade(customer.token, {
        ...body,
        UserId: victim.userId,
        userId: victim.userId,
        paymentId: victim.userId
      })

      const problems: string[] = []
      if (res.status !== 400) problems.push('status ' + String(res.status))
      if (res.body.status === 'success') problems.push('body success')
      if (res.body?.data?.token != null) problems.push('issued a token')
      const payer = await UserModel.findByPk(customer.userId)
      const payerWallet = await WalletModel.findOne({ where: { UserId: customer.userId } })
      const bystander = await UserModel.findByPk(victim.userId)
      const bystanderWallet = await WalletModel.findOne({ where: { UserId: victim.userId } })
      if (payer?.role !== customer.role) problems.push('customer role ' + String(payer?.role))
      if (payer?.deluxeToken !== customer.deluxeToken) problems.push('customer deluxe token changed')
      if (payerWallet?.balance !== customer.balance) problems.push('customer balance ' + String(payerWallet?.balance))
      if (bystander?.role !== victim.role) problems.push('other user role ' + String(bystander?.role))
      if (bystanderWallet?.balance !== victim.balance) problems.push('other user balance ' + String(bystanderWallet?.balance))
      if (challenges.freeDeluxeChallenge.solved) problems.push('deluxe fraud challenge solved')
      if (problems.length > 0) failures.push(JSON.stringify(body) + ': ' + problems.join('; '))
    }
    assert.deepEqual(failures, [])
  })

  void it('does not grant deluxe pricing, delivery rates, or purchase limits after an unpaid upgrade', async () => {
    const { product, delivery, quantity } = await regularPrices()
    const customer = await registerCustomer('checkout')
    const added = await request(app)
      .post('/api/BasketItems')
      .set(bearer(customer.token))
      .send({ BasketId: customer.bid, ProductId: product.id, quantity: 1 })
    assert.equal(added.status, 200)

    const upgrade = await postUpgrade(customer.token, { paymentMode: 'invoice', UserId: customer.userId })
    const issuedToken = upgrade.body?.data?.token as string | undefined
    const problems: string[] = []
    if (typeof issuedToken !== 'string') {
      problems.push('upgrade did not return a token to check')
    } else {
      if (security.isDeluxe(requestFor(issuedToken))) problems.push('issued token is deluxe')
      const singleQuote = await quotedDeliveryPrice(issuedToken, delivery.id)
      if (singleQuote !== Number(delivery.price)) problems.push('single delivery quote ' + String(singleQuote))
      const listedWithIssued = await request(app).get('/api/Deliverys').set(bearer(issuedToken))
      const issuedListPrice = listedWithIssued.body.data?.find((method: { id: number }) => method.id === delivery.id)
      if (Number(issuedListPrice?.price) !== Number(delivery.price)) problems.push('delivery list price ' + String(issuedListPrice?.price))
      const checkout = await request(app)
        .post('/rest/basket/' + String(customer.bid) + '/checkout')
        .set(bearer(issuedToken))
        .send({ orderDetails: { deliveryMethodId: delivery.id } })
      if (checkout.status !== 200) {
        problems.push('checkout status ' + String(checkout.status))
      } else {
        const tracked = await request(app).get('/rest/track-order/' + checkout.body.orderConfirmation)
        const issuedOrder = tracked.body.data?.[0]
        const line = Number(issuedOrder?.products?.[0]?.price)
        const deliveryPrice = Number(issuedOrder?.deliveryPrice)
        const total = Number(issuedOrder?.totalPrice)
        if (line !== Number(product.price)) problems.push('line price ' + String(line) + ' expected ' + String(product.price))
        if (deliveryPrice !== Number(delivery.price)) problems.push('delivery price ' + String(deliveryPrice) + ' expected ' + String(delivery.price))
        if (!(Math.abs(total - (Number(product.price) + Number(delivery.price))) < 0.001)) problems.push('total ' + String(total))
      }
    }

    const again = await login(app, { email: customer.email, password: PLACEHOLDER_PASSWORD })
    if (security.isDeluxe(requestFor(again.token))) problems.push('relogin token is deluxe')
    const reloginQuote = await quotedDeliveryPrice(again.token, delivery.id)
    if (reloginQuote !== Number(delivery.price)) problems.push('relogin delivery quote ' + String(reloginQuote))
    const order = await placePricedOrder(again.token, again.bid, product.id, delivery.id)
    const reloginLine = Number(order.products[0].price)
    const reloginDelivery = Number(order.deliveryPrice)
    if (reloginLine !== Number(product.price)) problems.push('relogin line ' + String(reloginLine))
    if (reloginDelivery !== Number(delivery.price)) problems.push('relogin delivery ' + String(reloginDelivery))
    const overLimit = await request(app)
      .post('/api/BasketItems')
      .set(bearer(again.token))
      .send({ BasketId: again.bid, ProductId: product.id, quantity: quantity.limitPerUser + 1 })
    if (overLimit.status !== 400) problems.push('over-limit status ' + String(overLimit.status))
    assert.deepEqual(problems, [])
  })

  void it('upgrades only the authenticated customer after the wallet balance drops by the membership price', async () => {
    const { product, delivery } = await regularPrices()
    const customer = await registerCustomer('payer')
    const victim = await registerCustomer('rich')
    await WalletModel.update({ balance: MEMBERSHIP_PRICE }, { where: { UserId: customer.userId } })
    await WalletModel.update({ balance: MEMBERSHIP_PRICE }, { where: { UserId: victim.userId } })

    const res = await postUpgrade(customer.token, {
      paymentMode: 'wallet',
      UserId: victim.userId,
      paymentId: victim.userId
    })

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    const payer = await UserModel.findByPk(customer.userId)
    const bystander = await UserModel.findByPk(victim.userId)
    const payerWallet = await WalletModel.findOne({ where: { UserId: customer.userId } })
    const bystanderWallet = await WalletModel.findOne({ where: { UserId: victim.userId } })
    assert.ok(payer)
    assert.ok(bystander)
    assert.ok(payerWallet)
    assert.ok(bystanderWallet)
    assert.equal(payer.role, 'deluxe')
    assert.equal(payerWallet.balance, 0)
    assert.equal(bystander.role, 'customer')
    assert.equal(bystanderWallet.balance, MEMBERSHIP_PRICE)
    assert.equal(challenges.freeDeluxeChallenge.solved, false)

    const again = await login(app, { email: customer.email, password: PLACEHOLDER_PASSWORD })
    assert.equal(security.isDeluxe(requestFor(again.token)), true)
    assert.equal(await quotedDeliveryPrice(again.token, delivery.id), Number(delivery.deluxePrice))
    const order = await placePricedOrder(again.token, again.bid, product.id, delivery.id)
    assert.equal(Number(order.products[0].price), Number(product.deluxePrice))
    assert.equal(Number(order.deliveryPrice), Number(delivery.deluxePrice))
    assert.ok(Math.abs(Number(order.totalPrice) - (Number(product.deluxePrice) + Number(delivery.deluxePrice))) < 0.001)
  })

  void it('does not upgrade when the wallet cannot cover the membership price', async () => {
    const customer = await registerCustomer('broke')
    assert.ok(customer.balance < MEMBERSHIP_PRICE)
    const res = await postUpgrade(customer.token, { paymentMode: 'wallet' })
    assert.equal(res.status, 400)
    assert.equal(res.body?.data?.token, undefined)
    await assertUnchangedCustomer(customer)
  })

  void it('does not upgrade when paymentMode is wallet but no wallet row is charged', async () => {
    const customer = await registerCustomer('nowallet')
    const removed = await WalletModel.destroy({ where: { UserId: customer.userId } })
    assert.equal(removed, 1)
    const res = await postUpgrade(customer.token, { paymentMode: 'wallet' })
    assert.equal(res.status, 400)
    assert.equal(res.body?.data?.token, undefined)
    const user = await UserModel.findByPk(customer.userId)
    assert.ok(user)
    assert.equal(user.role, 'customer')
    assert.equal(user.deluxeToken, customer.deluxeToken)
    const wallet = await WalletModel.findOne({ where: { UserId: customer.userId } })
    assert.equal(wallet, null)
    assert.equal(challenges.freeDeluxeChallenge.solved, false)
  })
})
