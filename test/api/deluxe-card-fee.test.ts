/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { register, login } from './helpers/auth'
import { UserModel } from '../../models/user'
import { CardModel } from '../../models/card'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { DeliveryModel } from '../../models/delivery'

const MEMBERSHIP_FEE = 49
const PLACEHOLDER_PASSWORD = 'placeholder-password'
const PLACEHOLDER_CARD_NUMBER = 1000000000000000
const APPLE_JUICE = 'Apple Juice (1000ml)'
const FOIL_CARD = 'Juice Shop Adversary Trading Card (Super Rare)'
const ONE_DAY_DELIVERY = 'One Day Delivery'

type AuthHeader = { Authorization: string, 'content-type': string }

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('card-mode deluxe membership fee', { concurrency: false }, () => {
  void it('does not treat a saved card expiring in 2080 as payment of 49', async () => {
    await assertCardPaymentIsNotFree(2080, (cardId) => cardId, 2079)
  })

  void it('does not treat a saved card expiring in 2099 as payment of 49', async () => {
    await assertCardPaymentIsNotFree(2099, (cardId) => cardId, 2100)
  })

  void it('does not treat a string card id as payment of 49', async () => {
    await assertCardPaymentIsNotFree(2090, (cardId) => String(cardId))
  })

  void it('does not let a saved card raise the per-customer quantity cap', async () => {
    const customer = await openCustomer()
    const cardId = await saveCard(customer, 2091)
    const upgrade = await upgradeWithCard(customer, cardId)
    const paid = feeCaptured(upgrade.balanceBefore, upgrade.balanceAfter)
    const renewed = await login(app, { email: customer.email, password: PLACEHOLDER_PASSWORD })
    const shopping = authHeader(renewed.token)

    const apple = await ProductModel.findOne({ where: { name: APPLE_JUICE } })
    assert.ok(apple)
    const stock = await QuantityModel.findOne({ where: { ProductId: apple.id } })
    assert.ok(stock?.limitPerUser)
    const limit = Number(stock.limitPerUser)
    assert.ok(Number(stock.quantity) > limit)
    const overCap = limit + 1

    const over = await request(app)
      .post('/api/BasketItems')
      .set(shopping)
      .send({ BasketId: renewed.bid, ProductId: apple.id, quantity: overCap, UserId: 1 })

    if (paid) {
      assert.equal(over.status, 200)
    } else {
      assert.equal(over.status, 400)
      assert.match(String(over.body.error), /only up to/)
      const single = await request(app)
        .post('/api/BasketItems')
        .set(shopping)
        .send({ BasketId: renewed.bid, ProductId: apple.id, quantity: 1, UserId: 1 })
      assert.equal(single.status, 200)
      const updated = await request(app)
        .put('/api/BasketItems/' + single.body.data.id)
        .set(shopping)
        .send({ quantity: overCap, UserId: 1 })
      assert.equal(updated.status, 400)
      assert.match(String(updated.body.error), /only up to/)
    }
    assert.equal(upgrade.role === 'deluxe', paid)
    assert.equal(await tokenIsDeluxe(shopping), paid)
  })

  void it('does not record deluxe product or delivery prices after an unpaid card upgrade', async () => {
    const customer = await openCustomer()
    const cardId = await saveCard(customer, 2092)
    const paidSetup = await catalogForCheckout()
    for (const productId of [paidSetup.apple.id, paidSetup.foil.id]) {
      const added = await request(app)
        .post('/api/BasketItems')
        .set(customer.header)
        .send({ BasketId: customer.bid, ProductId: productId, quantity: 1 })
      assert.equal(added.status, 200)
    }

    const upgrade = await upgradeWithCard(customer, cardId)
    const session = await sessionAfterUpgrade(customer, upgrade)
    const paid = feeCaptured(upgrade.balanceBefore, upgrade.balanceAfter)
    const { apple, foil, oneDay } = paidSetup
    const listed = await request(app).get('/api/Deliverys').set(session.header)
    assert.equal(listed.status, 200)
    const listedOneDay = listed.body.data.find((method: { name: string }) => method.name === ONE_DAY_DELIVERY)

    let orderId = ''
    try {
      const checkout = await request(app)
        .post('/rest/basket/' + session.bid + '/checkout')
        .set(session.header)
        .send({
          orderDetails: {
            paymentId: String(cardId),
            addressId: '1',
            deliveryMethodId: String(oneDay.id)
          }
        })
      assert.equal(checkout.status, 200)
      orderId = checkout.body.orderConfirmation

      const history = await request(app).get('/rest/order-history').set(session.header)
      assert.equal(history.status, 200)
      const order = history.body.data.find((row: { orderId: string }) => row.orderId === orderId)
      assert.ok(order)
      const appleLine = order.products.find((line: { name: string }) => line.name === APPLE_JUICE)
      const foilLine = order.products.find((line: { name: string }) => line.name === FOIL_CARD)
      assert.ok(appleLine)
      assert.ok(foilLine)
      assert.equal(money(appleLine.price), paid ? money(apple.deluxePrice) : money(apple.price))
      assert.equal(money(foilLine.price), paid ? money(foil.deluxePrice) : money(foil.price))
      assert.equal(money(order.deliveryPrice), paid ? money(oneDay.deluxePrice) : money(oneDay.price))
      const expectedTotal = money(appleLine.price) + money(foilLine.price) + money(order.deliveryPrice)
      assert.equal(money(order.totalPrice), money(expectedTotal))
    } finally {
      if (orderId) {
        await fs.rm(path.join('ftp', `order_${orderId}.pdf`), { force: true })
      }
    }

    assert.equal(money(listedOneDay.price), paid ? money(oneDay.deluxePrice) : money(oneDay.price))
    assert.equal(upgrade.role === 'deluxe', paid)
    assert.equal(session.deluxeSession, paid)
  })

  void it('does not let a saved card fund the wallet that pays for deluxe membership', async () => {
    const customer = await openCustomer()
    const cardId = await saveCard(customer, 2093)
    const before = await balanceOf(customer.header)

    const topUp = await request(app)
      .put('/rest/wallet/balance')
      .set(customer.header)
      .send({ balance: MEMBERSHIP_FEE, paymentId: cardId, UserId: 1 })
    const afterTopUp = await balanceOf(customer.header)

    const deluxe = await request(app)
      .post('/rest/deluxe-membership')
      .set(customer.header)
      .send({ paymentMode: 'wallet', UserId: 1 })
    const after = await balanceOf(customer.header)
    const user = await UserModel.findOne({ where: { email: customer.email } })

    assert.equal(topUp.status === 200, afterTopUp - before === MEMBERSHIP_FEE)
    assert.equal(
      `${afterTopUp}:${after}:${user?.role}:${deluxe.status}`,
      `${before}:${before}:customer:400`
    )
    assert.equal(user?.deluxeToken ?? '', '')
  })

  void it('does not upgrade either customer when the card belongs to someone else', async () => {
    const payer = await openCustomer()
    const owner = await openCustomer()
    const cardId = await saveCard(owner, 2094)
    const payerBefore = await balanceOf(payer.header)
    const ownerBefore = await balanceOf(owner.header)
    const ownerUserBefore = await UserModel.findOne({ where: { email: owner.email } })

    const upgrade = await request(app)
      .post('/rest/deluxe-membership')
      .set(payer.header)
      .send({ paymentMode: 'card', paymentId: cardId, UserId: ownerUserBefore?.id })

    const payerAfter = await UserModel.findOne({ where: { email: payer.email } })
    const ownerAfter = await UserModel.findOne({ where: { email: owner.email } })
    assert.equal(upgrade.status, 400)
    assert.equal(payerAfter?.role, 'customer')
    assert.equal(payerAfter?.deluxeToken ?? '', '')
    assert.equal(ownerAfter?.role, ownerUserBefore?.role)
    assert.equal(ownerAfter?.deluxeToken ?? '', ownerUserBefore?.deluxeToken ?? '')
    assert.equal(await balanceOf(payer.header), payerBefore)
    assert.equal(await balanceOf(owner.header), ownerBefore)
    const card = await CardModel.findByPk(cardId)
    assert.equal(card?.UserId, ownerUserBefore?.id)
  })
})

async function assertCardPaymentIsNotFree (expYear: number, paymentIdOf: (cardId: number) => number | string, rejectedYear?: number) {
  const customer = await openCustomer()
  if (rejectedYear !== undefined) {
    const rejected = await request(app)
      .post('/api/Cards')
      .set(customer.header)
      .send(cardBody(rejectedYear, 1))
    assert.equal(rejected.status, 400)
  }

  const balanceBeforeCreate = await balanceOf(customer.header)
  const created = await request(app)
    .post('/api/Cards')
    .set(customer.header)
    .send(cardBody(expYear, 1))
  assert.equal(created.status, 201)
  const user = await UserModel.findOne({ where: { email: customer.email } })
  assert.ok(user)
  assert.equal(created.body.data.UserId, user.id)
  assert.equal(created.body.data.expYear, expYear)
  assert.equal(await balanceOf(customer.header), balanceBeforeCreate)
  const stored = await CardModel.findByPk(created.body.data.id)
  assert.ok(stored)
  assert.ok(stored.expYear > new Date().getFullYear() || (stored.expYear === new Date().getFullYear() && stored.expMonth - 1 >= new Date().getMonth()))

  const seeded = await UserModel.findByPk(1)
  const seededRole = seeded?.role
  const upgrade = await upgradeWithCard(customer, paymentIdOf(created.body.data.id))
  const paid = feeCaptured(upgrade.balanceBefore, upgrade.balanceAfter)
  const session = await sessionAfterUpgrade(customer, upgrade)
  const upgraded = await UserModel.findOne({ where: { email: customer.email } })
  const seededAfter = await UserModel.findByPk(1)

  assert.equal(upgraded?.role === 'deluxe', paid)
  assert.equal(session.deluxeSession, paid)
  assert.equal(seededAfter?.role, seededRole)
  if (!paid) {
    assert.notEqual(upgrade.response.status, 200)
    assert.equal(upgraded?.role, 'customer')
    assert.equal(upgraded?.deluxeToken ?? '', '')
    assert.equal(upgrade.balanceAfter, upgrade.balanceBefore)
    const card = await CardModel.findByPk(created.body.data.id)
    assert.equal(card?.UserId, user.id)
    assert.equal(card?.expYear, expYear)
  }
}

async function openCustomer () {
  const email = `card-fee-${randomUUID()}@${config.get<string>('application.domain')}`
  await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  const header = authHeader(authentication.token)
  await balanceOf(header)
  return { email, token: authentication.token as string, bid: authentication.bid as number, header }
}

function authHeader (token: string): AuthHeader {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

function cardBody (expYear: number, userId: number) {
  return {
    fullName: 'Placeholder Customer',
    cardNum: PLACEHOLDER_CARD_NUMBER,
    expMonth: 1,
    expYear,
    UserId: userId
  }
}

async function saveCard (customer: { header: AuthHeader, email: string }, expYear: number) {
  const before = await balanceOf(customer.header)
  const created = await request(app)
    .post('/api/Cards')
    .set(customer.header)
    .send(cardBody(expYear, 1))
  assert.equal(created.status, 201)
  const user = await UserModel.findOne({ where: { email: customer.email } })
  assert.equal(created.body.data.UserId, user?.id)
  assert.equal(await balanceOf(customer.header), before)
  return created.body.data.id as number
}

async function balanceOf (header: AuthHeader) {
  for (let attempt = 0; attempt < 25; attempt++) {
    const res = await request(app).get('/rest/wallet/balance').set(header)
    if (res.status === 200) return Number(res.body.data)
    await new Promise((resolve) => setTimeout(resolve, 40))
  }
  throw new Error('wallet balance was not available')
}

async function upgradeWithCard (customer: { header: AuthHeader, email: string }, paymentId: number | string) {
  const balanceBefore = await balanceOf(customer.header)
  const response = await request(app)
    .post('/rest/deluxe-membership')
    .set(customer.header)
    .send({ paymentMode: 'card', paymentId, UserId: 1 })
  const balanceAfter = await balanceOf(customer.header)
  const user = await UserModel.findOne({ where: { email: customer.email } })
  return {
    response,
    balanceBefore,
    balanceAfter,
    role: user?.role,
    issuedToken: typeof response.body?.data?.token === 'string' ? response.body.data.token as string : undefined
  }
}

function feeCaptured (before: number, after: number) {
  return before >= MEMBERSHIP_FEE && before - after === MEMBERSHIP_FEE
}

async function sessionAfterUpgrade (customer: { token: string, bid: number, header: AuthHeader }, upgrade: { issuedToken?: string }) {
  const token = upgrade.issuedToken ?? customer.token
  const header = authHeader(token)
  const status = await request(app).get('/rest/deluxe-membership').set(header)
  return {
    token,
    bid: customer.bid,
    header,
    deluxeSession: status.status === 400 && status.body.error === 'You are already a deluxe member!'
  }
}

async function tokenIsDeluxe (header: AuthHeader) {
  const status = await request(app).get('/rest/deluxe-membership').set(header)
  return status.status === 400 && status.body.error === 'You are already a deluxe member!'
}

async function catalogForCheckout () {
  const apple = await ProductModel.findOne({ where: { name: APPLE_JUICE } })
  const foil = await ProductModel.findOne({ where: { name: FOIL_CARD }, paranoid: false })
  const oneDay = await DeliveryModel.findOne({ where: { name: ONE_DAY_DELIVERY } })
  assert.ok(apple)
  assert.ok(foil)
  assert.ok(oneDay)
  assert.equal(money(apple.price), 1.99)
  assert.equal(money(apple.deluxePrice), 0.99)
  assert.equal(money(foil.price), 99.99)
  assert.equal(money(foil.deluxePrice), 69.99)
  assert.equal(money(oneDay.price), 0.99)
  assert.equal(money(oneDay.deluxePrice), 0.5)
  const foilStock = await QuantityModel.findOne({ where: { ProductId: foil.id } })
  assert.ok(foilStock)
  assert.ok(foilStock.quantity >= 1)
  return { apple, foil, oneDay }
}

function money (value: unknown) {
  return Number(Number(value).toFixed(2))
}
