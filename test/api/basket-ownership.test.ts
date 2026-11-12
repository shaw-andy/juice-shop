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
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

const PLACEHOLDER_PASSWORD = 'placeholder-password'

interface Session {
  token: string
  bid: number
  email: string
}

interface StockedProduct {
  id: number
  price: number
}

let app: Express
let products: StockedProduct[]
let emailSequence = 0

before(
  async () => {
    const result = await createTestApp()
    app = result.app
    products = await stockedProducts()
  },
  { timeout: 60000 }
)

void describe('basket ownership', { concurrency: false }, () => {
  void it('GET /rest/basket/:id does not return another user basket', async () => {
    const victim = await openSession('victim-read')
    const attacker = await openSession('attacker-read')
    const product = products[0]
    await addItem(victim, product.id)

    const res = await request(app)
      .get('/rest/basket/' + victim.bid)
      .query({ id: attacker.bid, BasketId: attacker.bid })
      .set(auth(attacker.token))
      .send({ id: attacker.bid, BasketId: attacker.bid })

    assert.notEqual(res.body?.data?.id, victim.bid)
    assert.equal(listsProduct(res.body, product.id), false)
  })

  void it('GET /rest/basket/:id returns the caller basket when another basket id is also supplied', async () => {
    const victim = await openSession('victim-own-read')
    const attacker = await openSession('attacker-own-read')
    const ownProduct = products[0]
    const otherProduct = products[1]
    await addItem(attacker, ownProduct.id)
    await addItem(victim, otherProduct.id)

    const res = await request(app)
      .get('/rest/basket/' + attacker.bid)
      .query({ id: victim.bid, BasketId: victim.bid })
      .set(auth(attacker.token))
      .send({ id: victim.bid, BasketId: victim.bid })

    assert.equal(res.status, 200)
    assert.equal(res.body?.data?.id, attacker.bid)
    assert.equal(listsProduct(res.body, ownProduct.id), true)
    assert.equal(listsProduct(res.body, otherProduct.id), false)
  })

  void it('PUT /rest/basket/:id/coupon/:coupon does not change another user basket', async () => {
    const victim = await openSession('victim-coupon')
    const attacker = await openSession('attacker-coupon')
    const coupon = security.generateCoupon(15)
    const victimBefore = await BasketModel.findByPk(victim.bid)
    const attackerBefore = await BasketModel.findByPk(attacker.bid)

    const res = await request(app)
      .put('/rest/basket/' + victim.bid + '/coupon/' + encodeURIComponent(coupon))
      .set(auth(attacker.token))
      .send({ id: attacker.bid, BasketId: attacker.bid })

    const victimAfter = await BasketModel.findByPk(victim.bid)
    const attackerAfter = await BasketModel.findByPk(attacker.bid)
    assert.equal(victimAfter?.coupon ?? null, victimBefore?.coupon ?? null)
    assert.equal(attackerAfter?.coupon ?? null, attackerBefore?.coupon ?? null)
    assert.equal(res.body?.discount, undefined)
  })

  void it('PUT /rest/basket/:id/coupon/:coupon updates the caller basket and not a basket id supplied beside it', async () => {
    const victim = await openSession('victim-own-coupon')
    const attacker = await openSession('attacker-own-coupon')
    const coupon = security.generateCoupon(15)

    const res = await request(app)
      .put('/rest/basket/' + attacker.bid + '/coupon/' + encodeURIComponent(coupon))
      .set(auth(attacker.token))
      .send({ id: victim.bid, BasketId: victim.bid })

    const victimAfter = await BasketModel.findByPk(victim.bid)
    const attackerAfter = await BasketModel.findByPk(attacker.bid)
    assert.equal(res.status, 200)
    assert.equal(res.body.discount, 15)
    assert.equal(attackerAfter?.coupon, coupon)
    assert.equal(victimAfter?.coupon ?? null, null)
  })

  void it('POST /rest/basket/:id/checkout does not check out another user basket', async () => {
    const victim = await openSession('victim-checkout')
    const attacker = await openSession('attacker-checkout')
    const product = products[0]
    await addItem(victim, product.id)
    const before = await snapshot(victim, attacker, product.id)
    const pdfsBefore = listOrderPdfs()

    try {
      const res = await request(app)
        .post('/rest/basket/' + victim.bid + '/checkout')
        .set(auth(attacker.token))
        .send({ id: attacker.bid, BasketId: attacker.bid, couponData: 'placeholder' })

      const after = await snapshot(victim, attacker, product.id)
      assert.deepEqual(
        { ...after, newOrderPdfs: newOrderPdfs(pdfsBefore).length },
        { ...before, newOrderPdfs: 0 }
      )
      assert.equal(res.body?.orderConfirmation, undefined)
    } finally {
      removeNewPdfs(pdfsBefore)
    }
  })

  void it('POST /rest/basket/:id/checkout checks out the caller basket and not a basket id supplied beside it', async () => {
    const victim = await openSession('victim-own-checkout')
    const attacker = await openSession('attacker-own-checkout')
    const product = products[0]
    await addItem(victim, product.id)
    await addItem(attacker, product.id)
    const before = await snapshot(victim, attacker, product.id)
    const pdfsBefore = listOrderPdfs()

    try {
      const res = await request(app)
        .post('/rest/basket/' + attacker.bid + '/checkout')
        .set(auth(attacker.token))
        .send({ id: victim.bid, BasketId: victim.bid })

      const after = await snapshot(victim, attacker, product.id)
      assert.equal(res.status, 200)
      assert.equal(typeof res.body.orderConfirmation, 'string')
      assert.equal(after.attackerItems, 0)
      assert.equal(after.victimItems, before.victimItems)
      assert.equal(after.stock, before.stock - 1)
      assert.equal(after.victimWallet, before.victimWallet)
      assert.equal(after.ordersForProduct, before.ordersForProduct + 1)
      assert.equal(newOrderPdfs(pdfsBefore).length, 1)
    } finally {
      removeNewPdfs(pdfsBefore)
    }
  })

  void it('POST /rest/basket/:id/checkout without a login does not change the basket', async () => {
    const victim = await openSession('victim-anonymous')
    const product = products[0]
    await addItem(victim, product.id)
    const itemsBefore = await BasketItemModel.count({ where: { BasketId: victim.bid } })
    const stockBefore = await stockOf(product.id)
    const pdfsBefore = listOrderPdfs()

    try {
      const res = await request(app)
        .post('/rest/basket/' + victim.bid + '/checkout')
        .set({ 'content-type': 'application/json' })
        .send({ id: victim.bid, BasketId: victim.bid })

      assert.equal(res.status, 401)
      assert.equal(await BasketItemModel.count({ where: { BasketId: victim.bid } }), itemsBefore)
      assert.equal(await stockOf(product.id), stockBefore)
      assert.deepEqual(newOrderPdfs(pdfsBefore), [])
    } finally {
      removeNewPdfs(pdfsBefore)
    }
  })
})

async function openSession (label: string): Promise<Session> {
  emailSequence += 1
  const email = 'basket-' + label + '-' + emailSequence + '@example.test'
  await register(app, { email, password: PLACEHOLDER_PASSWORD })
  const authentication = await login(app, { email, password: PLACEHOLDER_PASSWORD })
  const bid = Number(authentication.bid)
  assert.equal(Number.isInteger(bid), true)
  const basket = await BasketModel.findByPk(bid)
  assert.equal(basket == null, false)
  return { token: authentication.token, bid, email }
}

function auth (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

async function addItem (session: Session, productId: number) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(auth(session.token))
    .send({ ProductId: productId, BasketId: session.bid, quantity: 1 })
  assert.equal(res.status, 200)
  assert.equal(res.body?.data?.BasketId, session.bid)
}

async function stockedProducts (): Promise<StockedProduct[]> {
  const rows = await ProductModel.findAll()
  const quantities = await QuantityModel.findAll()
  const matches = rows.flatMap((product) => {
    const stock = quantities.find((row) => row.ProductId === product.id)
    const price = Number(product.price)
    if (stock == null || stock.quantity < 5) return []
    if (stock.limitPerUser != null && stock.limitPerUser < 1) return []
    if (!(price >= 10)) return []
    return [{ id: product.id, price }]
  })
  assert.equal(matches.length >= 2, true)
  return matches.slice(0, 2)
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.equal(row == null, false)
  return Number(row?.quantity)
}

async function walletBalance (bid: number) {
  const basket = await BasketModel.findByPk(bid)
  const wallet = await WalletModel.findOne({ where: { UserId: basket?.UserId } })
  assert.equal(wallet == null, false)
  return Number(wallet?.balance)
}

async function ordersForProduct (productId: number) {
  const orders = await db.ordersCollection.find({})
  return orders.filter((order: { products?: Array<{ id?: number }> }) => {
    return Array.isArray(order.products) && order.products.some((product) => product.id === productId)
  }).length
}

async function snapshot (victim: Session, attacker: Session, productId: number) {
  return {
    victimItems: await BasketItemModel.count({ where: { BasketId: victim.bid } }),
    attackerItems: await BasketItemModel.count({ where: { BasketId: attacker.bid } }),
    stock: await stockOf(productId),
    victimWallet: await walletBalance(victim.bid),
    attackerWallet: await walletBalance(attacker.bid),
    ordersForProduct: await ordersForProduct(productId),
    victimOrders: await ordersForEmail(victim.email),
    attackerOrders: await ordersForEmail(attacker.email)
  }
}

function newOrderPdfs (before: string[]) {
  const known = new Set(before)
  return listOrderPdfs().filter((name) => !known.has(name))
}

async function ordersForEmail (email: string) {
  const orders = await db.ordersCollection.find({ email: email.replace(/[aeiou]/gi, '*') })
  return orders.length
}

function listsProduct (body: { data?: { Products?: Array<{ id?: number }> } }, productId: number) {
  const listed = body?.data?.Products
  if (!Array.isArray(listed)) return false
  return listed.some((product) => product?.id === productId)
}

function listOrderPdfs () {
  return fs.readdirSync(path.resolve('ftp')).filter((name) => /^order_.*\.pdf$/.test(name))
}

function removeNewPdfs (before: string[]) {
  const known = new Set(before)
  for (const name of listOrderPdfs()) {
    if (!known.has(name)) fs.unlinkSync(path.resolve('ftp', name))
  }
}
