/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'

let app: Express

const password = 'Password1'
const buyerEmail = 'buyer-stock@example.test'
const otherEmail = 'other-stock@example.test'

interface CatalogItem {
  id: number
  name: string
  stock: number
  limitPerUser: number | null
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  await register(app, { email: buyerEmail, password })
  await register(app, { email: otherEmail, password })
}, { timeout: 60000 })

async function authenticate (email: string) {
  const authentication = await login(app, { email, password })
  return {
    token: authentication.token as string,
    basketId: Number(authentication.bid)
  }
}

async function catalog (): Promise<CatalogItem[]> {
  const products = await ProductModel.findAll({ paranoid: false })
  const quantities = await QuantityModel.findAll()
  return products.map((product) => {
    const row = quantities.find((quantity) => quantity.ProductId === product.id)
    return {
      id: product.id,
      name: product.name,
      stock: row?.quantity ?? 0,
      limitPerUser: row?.limitPerUser ?? null
    }
  })
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row, `missing quantity row for product ${productId}`)
  return row.quantity
}

function rawBasketItem (basketId: number, checked: { productId: number, quantity: number }, nested: Record<string, unknown>) {
  return JSON.stringify({
    ProductId: checked.productId,
    BasketId: String(basketId),
    quantity: checked.quantity,
    nested
  })
}

async function postRaw (token: string, rawBody: string) {
  return await request(app)
    .post('/api/BasketItems')
    .set('Authorization', 'Bearer ' + token)
    .set('Content-Type', 'application/json')
    .send(rawBody)
}

async function checkout (token: string, basketId: number) {
  const res = await request(app)
    .post('/rest/basket/' + basketId + '/checkout')
    .set('Authorization', 'Bearer ' + token)
    .set('Content-Type', 'application/json')
    .send({})
  const orderId = res.body?.orderConfirmation
  if (typeof orderId === 'string') {
    const pdf = path.resolve('ftp', 'order_' + orderId + '.pdf')
    if (fs.existsSync(pdf)) fs.unlinkSync(pdf)
  }
  return res
}

async function orderLines (token: string) {
  const res = await request(app)
    .get('/rest/order-history')
    .set('Authorization', 'Bearer ' + token)
  assert.equal(res.status, 200)
  const orders = Array.isArray(res.body.data) ? res.body.data : []
  return orders.flatMap((order: { products?: Array<{ id?: number, quantity?: number }> }) => order.products ?? [])
}

void describe('POST /api/BasketItems nested JSON keys', () => {
  void it('does not save or check out a sold-out product hidden under a nested key', async () => {
    const buyer = await authenticate(buyerEmail)
    const items = await catalog()
    const decoy = items.find((item) => item.name === 'OWASP Juice Shop CTF Girlie-Shirt')
    const soldOut = items.find((item) => item.name === 'OWASP Juice Shop Coaster (10pcs)')
    assert.ok(decoy, 'expected an in-stock product with no purchase cap')
    assert.ok(soldOut, 'expected a sold-out product')
    assert.equal(soldOut.limitPerUser, null)
    assert.equal(soldOut.stock, 0)
    assert.ok(decoy.stock >= 1)
    assert.equal(decoy.limitPerUser, null)

    const soldOutBefore = await stockOf(soldOut.id)
    const decoyBefore = await stockOf(decoy.id)
    const hiddenQuantity = 100
    const res = await postRaw(buyer.token, rawBasketItem(buyer.basketId, {
      productId: decoy.id,
      quantity: 1
    }, {
      ProductId: soldOut.id,
      quantity: hiddenQuantity
    }))

    let saved: { ProductId: number, quantity: number, BasketId: number } | null = null
    if (res.status >= 200 && res.status < 300) {
      const row = await BasketItemModel.findByPk(res.body.data.id)
      assert.ok(row, 'accepted response did not persist a basket item')
      saved = { ProductId: row.ProductId, quantity: row.quantity, BasketId: row.BasketId }
      const basketRes = await request(app)
        .get('/rest/basket/' + buyer.basketId)
        .set('Authorization', 'Bearer ' + buyer.token)
      assert.equal(basketRes.status, 200)
      const products = basketRes.body.data?.Products ?? []
      const checkoutRes = await checkout(buyer.token, buyer.basketId)
      const lines = await orderLines(buyer.token)
      const problems = outcomeProblems({
        status: res.status,
        saved,
        basketProducts: products,
        checkoutStatus: checkoutRes.status,
        orderLines: lines,
        authorized: { productId: decoy.id, quantity: 1, basketId: buyer.basketId },
        forbiddenProductId: soldOut.id
      })
      const soldOutAfter = await stockOf(soldOut.id)
      const decoyAfter = await stockOf(decoy.id)
      if (soldOutAfter !== soldOutBefore) {
        problems.push(`sold-out stock changed from ${soldOutBefore} to ${soldOutAfter}`)
      }
      if (decoyAfter !== decoyBefore - 1) {
        problems.push(`checked product stock changed from ${decoyBefore} to ${decoyAfter}, expected a decrease of 1`)
      }
      assert.deepEqual(problems, [])
      return
    }

    assert.ok(res.status >= 400 && res.status < 500, `unexpected status ${res.status}: ${res.text}`)
    const leftover = await BasketItemModel.findAll({ where: { ProductId: soldOut.id, BasketId: buyer.basketId } })
    assert.equal(leftover.length, 0)
    assert.equal(await stockOf(soldOut.id), soldOutBefore)
    assert.equal(await stockOf(decoy.id), decoyBefore)
  })

  void it('does not save or check out a quantity hidden above the purchase cap', async () => {
    const buyer = await authenticate(buyerEmail)
    const items = await catalog()
    const limited = items.find((item) => item.name === 'Melon Bike (Comeback-Product 2018 Edition)')
    assert.ok(limited, 'expected a product with a per-customer cap and stock')
    assert.equal(limited.limitPerUser, 1)
    assert.ok(limited.stock >= 1)
    assert.ok(limited.stock < 100)

    const stockBefore = await stockOf(limited.id)
    const hiddenQuantity = 100
    const res = await postRaw(buyer.token, rawBasketItem(buyer.basketId, {
      productId: limited.id,
      quantity: 1
    }, {
      quantity: hiddenQuantity
    }))

    if (res.status >= 200 && res.status < 300) {
      const row = await BasketItemModel.findByPk(res.body.data.id)
      assert.ok(row, 'accepted response did not persist a basket item')
      const basketRes = await request(app)
        .get('/rest/basket/' + buyer.basketId)
        .set('Authorization', 'Bearer ' + buyer.token)
      assert.equal(basketRes.status, 200)
      const products = basketRes.body.data?.Products ?? []
      const checkoutRes = await checkout(buyer.token, buyer.basketId)
      const lines = await orderLines(buyer.token)
      const problems = outcomeProblems({
        status: res.status,
        saved: { ProductId: row.ProductId, quantity: row.quantity, BasketId: row.BasketId },
        basketProducts: products,
        checkoutStatus: checkoutRes.status,
        orderLines: lines,
        authorized: { productId: limited.id, quantity: 1, basketId: buyer.basketId },
        forbiddenProductId: limited.id
      })
      const stockAfter = await stockOf(limited.id)
      if (stockAfter !== stockBefore - 1) {
        problems.push(`capped product stock changed from ${stockBefore} to ${stockAfter}, expected a decrease of 1`)
      }
      const oversized = lines.filter((line) => Number(line.id) === limited.id && Number(line.quantity) > 1)
      if (oversized.length > 0) {
        problems.push(`order recorded quantity ${oversized.map((line) => line.quantity).join(',')}`)
      }
      assert.deepEqual(problems, [])
      return
    }

    assert.ok(res.status >= 400 && res.status < 500, `unexpected status ${res.status}: ${res.text}`)
    const leftover = await BasketItemModel.findAll({ where: { ProductId: limited.id, BasketId: buyer.basketId } })
    assert.equal(leftover.length, 0)
    assert.equal(await stockOf(limited.id), stockBefore)
  })

  void it('does not attach the item to a basket other than the one authorized by the ownership check', async () => {
    const buyer = await authenticate(buyerEmail)
    const other = await authenticate(otherEmail)
    const items = await catalog()
    const decoy = items.find((item) => item.name === 'OWASP Juice Shop CTF Girlie-Shirt')
    assert.ok(decoy)
    assert.notEqual(buyer.basketId, other.basketId)

    const otherBefore = await BasketItemModel.count({ where: { BasketId: other.basketId } })
    const res = await postRaw(buyer.token, rawBasketItem(buyer.basketId, {
      productId: decoy.id,
      quantity: 1
    }, {
      BasketId: String(other.basketId)
    }))

    const otherAfter = await BasketItemModel.count({ where: { BasketId: other.basketId } })
    assert.equal(otherAfter, otherBefore, 'item was written into a basket the ownership check did not authorize')

    if (res.status >= 200 && res.status < 300) {
      const row = await BasketItemModel.findByPk(res.body.data.id)
      assert.ok(row)
      assert.equal(Number(row.BasketId), buyer.basketId)
      assert.equal(Number(row.ProductId), decoy.id)
      assert.equal(Number(row.quantity), 1)
      await checkout(buyer.token, buyer.basketId)
      return
    }

    assert.ok(res.status >= 400 && res.status < 500, `unexpected status ${res.status}: ${res.text}`)
  })

  void it('still rejects a sold-out product when that product is the one the stock check sees', async () => {
    const buyer = await authenticate(buyerEmail)
    const items = await catalog()
    const soldOut = items.find((item) => item.name === 'OWASP Juice Shop Coaster (10pcs)')
    assert.ok(soldOut)
    const stockBefore = await stockOf(soldOut.id)
    const res = await postRaw(buyer.token, JSON.stringify({
      ProductId: soldOut.id,
      BasketId: String(buyer.basketId),
      quantity: 1
    }))
    assert.equal(res.status, 400)
    const leftover = await BasketItemModel.findAll({ where: { ProductId: soldOut.id, BasketId: buyer.basketId } })
    assert.equal(leftover.length, 0)
    assert.equal(await stockOf(soldOut.id), stockBefore)
  })
})

function outcomeProblems (input: {
  status: number
  saved: { ProductId: number, quantity: number, BasketId: number }
  basketProducts: Array<{ id?: number, BasketItem?: { ProductId?: number, quantity?: number, BasketId?: number } }>
  checkoutStatus: number
  orderLines: Array<{ id?: number, quantity?: number }>
  authorized: { productId: number, quantity: number, basketId: number }
  forbiddenProductId: number
}) {
  const problems: string[] = []
  if (input.status < 200 || input.status >= 300) {
    problems.push(`status ${input.status}`)
  }
  if (Number(input.saved.ProductId) !== input.authorized.productId) {
    problems.push(`saved ProductId ${input.saved.ProductId} but the stock check saw ${input.authorized.productId}`)
  }
  if (Number(input.saved.quantity) !== input.authorized.quantity) {
    problems.push(`saved quantity ${input.saved.quantity} but the stock check saw ${input.authorized.quantity}`)
  }
  if (Number(input.saved.BasketId) !== input.authorized.basketId) {
    problems.push(`saved BasketId ${input.saved.BasketId} but the ownership check saw ${input.authorized.basketId}`)
  }
  const mismatch = input.basketProducts.filter((product) => {
    return Number(product.id) !== input.authorized.productId ||
      Number(product.BasketItem?.quantity) !== input.authorized.quantity ||
      Number(product.BasketItem?.ProductId) !== input.authorized.productId
  })
  if (input.basketProducts.length !== 1 || mismatch.length > 0) {
    problems.push(`basket held ${JSON.stringify(input.basketProducts.map((product) => ({
      id: product.id,
      ProductId: product.BasketItem?.ProductId,
      quantity: product.BasketItem?.quantity
    })))}`)
  }
  if (input.checkoutStatus !== 200) {
    problems.push(`checkout status ${input.checkoutStatus}`)
  }
  const forbiddenLines = input.orderLines.filter((line) => {
    return Number(line.id) === input.forbiddenProductId &&
      (input.forbiddenProductId !== input.authorized.productId || Number(line.quantity) !== input.authorized.quantity)
  })
  if (input.forbiddenProductId !== input.authorized.productId && forbiddenLines.length > 0) {
    problems.push(`order recorded forbidden product ${input.forbiddenProductId}`)
  }
  return problems
}
