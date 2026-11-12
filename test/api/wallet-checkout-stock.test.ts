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
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import { ordersCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'

const password = 'placeholder-password'
const ftpDir = path.resolve('ftp')
const orderPdf = /^order_.*\.pdf$/

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('wallet checkout stock', { concurrency: 1 }, () => {
  void it('does not change stock when wallet payment is refused', async () => {
    const buyer = await registerAndLogin('wallet-stock-buyer@example.test')
    const other = await registerAndLogin('wallet-stock-other@example.test')
    const hoodie = await pricedProduct('OWASP Juice Shop Hoodie')
    const patch = await pricedProduct('OWASP Juice Shop-CTF Velcro Patch')
    await QuantityModel.update({ quantity: 4, limitPerUser: null }, { where: { ProductId: hoodie.id } })
    await QuantityModel.update({ quantity: 6, limitPerUser: null }, { where: { ProductId: patch.id } })
    assert.equal((await walletBalance(buyer.header)).data, 0)

    const hoodieLine = await request(app)
      .post('/api/BasketItems')
      .set(buyer.header)
      .send({ BasketId: buyer.bid, ProductId: hoodie.id, quantity: 2 })
    const patchLine = await request(app)
      .post('/api/BasketItems')
      .set(buyer.header)
      .send({ BasketId: buyer.bid, ProductId: patch.id, quantity: -1 })
    assert.equal(hoodieLine.status, 200)
    assert.equal(patchLine.status, 200)

    const ordersBefore = (await ordersCollection.find({})).length
    for (let attempt = 0; attempt < 3; attempt++) {
      const seenPdfs = watchOrderPdfs()
      const checkout = await postWalletCheckout(buyer.bid, buyer.header)
      const createdPdfs = seenPdfs.finish()
      assert.equal(checkout.status, 500)
      assert.equal(checkout.body?.error?.message, 'Insufficient wallet balance.')
      assert.equal(await quantityOf(hoodie.id), 4)
      assert.equal(await quantityOf(patch.id), 6)
      assert.equal((await walletBalance(buyer.header)).data, 0)
      assert.equal(createdPdfs.length, 0)
    }
    assert.equal((await ordersCollection.find({})).length, ordersBefore)

    const basket = await request(app).get(`/rest/basket/${buyer.bid}`).set(buyer.header)
    const lines = basket.body.data.Products as Array<{ BasketItem: { quantity: number, ProductId: number } }>
    const hoodieItem = lines.find((line) => line.BasketItem.ProductId === hoodie.id)
    const patchItem = lines.find((line) => line.BasketItem.ProductId === patch.id)
    assert.equal(hoodieItem?.BasketItem.quantity, 2)
    assert.equal(patchItem?.BasketItem.quantity, -1)

    await WalletModel.update({ balance: 1 }, { where: { UserId: buyer.userId } })
    const partialPdfs = watchOrderPdfs()
    const partial = await postWalletCheckout(buyer.bid, buyer.header)
    const partialCreated = partialPdfs.finish()
    assert.equal(partial.status, 500)
    assert.equal(partial.body?.error?.message, 'Insufficient wallet balance.')
    assert.equal(await quantityOf(hoodie.id), 4)
    assert.equal(await quantityOf(patch.id), 6)
    assert.equal((await walletBalance(buyer.header)).data, 1)
    assert.equal(partialCreated.length, 0)

    const otherAdd = await request(app)
      .post('/api/BasketItems')
      .set(other.header)
      .send({ BasketId: other.bid, ProductId: hoodie.id, quantity: 4 })
    assert.equal(otherAdd.status, 200)
  })

  void it('does not reduce stock when the wallet is emptied after it is read', async () => {
    const buyer = await registerAndLogin('wallet-stock-race@example.test')
    const smoothie = await pricedProduct('Green Smoothie')
    await QuantityModel.update({ quantity: 10, limitPerUser: null }, { where: { ProductId: smoothie.id } })
    const added = await request(app)
      .post('/api/BasketItems')
      .set(buyer.header)
      .send({ BasketId: buyer.bid, ProductId: smoothie.id, quantity: 1 })
    assert.equal(added.status, 200)
    await WalletModel.update({ balance: 500 }, { where: { UserId: buyer.userId } })

    let drainedAfterRead = false
    const hookName = 'drainWalletBalanceAfterRead'
    WalletModel.addHook('afterFind', hookName, async (found: unknown) => {
      const rows = Array.isArray(found) ? found : found == null ? [] : [found]
      for (const row of rows) {
        if ((row as { UserId?: number }).UserId === buyer.userId) {
          drainedAfterRead = true
          await WalletModel.update({ balance: 0 }, { where: { UserId: buyer.userId }, hooks: false })
        }
      }
    })

    try {
      const seenPdfs = watchOrderPdfs()
      const checkout = await postWalletCheckout(buyer.bid, buyer.header)
      const createdPdfs = seenPdfs.finish()
      WalletModel.removeHook('afterFind', hookName)
      const stock = await quantityOf(smoothie.id)
      const balance = Number((await walletBalance(buyer.header)).data)
      assert.ok(balance >= 0)
      if (drainedAfterRead) {
        assert.equal(checkout.status, 500)
        assert.equal(checkout.body?.orderConfirmation, undefined)
        assert.equal(stock, 10)
        assert.equal(createdPdfs.length, 0)
        const basket = await request(app).get(`/rest/basket/${buyer.bid}`).set(buyer.header)
        const lines = basket.body.data.Products as Array<{ BasketItem: { quantity: number, ProductId: number } }>
        assert.equal(lines.find((line) => line.BasketItem.ProductId === smoothie.id)?.BasketItem.quantity, 1)
      } else {
        assert.equal(checkout.status, 200)
        assert.ok(checkout.body.orderConfirmation)
        assert.equal(stock, 9)
        assert.ok(balance < 500)
      }
    } finally {
      WalletModel.removeHook('afterFind', hookName)
    }
  })
})

async function registerAndLogin (email: string) {
  await register(app, { email, password })
  const { token, bid } = await login(app, { email, password })
  const authenticated = security.authenticatedUsers.get(token)
  assert.ok(authenticated)
  return {
    bid,
    userId: authenticated.data.id as number,
    header: { Authorization: `Bearer ${token}`, 'content-type': 'application/json', Accept: 'application/json' }
  }
}

async function pricedProduct (name: string) {
  const product = await ProductModel.findOne({ where: { name } })
  assert.ok(product)
  assert.ok(Number(product.price) > 0)
  return product
}

async function quantityOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row)
  return row.quantity
}

async function walletBalance (header: Record<string, string>) {
  const res = await request(app).get('/rest/wallet/balance').set(header)
  assert.equal(res.status, 200)
  return res.body as { data: number }
}

function postWalletCheckout (basketId: number, header: Record<string, string>) {
  return request(app)
    .post(`/rest/basket/${basketId}/checkout`)
    .set(header)
    .send({ orderDetails: { paymentId: 'wallet' } })
}

function watchOrderPdfs () {
  const before = new Set(fs.readdirSync(ftpDir).filter((name) => orderPdf.test(name)))
  const seen = new Set<string>()
  const watcher = fs.watch(ftpDir, (_event, filename) => {
    if (filename && orderPdf.test(filename)) seen.add(filename)
  })
  return {
    finish () {
      watcher.close()
      const after = fs.readdirSync(ftpDir).filter((name) => orderPdf.test(name) && !before.has(name))
      const created = [...new Set([...after, ...seen].filter((name) => !before.has(name)))]
      for (const name of created) {
        const fullPath = path.join(ftpDir, name)
        if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath)
      }
      return created
    }
  }
}
