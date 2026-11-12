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
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { register, login } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as security from '../../lib/insecurity'

const STOCK = 4
const PLACEHOLDER_PASSWORD = 'placeholder-password'
const WALLET_BALANCE = 100000

let app: Express
const catalog: Array<{ id: number, price: number }> = []
const productPool: Array<{ id: number, price: number }> = []
const usedOrderPrefixes = new Set<string>()

before(async () => {
  const result = await createTestApp()
  app = result.app
  const products = await ProductModel.findAll()
  const quantities = await QuantityModel.findAll()
  for (const product of products) {
    const price = Number(product.price)
    if (!Number.isInteger(price) || price <= 0) continue
    if (!quantities.some(row => row.ProductId === product.id)) continue
    catalog.push({ id: product.id, price })
  }
  assert.ok(catalog.length >= 1, 'need a product with a whole-number price')
  productPool.push(...catalog)
}, { timeout: 60000 })

interface Customer {
  email: string
  userId: number
  bid: number
  authHeader: { Authorization: string, 'content-type': string }
}

interface ClaimedProduct {
  id: number
  price: number
  quantity: number
}

void describe('stock reservation', { concurrency: 1 }, () => {
  void it('two customers cannot each buy the full remaining stock', async () => {
    const product = await claimProduct()
    const customers = [await makeCustomer('add-a'), await makeCustomer('add-b')]
    const tracker = trackOrderFiles(customers.map(customer => customer.email))
    try {
      for (const customer of customers) {
        await addItem(customer, product.id, STOCK)
      }
      const heldBefore = await basketUnitsFor(customers, product.id)
      const checkedOut = []
      for (const customer of customers) checkedOut.push(await checkout(customer))
      await assertExclusiveSale(product, customers, heldBefore, checkedOut, tracker)
    } finally {
      tracker.cleanup()
    }
  })

  void it('two customers cannot both raise a basket line to the full stock and buy it', async () => {
    const product = await claimProduct()
    const customers = [await makeCustomer('put-a'), await makeCustomer('put-b')]
    const tracker = trackOrderFiles(customers.map(customer => customer.email))
    try {
      const itemIds = []
      for (const customer of customers) {
        const added = await addItem(customer, product.id, 1)
        assert.equal(added.status, 200)
        itemIds.push(added.body.data.id as number)
      }
      for (let i = 0; i < customers.length; i++) {
        await updateQuantity(customers[i], itemIds[i], STOCK)
      }
      const heldBefore = await basketUnitsFor(customers, product.id)
      const checkedOut = []
      for (const customer of customers) checkedOut.push(await checkout(customer))
      await assertExclusiveSale(product, customers, heldBefore, checkedOut, tracker)
    } finally {
      tracker.cleanup()
    }
  })

  void it('concurrent adds of the full stock cannot both succeed when both pass the stock read', async () => {
    const product = await claimProduct()
    const customers = [await makeCustomer('race-add-a'), await makeCustomer('race-add-b')]
    const tracker = trackOrderFiles(customers.map(customer => customer.email))
    try {
      await withBothQuantityReads(() => Promise.all(customers.map(async customer => await addItem(customer, product.id, STOCK))))
      const heldBefore = await basketUnitsFor(customers, product.id)
      const checkedOut = await withBothQuantityReads(() => Promise.all(customers.map(async customer => await checkout(customer))))
      await assertExclusiveSale(product, customers, heldBefore, checkedOut, tracker)
    } finally {
      tracker.cleanup()
    }
  })

  void it('concurrent quantity updates cannot reserve more than remains after both pass the stock read', async () => {
    const initial = 4
    const requested = 3
    const product = await claimProduct(initial)
    const customers = [await makeCustomer('race-put-a'), await makeCustomer('race-put-b')]
    const tracker = trackOrderFiles(customers.map(customer => customer.email))
    try {
      const itemIds = []
      for (const customer of customers) {
        const added = await addItem(customer, product.id, 1)
        assert.equal(added.status, 200)
        itemIds.push(added.body.data.id as number)
      }
      await withBothQuantityReads(() => Promise.all(customers.map(async (customer, index) => await updateQuantity(customer, itemIds[index], requested))))
      const heldBefore = await basketUnitsFor(customers, product.id)
      const checkedOut = await withBothQuantityReads(() => Promise.all(customers.map(async customer => await checkout(customer))))
      await assertExclusiveSale(product, customers, heldBefore, checkedOut, tracker)
    } finally {
      tracker.cleanup()
    }
  })

  void it('two concurrent checkouts cannot both commit the same units after both read the stock', async () => {
    const product = await claimProduct()
    const customers = [await makeCustomer('race-pay-a'), await makeCustomer('race-pay-b')]
    const tracker = trackOrderFiles(customers.map(customer => customer.email))
    try {
      for (const customer of customers) {
        await BasketItemModel.create({ ProductId: product.id, BasketId: customer.bid, quantity: STOCK })
      }
      const balances = new Map<number, number>()
      for (const customer of customers) {
        balances.set(customer.userId, await walletBalance(customer))
      }
      const checkedOut = await withBothQuantityReads(() => Promise.all(customers.map(async customer => await checkout(customer))))
      const sales = []
      for (let i = 0; i < customers.length; i++) {
        sales.push(await saleFor(customers[i], product.id, checkedOut[i], balances.get(customers[i].userId) ?? 0, tracker))
      }
      const sold = sales.reduce((sum, sale) => sum + sale.quantity, 0)
      const stock = await stockOf(product.id)
      assert.equal(sold, STOCK, `one checkout must take the ${STOCK} units and the other must be refused, sold ${sold}`)
      assert.equal(stock, 0, `stock after a single sale of ${STOCK} is ${String(stock)}`)
      const winners = sales.filter(sale => sale.quantity > 0)
      assert.equal(winners.length, 1)
      for (const sale of sales) {
        if (sale.quantity > 0) {
          assert.equal(sale.status, 200)
          assert.equal(sale.balanceDelta, walletDelta(product.price, sale.quantity))
          assert.deepEqual(sale.newFiles, ['order_' + sale.orderId + '.pdf'])
          assert.equal(await unitsInBasket(sale.bid, product.id), 0)
        } else {
          assert.notEqual(sale.status, 200)
          assert.equal(sale.balanceDelta, 0, 'refused checkout charged or credited the wallet')
          assert.deepEqual(sale.newFiles, [], 'refused checkout created an order file')
          assert.equal(sale.orderCount, 0, 'refused checkout stored an order')
          assert.equal(await unitsInBasket(sale.bid, product.id), STOCK, 'refused checkout removed the basket line')
        }
      }
    } finally {
      tracker.cleanup()
    }
  })
})

async function claimProduct (quantity = STOCK): Promise<ClaimedProduct> {
  if (productPool.length === 0) productPool.push(...catalog)
  const product = productPool.pop()
  assert.ok(product)
  await BasketItemModel.destroy({ where: { ProductId: product.id } })
  await QuantityModel.update({ quantity, limitPerUser: null }, { where: { ProductId: product.id } })
  assert.equal(await stockOf(product.id), quantity)
  return { id: product.id, price: product.price, quantity }
}

async function makeCustomer (label: string): Promise<Customer> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const email = `${label}-${attempt}-${Date.now()}@example.test`
    const prefix = security.hash(email).slice(0, 4)
    if (usedOrderPrefixes.has(prefix)) continue
    usedOrderPrefixes.add(prefix)
    const registered = await register(app, { email, password: PLACEHOLDER_PASSWORD })
    const userId = registered.body.data.id as number
    const authenticated = await login(app, { email, password: PLACEHOLDER_PASSWORD })
    await fundWallet(userId)
    return {
      email,
      userId,
      bid: authenticated.bid as number,
      authHeader: { Authorization: 'Bearer ' + authenticated.token, 'content-type': 'application/json' }
    }
  }
  throw new Error('could not register a customer')
}

async function fundWallet (userId: number) {
  for (let i = 0; i < 50; i++) {
    const wallet = await WalletModel.findOne({ where: { UserId: userId } })
    if (wallet != null) {
      await wallet.update({ balance: WALLET_BALANCE })
      return
    }
    await new Promise(resolve => { setTimeout(resolve, 20) })
  }
  throw new Error('wallet was not created for the new user')
}

function addItem (customer: Customer, productId: number, quantity: number) {
  return request(app)
    .post('/api/BasketItems')
    .set(customer.authHeader)
    .send({ BasketId: customer.bid, ProductId: productId, quantity })
}

function updateQuantity (customer: Customer, itemId: number, quantity: number) {
  return request(app)
    .put('/api/BasketItems/' + String(itemId))
    .set(customer.authHeader)
    .send({ quantity })
}

function checkout (customer: Customer) {
  return request(app)
    .post('/rest/basket/' + String(customer.bid) + '/checkout')
    .set(customer.authHeader)
    .send({ orderDetails: { paymentId: 'wallet' } })
}

async function walletBalance (customer: Customer) {
  const res = await request(app).get('/rest/wallet/balance').set(customer.authHeader)
  assert.equal(res.status, 200)
  return Number(res.body.data)
}

async function stockOf (productId: number) {
  const row = await QuantityModel.findOne({ where: { ProductId: productId } })
  assert.ok(row)
  return row.quantity
}

async function unitsInBasket (basketId: number, productId: number) {
  const items = await BasketItemModel.findAll({ where: { BasketId: basketId, ProductId: productId } })
  return items.reduce((sum, item) => sum + item.quantity, 0)
}

async function basketUnitsFor (customers: Customer[], productId: number) {
  const held = new Map<number, number>()
  for (const customer of customers) {
    held.set(customer.bid, await unitsInBasket(customer.bid, productId))
  }
  return held
}

function walletDelta (price: number, quantity: number) {
  return -price * quantity + Math.round(price / 10) * quantity
}

function orderFilePrefix (email: string) {
  return 'order_' + security.hash(email).slice(0, 4) + '-'
}

function pdfsFor (email: string) {
  return fs.readdirSync('ftp').filter(name => name.startsWith(orderFilePrefix(email)) && name.endsWith('.pdf'))
}

function trackOrderFiles (emails: string[]) {
  const before = new Map(emails.map(email => [email, new Set(pdfsFor(email))]))
  return {
    created (email: string) {
      return pdfsFor(email).filter(name => !before.get(email)?.has(name)).sort()
    },
    cleanup () {
      for (const email of emails) {
        for (const name of pdfsFor(email)) {
          if (!before.get(email)?.has(name)) fs.unlinkSync(path.join('ftp', name))
        }
      }
    }
  }
}

/**
 * Hold every quantity read until `count` reads have started, then release them together.
 * A fix that reads the stock and later writes it still overlaps on that read.
 * A single conditional update does not need the read and is not delayed.
 */
async function withBothQuantityReads<T> (run: () => Promise<T>): Promise<T> {
  const name = 'stock-read-' + Math.random().toString(16).slice(2)
  let seen = 0
  let open = () => {}
  const opened = new Promise<void>(resolve => { open = resolve })
  QuantityModel.addHook('afterFind', name, async () => {
    seen += 1
    if (seen >= 2) open()
    await Promise.race([
      opened,
      new Promise<void>(resolve => { setTimeout(resolve, 1500) })
    ])
  })
  try {
    return await run()
  } finally {
    open()
    QuantityModel.removeHook('afterFind', name)
  }
}

async function saleFor (customer: Customer, productId: number, response: Response, balanceBefore: number, tracker: ReturnType<typeof trackOrderFiles>) {
  const history = await request(app).get('/rest/order-history').set(customer.authHeader)
  assert.equal(history.status, 200)
  const orders = history.body.data as Array<{ orderId: string, products?: Array<{ id: number, quantity: number }> }>
  assert.ok(Array.isArray(orders))
  const matching: Array<{ orderId: string, quantity: number }> = []
  for (const order of orders) {
    const quantity = (order.products ?? []).filter(line => line.id === productId).reduce((sum, line) => sum + line.quantity, 0)
    if (quantity > 0) matching.push({ orderId: order.orderId, quantity })
  }
  const quantity = matching.reduce((sum, order) => sum + order.quantity, 0)
  return {
    bid: customer.bid,
    status: response.status,
    quantity,
    orderId: matching[0]?.orderId,
    orderCount: orders.length,
    balanceDelta: await walletBalance(customer) - balanceBefore,
    newFiles: tracker.created(customer.email)
  }
}

async function assertExclusiveSale (
  product: ClaimedProduct,
  customers: Customer[],
  heldBefore: Map<number, number>,
  checkouts: Response[],
  tracker: ReturnType<typeof trackOrderFiles>
) {
  const sales = []
  for (let i = 0; i < customers.length; i++) {
    sales.push(await saleFor(customers[i], product.id, checkouts[i], WALLET_BALANCE, tracker))
  }
  let sold = 0
  let held = 0
  for (const sale of sales) {
    sold += sale.quantity
    const remaining = await unitsInBasket(sale.bid, product.id)
    held += remaining
    const reserved = heldBefore.get(sale.bid) ?? 0
    if (sale.quantity > 0) {
      assert.equal(sale.status, 200)
      assert.equal(sale.balanceDelta, walletDelta(product.price, sale.quantity))
      assert.deepEqual(sale.newFiles, ['order_' + sale.orderId + '.pdf'])
    } else if (reserved > 0) {
      assert.notEqual(sale.status, 200, 'checkout of reserved units succeeded without storing the sale')
      assert.equal(sale.balanceDelta, 0, 'refused checkout charged or credited the wallet')
      assert.deepEqual(sale.newFiles, [], 'refused checkout created an order file')
      assert.equal(sale.orderCount, 0, 'refused checkout stored an order')
      assert.equal(remaining, reserved, 'refused checkout removed the basket line')
    } else {
      assert.equal(sale.balanceDelta, 0)
    }
  }
  const stock = await stockOf(product.id)
  const initial = product.quantity
  assert.ok(
    stock >= 0 && sold + held <= initial && (stock === initial - sold || stock === initial - sold - held),
    `sold ${sold}, still held ${held}, stock ${stock}, started at ${initial}`
  )
}
