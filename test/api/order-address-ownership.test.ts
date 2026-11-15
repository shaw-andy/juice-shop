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
import { login } from './helpers/auth'
import { AddressModel } from '../../models/address'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'

let app: Express
let productId: number
let buyer: Customer
let owner: Customer
let accountant: Customer
let ownedAddressId: number
let foreignAddressId: number

interface Customer {
  id: number
  email: string
  token: string
  bid: number
}

const password = 'placeholder'
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app

  buyer = await registerCustomer(`address-buyer-${Date.now()}@example.com`)
  owner = await registerCustomer(`address-owner-${Date.now()}@example.com`)
  accountant = await registerCustomer(`address-accountant-${Date.now()}@example.com`)
  await UserModel.update({ role: 'accounting' }, { where: { id: accountant.id } })
  const accountingLogin = await login(app, { email: accountant.email, password })
  accountant = { ...accountant, token: accountingLogin.token, bid: accountingLogin.bid }

  ownedAddressId = await createAddress(buyer.token, '9800000001', 'Buyer Street')
  foreignAddressId = await createAddress(owner.token, '9800000002', 'Owner Street')

  const stocked = (await QuantityModel.findAll()).find((row) => {
    return row.quantity >= 5 && (row.limitPerUser == null || row.limitPerUser >= 1)
  })
  assert.ok(stocked)
  productId = stocked.ProductId
}, { timeout: 60000 })

void describe('checkout delivery address ownership', { concurrency: false }, () => {
  void it('records and returns the signed-in customer address id', async () => {
    const res = await checkout(ownedAddressId)
    assert.equal(res.status, 200)
    const addressId = await trackedAddress(res.body.orderConfirmation)
    assert.equal(String(addressId), String(ownedAddressId))
    const visible = (await allOrders()).filter((order) => order.orderId === res.body.orderConfirmation)
    assert.equal(visible.length, 1)
    assert.equal(String(visible[0].addressId), String(ownedAddressId))
    const history = (await buyerOrders()).filter((order) => order.orderId === res.body.orderConfirmation)
    assert.equal(history.length, 1)
    assert.equal(String(history[0].addressId), String(ownedAddressId))
  })

  void it('accepts checkout when no delivery address is supplied', async () => {
    await addItem()
    const res = await request(app)
      .post('/rest/basket/' + buyer.bid + '/checkout')
      .set(bearer(buyer.token))
    assert.equal(res.status, 200)
    const addressId = await trackedAddress(res.body.orderConfirmation)
    assert.equal(addressId ?? null, null)
  })

  void it('rejects another customer address id before saving the order or changing stock, basket, or invoice files', async () => {
    const denied = await request(app)
      .get('/api/Addresss/' + foreignAddressId)
      .set(bearer(buyer.token))
    assert.equal(denied.status, 400)

    await expectAddressRejected(foreignAddressId, foreignAddressId, 'another customer address')
  })

  void it('rejects an address id taken from a public recycling request', async () => {
    const recycle = await request(app).get('/api/Recycles/1')
    assert.equal(recycle.status, 200)
    const leakedAddressId = recycle.body.data?.[0]?.AddressId
    assert.equal(typeof leakedAddressId, 'number')
    assert.notEqual(leakedAddressId, ownedAddressId)

    const denied = await request(app)
      .get('/api/Addresss/' + leakedAddressId)
      .set(bearer(buyer.token))
    assert.equal(denied.status, 400)

    await expectAddressRejected(leakedAddressId, leakedAddressId, 'recycling address')
  })

  void it('rejects an address id that is not a saved address', async () => {
    const missingAddressId = 2147483000
    await expectAddressRejected(missingAddressId, missingAddressId, 'missing address')
  })

  void it('rejects a string address id the customer does not own', async () => {
    await expectAddressRejected(String(foreignAddressId), foreignAddressId, 'string address')
  })

  void it('does not persist a foreign address id submitted together with an owned address id', async () => {
    await addItem()
    const beforeEffects = await effects()
    const beforeIds = new Set((await allOrders()).map((order) => order.orderId))
    const res = await checkout([ownedAddressId, foreignAddressId], false)
    const created = (await allOrders()).filter((order) => !beforeIds.has(order.orderId))
    const carriesForeignId = created.some((order) => references(order.addressId, foreignAddressId))
    assert.equal(carriesForeignId, false)
    if (res.status < 400) {
      const addressId = await trackedAddress(res.body.orderConfirmation)
      assert.equal(String(addressId), String(ownedAddressId))
      const stored = await AddressModel.findByPk(ownedAddressId)
      assert.equal(stored?.UserId, buyer.id)
    } else {
      assert.ok(res.status >= 400)
      assert.deepEqual(await effects(), beforeEffects)
    }
  })

  void it('rejects a nested address id the customer does not own', async () => {
    await expectAddressRejected({ id: foreignAddressId }, foreignAddressId, 'nested address')
  })

  void it('keeps the authorized address when a later lookup returns a different row', async (t) => {
    let calls = 0
    let authorizedId: number | undefined
    const original = AddressModel.findOne.bind(AddressModel)
    t.mock.method(AddressModel, 'findOne', async (options: unknown) => {
      calls += 1
      if (calls === 1) {
        const row = await original(options as object)
        authorizedId = row?.id
        return row
      }
      return await original({ where: { id: foreignAddressId } })
    })

    const res = await checkout(ownedAddressId)
    assert.equal(res.status, 200)
    const addressId = await trackedAddress(res.body.orderConfirmation)
    assert.equal(String(addressId), String(ownedAddressId))
    assert.notEqual(String(addressId), String(foreignAddressId))
    if (calls > 0) {
      assert.equal(authorizedId, ownedAddressId)
      assert.equal(String(addressId), String(authorizedId))
    }
    const created = (await allOrders()).filter((order) => order.orderId === res.body.orderConfirmation)
    assert.equal(created.some((order) => references(order.addressId, foreignAddressId)), false)
  })
})

async function expectAddressRejected (submitted: unknown, forbidden: number, label: string) {
  await addItem()
  const beforeEffects = await effects()
  const beforeIds = new Set((await allOrders()).map((order) => order.orderId))
  const res = await checkout(submitted, false)
  const created = (await allOrders()).filter((order) => !beforeIds.has(order.orderId))
  const tracked = res.body?.orderConfirmation !== undefined ? await trackedAddress(res.body.orderConfirmation) : undefined
  const history = await buyerOrders()
  assert.deepEqual({
    label,
    rejected: res.status >= 400,
    storedOnCreatedOrder: created.some((order) => references(order.addressId, forbidden)),
    returnedByTracking: references(tracked, forbidden),
    returnedByOrderHistory: history.some((order) => {
      return !beforeIds.has(order.orderId) && references(order.addressId, forbidden)
    }),
    sideEffects: await effects()
  }, {
    label,
    rejected: true,
    storedOnCreatedOrder: false,
    returnedByTracking: false,
    returnedByOrderHistory: false,
    sideEffects: beforeEffects
  })
}

async function checkout (addressId: unknown, withItem = true) {
  if (withItem) await addItem()
  return await request(app)
    .post('/rest/basket/' + buyer.bid + '/checkout')
    .set(bearer(buyer.token))
    .send({
      UserId: owner.id,
      orderDetails: {
        addressId,
        paymentId: 'card'
      }
    })
}

async function addItem () {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(bearer(buyer.token))
    .send({ BasketId: buyer.bid, ProductId: productId, quantity: 1 })
  assert.equal(res.status, 200)
}

async function effects () {
  const quantity = await QuantityModel.findOne({ where: { ProductId: productId } })
  return {
    items: await BasketItemModel.count({ where: { BasketId: buyer.bid } }),
    quantity: quantity?.quantity,
    pdfs: fs.readdirSync(path.resolve('ftp')).filter((name) => /^order_.*\.pdf$/.test(name)).sort()
  }
}

async function trackedAddress (orderId: unknown) {
  assert.equal(typeof orderId, 'string')
  const res = await request(app).get('/rest/track-order/' + encodeURIComponent(String(orderId)))
  assert.equal(res.status, 200)
  return res.body?.data?.[0]?.addressId
}

async function allOrders () {
  const accounting = await request(app)
    .get('/rest/order-history/orders')
    .set(bearer(accountant.token))
  assert.equal(accounting.status, 200)
  return asArray(accounting.body.data)
}

async function buyerOrders () {
  const history = await request(app)
    .get('/rest/order-history')
    .set(bearer(buyer.token))
  assert.equal(history.status, 200)
  return asArray(history.body.data)
}

function references (value: unknown, forbidden: number): boolean {
  return addressValues(value).includes(String(forbidden))
}

function addressValues (value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => addressValues(item))
  if (value != null && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).flatMap((item) => addressValues(item))
  }
  if (value == null || value === '') return []
  return [String(value)]
}

function asArray (value: unknown): any[] {
  return Array.isArray(value) ? value : []
}

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, ...jsonHeader }
}

async function registerCustomer (email: string): Promise<Customer> {
  const registered = await request(app)
    .post('/api/Users/')
    .set(jsonHeader)
    .send({
      email,
      password,
      passwordRepeat: password,
      securityQuestion: null,
      securityAnswer: null
    })
  assert.ok(registered.status === 201 || registered.status === 200)
  const auth = await login(app, { email, password })
  return { id: registered.body.data.id, email, token: auth.token, bid: auth.bid }
}

async function createAddress (token: string, mobileNum: string, streetAddress: string) {
  const res = await request(app)
    .post('/api/Addresss')
    .set(bearer(token))
    .send({
      fullName: 'Delivery Owner',
      mobileNum,
      zipCode: '10001',
      streetAddress,
      city: 'NYC',
      state: 'NY',
      country: 'US',
      UserId: 1
    })
  assert.equal(res.status, 201)
  assert.equal(typeof res.body.data.id, 'number')
  return res.body.data.id as number
}
