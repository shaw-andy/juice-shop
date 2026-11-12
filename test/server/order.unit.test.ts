/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { placeOrder } from '../../routes/order'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import { DeliveryModel } from '../../models/delivery'
import { sequelize } from '../../models/index'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

void describe('order', () => {
  let req: any
  let res: any
  let next: any

  function basketWith (price: number) {
    return {
      id: 1,
      Products: [{
        BasketItem: { id: 1, ProductId: 1, quantity: 1 },
        price,
        deluxePrice: price,
        name: 'Product 1',
        id: 1
      }],
      update: mock.fn(async () => {}),
      coupon: null
    }
  }

  beforeEach(() => {
    req = { params: { id: '1' }, body: {}, headers: {}, __: mock.fn((s) => s), socket: { remoteAddress: '127.0.0.1' } }
    res = { json: mock.fn(), status: mock.fn(() => res) }
    next = mock.fn()
    // Reset mocks that might have been set globally or on models
    mock.restoreAll()
    mock.method(sequelize, 'transaction', async (work: (t: unknown) => Promise<unknown>) => await work({}))
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
  })

  void it('should call next with error if basket does not exist', async () => {
    mock.method(BasketModel, 'findOne', async () => null)

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p as Error

    assert.match(err.message, /Basket with id=1 does not exist/)
  })

  void it('should call next with error if basket is empty', async () => {
    mock.method(BasketModel, 'findOne', async () => ({ id: 1, Products: [], update: mock.fn(), coupon: null }))

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p as Error

    assert.match(err.message, /Basket with id=1 is empty/)
  })

  void it('should call next with error if QuantityModel.findOne fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    mock.method(BasketItemModel, 'destroy', async () => 1)
    const error = new Error('Quantity error')
    mock.method(QuantityModel, 'findOne', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if quantity decrement fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    mock.method(BasketItemModel, 'destroy', async () => 1)
    const error = new Error('Quantity update error')
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10, decrement: async () => { throw error } }))

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if WalletModel.update fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(100))
    mock.method(BasketItemModel, 'destroy', async () => 1)
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10, decrement: async () => {} }))
    req.body.UserId = 1
    req.body.orderDetails = { paymentId: 'wallet' }
    mock.method(WalletModel, 'findOne', async () => ({ id: 1, balance: 1000 }))
    const error = new Error('Wallet decrement error')
    mock.method(WalletModel, 'update', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if WalletModel.increment fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    mock.method(BasketItemModel, 'destroy', async () => 1)
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10, decrement: async () => {} }))
    req.body.UserId = 1
    const error = new Error('Wallet increment error')
    mock.method(WalletModel, 'increment', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if DeliveryModel.findOne fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    req.body.orderDetails = { deliveryMethodId: 1 }
    const error = new Error('Delivery error')
    mock.method(DeliveryModel, 'findOne', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if ordersCollection.insert fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    mock.method(BasketItemModel, 'destroy', async () => 1)
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10, decrement: async () => {} }))
    const error = new Error('Insert error')
    mock.method(db.ordersCollection, 'insert', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if BasketItemModel.destroy fails', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    const error = new Error('Destroy error')
    mock.method(BasketItemModel, 'destroy', async () => { throw error })
    mock.method(db.ordersCollection, 'insert', async () => {})

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should handle base64 coupon data in calculateApplicableDiscount', async () => {
    const validOn = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()
    const couponData = Buffer.from(`WMNSDY2019-${validOn}`).toString('base64')
    req.body.couponData = couponData

    mock.method(BasketModel, 'findOne', async () => basketWith(10))
    mock.method(db.ordersCollection, 'insert', async () => {})
    mock.method(BasketItemModel, 'destroy', async () => 1)
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10, decrement: async () => {} }))
    mock.method(WalletModel, 'increment', async () => {})

    const p = new Promise((resolve) => {
      res.json = (data: any) => { resolve(data) }
    })

    placeOrder()(req, res, next)
    await p

    assert.ok(true)
  })

  void it('should call next with error if wallet balance is insufficient', async () => {
    mock.method(BasketModel, 'findOne', async () => basketWith(100))
    mock.method(BasketItemModel, 'destroy', async () => 1)
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10, decrement: async () => {} }))
    req.body.UserId = 1
    req.body.orderDetails = { paymentId: 'wallet' }
    mock.method(WalletModel, 'findOne', async () => ({ id: 1, balance: 10 }))
    mock.method(WalletModel, 'update', async () => [0])

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p as Error

    assert.match(err.message, /Insufficient wallet balance/)
  })
})
