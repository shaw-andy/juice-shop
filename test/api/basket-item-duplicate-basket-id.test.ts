/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const placeholderPassword = 'placeholder-password'

let app: Express
let attackerBid: number
let victimBid: number
let attackerHeader: { Authorization: string, 'content-type': string }
let victimHeader: { Authorization: string, 'content-type': string }
let productIds: number[]

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const attackerEmail = 'basket-dup-attacker@example.test'
    const victimEmail = 'basket-dup-victim@example.test'
    await register(app, { email: attackerEmail, password: placeholderPassword })
    await register(app, { email: victimEmail, password: placeholderPassword })

    const attacker = await login(app, { email: attackerEmail, password: placeholderPassword })
    const victim = await login(app, { email: victimEmail, password: placeholderPassword })
    attackerBid = attacker.bid
    victimBid = victim.bid
    attackerHeader = {
      Authorization: 'Bearer ' + attacker.token,
      'content-type': 'application/json'
    }
    victimHeader = {
      Authorization: 'Bearer ' + victim.token,
      'content-type': 'application/json'
    }

    const quantities = await QuantityModel.findAll()
    productIds = quantities
      .filter((row) => row.quantity >= 1 && (row.limitPerUser == null || row.limitPerUser >= 1))
      .map((row) => row.ProductId)
    assert.ok(productIds.length >= 5, 'need five in-stock products')
    assert.notEqual(attackerBid, victimBid)
  },
  { timeout: 120000 }
)

after(() => {
  BasketItemModel.removeHook('beforeCreate', 'duplicate-basket-id')
})

void describe('POST /api/BasketItems duplicate BasketId', { concurrency: false }, () => {
  void it('does not put the line item in a later basket when the first BasketId matches the caller', async () => {
    await expectAuthorizedBasketOnly(
      `{"ProductId":${productIds[0]},"BasketId":${attackerBid},"quantity":1,"BasketId":${victimBid}}`,
      productIds[0]
    )
  })

  void it('does not put the line item in the last basket when an earlier duplicate matches the caller', async () => {
    await expectAuthorizedBasketOnly(
      `{"ProductId":${productIds[1]},"BasketId":${attackerBid},"quantity":1,"BasketId":${attackerBid},"BasketId":${victimBid}}`,
      productIds[1]
    )
  })

  void it('does not put the line item in a later basket when BasketId values are strings', async () => {
    await expectAuthorizedBasketOnly(
      `{"ProductId":${productIds[2]},"BasketId":"${attackerBid}","quantity":1,"BasketId":"${victimBid}"}`,
      productIds[2]
    )
  })

  void it('does not put the line item in a later basket when the second BasketId key is unicode-escaped', async () => {
    await expectAuthorizedBasketOnly(
      `{"ProductId":${productIds[3]},"BasketId":${attackerBid},"quantity":1,"\\u0042asketId":${victimBid}}`,
      productIds[3]
    )
  })

  void it('does not put the line item in a nested BasketId that the ownership check did not authorize', async () => {
    await expectAuthorizedBasketOnly(
      `{"ProductId":${productIds[4]},"BasketId":${attackerBid},"quantity":1,"extra":{"BasketId":${victimBid}}}`,
      productIds[4]
    )
  })
})

async function expectAuthorizedBasketOnly (rawBody: string, productId: number) {
  const writtenTo: number[] = []
  BasketItemModel.addHook('beforeCreate', 'duplicate-basket-id', (instance: { get (key: string): unknown }) => {
    writtenTo.push(Number(instance.get('BasketId')))
  })
  try {
    const before = await BasketItemModel.count({ where: { BasketId: victimBid, ProductId: productId } })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(attackerHeader)
      .send(rawBody)

    const after = await BasketItemModel.count({ where: { BasketId: victimBid, ProductId: productId } })
    assert.equal(
      after,
      before,
      `victim basket ${victimBid} gained product ${productId}; status ${res.status} body ${JSON.stringify(res.body)}`
    )
    assert.equal(writtenTo.includes(victimBid), false, `a create for basket ${victimBid} happened before the response`)

    if (res.status >= 200 && res.status < 300) {
      assert.equal(Number(res.body?.data?.BasketId), attackerBid)
      const saved = await BasketItemModel.findByPk(res.body.data.id)
      assert.ok(saved)
      assert.equal(Number(saved.BasketId), attackerBid)
    }

    const seen = await request(app)
      .get('/rest/basket/' + String(victimBid))
      .set(victimHeader)
    assert.equal(seen.status, 200)
    const products = seen.body?.data?.Products ?? []
    assert.equal(
      products.some((product: { id: number }) => product.id === productId),
      false,
      `victim basket response included product ${productId}`
    )
  } finally {
    BasketItemModel.removeHook('beforeCreate', 'duplicate-basket-id')
  }
}
