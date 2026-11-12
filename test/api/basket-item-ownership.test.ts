/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { BasketItemModel } from '../../models/basketitem'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const password = 'placeholder-password'

interface Customer {
  bid: number
  header: { Authorization: string, 'content-type': string }
}

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function customer (email: string): Promise<Customer> {
  await register(app, { email, password })
  const authentication = await login(app, { email, password })
  return {
    bid: authentication.bid,
    header: {
      Authorization: 'Bearer ' + authentication.token,
      'content-type': 'application/json'
    }
  }
}

async function createItem (owner: Customer, productId: number, quantity: number): Promise<number> {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(owner.header)
    .send({ BasketId: owner.bid, ProductId: productId, quantity })
  assert.equal(res.status, 200)
  assert.equal(res.body.data.BasketId, owner.bid)
  assert.equal(res.body.data.quantity, quantity)
  return res.body.data.id
}

async function readItem (id: number) {
  const row = await BasketItemModel.findByPk(id)
  assert.ok(row)
  return row
}

void describe('PUT /api/BasketItems/:id ownership', () => {
  void it('rejects a quantity change to another customer basket item and leaves the row unchanged', async () => {
    const victim = await customer('basket-victim-qty@juice-sh.op')
    const attacker = await customer('basket-attacker-qty@juice-sh.op')
    const itemId = await createItem(victim, 3, 1)

    const res = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(attacker.header)
      .send({ quantity: 2 })

    const stored = await readItem(itemId)
    assert.equal(stored.quantity, 1)
    assert.equal(stored.ProductId, 3)
    assert.equal(stored.BasketId, victim.bid)
    assert.equal(res.status, 401)
  })

  void it('rejects a quantity change of the seeded first basket item', async () => {
    const attacker = await customer('basket-attacker-seed@juice-sh.op')
    const before = await readItem(1)

    const res = await request(app)
      .put('/api/BasketItems/1')
      .set(attacker.header)
      .send({ quantity: before.quantity + 1 })

    const stored = await readItem(1)
    assert.equal(stored.quantity, before.quantity)
    assert.equal(stored.ProductId, before.ProductId)
    assert.equal(stored.BasketId, before.BasketId)
    assert.equal(res.status, 401)
  })

  void it('rejects a zero quantity, which skips the stock check, and leaves the row unchanged', async () => {
    const victim = await customer('basket-victim-zero@juice-sh.op')
    const attacker = await customer('basket-attacker-zero@juice-sh.op')
    const itemId = await createItem(victim, 3, 2)

    const res = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(attacker.header)
      .send({ quantity: 0 })

    const stored = await readItem(itemId)
    assert.equal(stored.quantity, 2)
    assert.equal(stored.BasketId, victim.bid)
    assert.equal(res.status, 401)
  })

  void it('rejects a product change on another customer basket item and leaves the product unchanged', async () => {
    const victim = await customer('basket-victim-product@juice-sh.op')
    const attacker = await customer('basket-attacker-product@juice-sh.op')
    const itemId = await createItem(victim, 3, 1)

    const res = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(attacker.header)
      .send({ ProductId: 1 })

    const stored = await readItem(itemId)
    assert.equal(stored.ProductId, 3)
    assert.equal(stored.quantity, 1)
    assert.equal(stored.BasketId, victim.bid)
    assert.equal(res.status, 401)
  })

  void it('rejects moving another customer basket item into the caller basket', async () => {
    const victim = await customer('basket-victim-move@juice-sh.op')
    const attacker = await customer('basket-attacker-move@juice-sh.op')
    const itemId = await createItem(victim, 3, 1)

    const res = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(attacker.header)
      .send({ BasketId: attacker.bid, quantity: 1 })

    const stored = await readItem(itemId)
    assert.equal(stored.BasketId, victim.bid)
    assert.equal(stored.quantity, 1)
    assert.equal(stored.ProductId, 3)
    assert.equal(res.status, 401)
  })

  void it('does not write the body when the row basket changes after the first read', async () => {
    const victim = await customer('basket-victim-reread@juice-sh.op')
    const attacker = await customer('basket-attacker-reread@juice-sh.op')
    const itemId = await createItem(attacker, 8, 1)
    const hookName = 'basket-item-reread-' + String(itemId)
    let swapped = false

    BasketItemModel.addHook('afterFind', hookName, async (result: unknown) => {
      const row = Array.isArray(result) ? result[0] : result
      if (swapped || row == null || typeof row !== 'object') return
      const id = Number((row as { id?: unknown }).id)
      if (id !== itemId) return
      swapped = true
      await BasketItemModel.update({ BasketId: victim.bid }, {
        where: { id: itemId },
        hooks: false,
        validate: false
      })
    })

    try {
      await request(app)
        .put('/api/BasketItems/' + itemId)
        .set(attacker.header)
        .send({ quantity: 4 })
    } finally {
      BasketItemModel.removeHook('afterFind', hookName)
    }

    const stored = await readItem(itemId)
    assert.equal(swapped, true)
    assert.equal(stored.quantity, 1)
  })

  void it('still lets the owner change quantity on their own basket item', async () => {
    const owner = await customer('basket-owner-qty@juice-sh.op')
    const itemId = await createItem(owner, 3, 1)

    const res = await request(app)
      .put('/api/BasketItems/' + itemId)
      .set(owner.header)
      .send({ quantity: 2 })

    const stored = await readItem(itemId)
    assert.equal(res.status, 200)
    assert.equal(stored.quantity, 2)
    assert.equal(stored.BasketId, owner.bid)
    assert.equal(stored.ProductId, 3)
  })
})

void describe('DELETE /api/BasketItems/:id ownership', () => {
  void it('rejects deleting another customer basket item and leaves the row in place', async () => {
    const victim = await customer('basket-victim-delete@juice-sh.op')
    const attacker = await customer('basket-attacker-delete@juice-sh.op')
    const itemId = await createItem(victim, 6, 1)

    const res = await request(app)
      .delete('/api/BasketItems/' + itemId)
      .set(attacker.header)

    const stored = await readItem(itemId)
    assert.equal(res.status, 401)
    assert.equal(stored.BasketId, victim.bid)
    assert.equal(stored.quantity, 1)
    assert.equal(stored.ProductId, 6)
  })

  void it('still lets the owner delete their own basket item', async () => {
    const owner = await customer('basket-owner-delete@juice-sh.op')
    const itemId = await createItem(owner, 6, 1)

    const res = await request(app)
      .delete('/api/BasketItems/' + itemId)
      .set(owner.header)

    assert.equal(res.status, 200)
    assert.equal(await BasketItemModel.findByPk(itemId), null)
  })
})
