/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'

const password = 'placeholder'

let app: Express

interface BasketLine {
  id: number
  BasketId: number
  ProductId: number
  quantity: number
}

interface Customer {
  bid: number
  header: { Authorization: string, 'content-type': string }
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('basket line ownership', { concurrency: false }, () => {
  void it('refuses to delete or retarget another customer basket line', async () => {
    const caller = await customer('cart-caller@example.test')
    const owner = await customer('cart-owner@example.test')
    const callerLine = await addLine(caller, 3, 1)
    const ownerLine = await addLine(owner, 3, 1)
    const listed = await listLines(caller)
    const foreign = listed.find((line) => line.id === ownerLine.id)
    assert.ok(foreign)
    assert.equal(foreign.BasketId, owner.bid)
    assert.notEqual(foreign.BasketId, caller.bid)

    const seeded = listed.find((line) => line.BasketId !== caller.bid && line.BasketId !== owner.bid)
    assert.ok(seeded)

    const deleteByCallerLine = await deleteLine(caller, ownerLine.id, caller.bid, { id: callerLine.id, BasketId: caller.bid })
    await assertUntouched(ownerLine)
    await assertUntouched(callerLine)
    assertRefused(deleteByCallerLine)

    const deleteByOwnerBasket = await deleteLine(caller, ownerLine.id, caller.bid, { BasketId: owner.bid, id: ownerLine.id })
    await assertUntouched(ownerLine)
    await assertUntouched(callerLine)
    assertRefused(deleteByOwnerBasket)

    const deleteSeeded = await deleteLine(caller, seeded.id, caller.bid)
    await assertUntouched(seeded)
    await assertUntouched(callerLine)
    assertRefused(deleteSeeded)

    const retarget = await request(app)
      .put('/api/BasketItems/' + ownerLine.id)
      .set(caller.header)
      .send({ quantity: ownerLine.quantity + 1, id: callerLine.id })
    await assertUntouched(ownerLine)
    await assertUntouched(callerLine)
    assertRefused(retarget.status)

    const ownUpdate = await request(app)
      .put('/api/BasketItems/' + callerLine.id)
      .set(caller.header)
      .send({ quantity: callerLine.quantity + 1 })
    assert.equal(ownUpdate.status, 200)
    assert.equal(ownUpdate.body.data.quantity, callerLine.quantity + 1)
    assert.equal(ownUpdate.body.data.BasketId, caller.bid)
    await assertUntouched(ownerLine)

    const ownDelete = await request(app)
      .delete('/api/BasketItems/' + callerLine.id)
      .set(caller.header)
    assert.equal(ownDelete.status, 200)
    assert.equal(await BasketItemModel.findByPk(callerLine.id), null)
    await assertUntouched(ownerLine)
    await assertUntouched(seeded)
  })
})

async function customer (email: string): Promise<Customer> {
  await register(app, { email, password })
  const authentication = await login(app, { email, password })
  return {
    bid: authentication.bid,
    header: { Authorization: 'Bearer ' + authentication.token, 'content-type': 'application/json' }
  }
}

async function addLine (who: Customer, productId: number, quantity: number): Promise<BasketLine> {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(who.header)
    .send({ BasketId: who.bid, ProductId: productId, quantity })
  assert.equal(res.status, 200)
  return {
    id: res.body.data.id,
    BasketId: res.body.data.BasketId,
    ProductId: res.body.data.ProductId,
    quantity: res.body.data.quantity
  }
}

async function listLines (who: Customer): Promise<BasketLine[]> {
  const res = await request(app)
    .get('/api/BasketItems')
    .set(who.header)
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

function assertRefused (status: number) {
  assert.ok(status >= 400)
}

async function deleteLine (who: Customer, lineId: number, callerBasketId: number, body?: Record<string, number>) {
  let status = 0
  await duringLaterLookups(lineId, callerBasketId, async () => {
    const res = await request(app)
      .delete('/api/BasketItems/' + lineId)
      .set(who.header)
      .send(body)
    status = res.status
  })
  return status
}

async function assertUntouched (snapshot: BasketLine) {
  const row = await BasketItemModel.findByPk(snapshot.id)
  assert.ok(row, 'line ' + snapshot.id + ' was removed')
  assert.equal(row.id, snapshot.id)
  assert.equal(row.BasketId, snapshot.BasketId)
  assert.equal(row.ProductId, snapshot.ProductId)
  assert.equal(row.quantity, snapshot.quantity)
}

// A lookup after the first one reports the caller's basket for this line id.
// Refusal has to use the line that the write will change, which still belongs to the other customer.
async function duringLaterLookups (lineId: number, callerBasketId: number, action: () => Promise<void>) {
  const originalFindOne = BasketItemModel.findOne
  const originalFindByPk = BasketItemModel.findByPk
  let reads = 0
  const note = (row: { id?: number, setDataValue?: (key: string, value: number) => void, changed?: (key: string, value: boolean) => void } | null) => {
    if (row && Number(row.id) === lineId) {
      reads += 1
      if (reads > 1 && row.setDataValue && row.changed) {
        row.setDataValue('BasketId', callerBasketId)
        row.changed('BasketId', false)
      }
    }
    return row
  }
  BasketItemModel.findOne = (async (...args: Parameters<typeof originalFindOne>) => {
    return note(await originalFindOne.apply(BasketItemModel, args))
  }) as typeof BasketItemModel.findOne
  BasketItemModel.findByPk = (async (...args: Parameters<typeof originalFindByPk>) => {
    return note(await originalFindByPk.apply(BasketItemModel, args))
  }) as typeof BasketItemModel.findByPk
  try {
    await action()
  } finally {
    BasketItemModel.findOne = originalFindOne
    BasketItemModel.findByPk = originalFindByPk
  }
}
