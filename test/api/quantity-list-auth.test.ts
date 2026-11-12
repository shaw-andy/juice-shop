/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { QuantityModel } from '../../models/quantity'
import * as security from '../../lib/insecurity'

interface InventoryRow {
  ProductId: number
  quantity: number
  limitPerUser: number | null
}

let app: Express
let stored: InventoryRow[]

function collectInventory (value: unknown, found: InventoryRow[]) {
  if (Array.isArray(value)) {
    for (const item of value) collectInventory(item, found)
    return
  }
  if (value === null || typeof value !== 'object') return
  const record = value as Record<string, unknown>
  if ('quantity' in record || 'limitPerUser' in record) {
    found.push({
      ProductId: Number(record.ProductId),
      quantity: Number(record.quantity),
      limitPerUser: record.limitPerUser === null || record.limitPerUser === undefined ? null : Number(record.limitPerUser)
    })
    return
  }
  for (const nested of Object.values(record)) collectInventory(nested, found)
}

function inventoryIn (body: unknown): InventoryRow[] {
  const found: InventoryRow[] = []
  collectInventory(body, found)
  return found.sort((a, b) => a.ProductId - b.ProductId)
}

function mentionsStockFields (body: unknown) {
  const raw = JSON.stringify(body)
  return raw.includes('"quantity"') || raw.includes('"limitPerUser"')
}

function assertInventoryRefused (res: Response) {
  assert.deepEqual(
    {
      status: res.status,
      error: (res.body as { error?: string }).error,
      inventory: inventoryIn(res.body),
      mentionsStockFields: mentionsStockFields(res.body)
    },
    {
      status: 403,
      error: 'Malicious activity detected',
      inventory: [],
      mentionsStockFields: false
    }
  )
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  stored = (await QuantityModel.findAll({ order: [['ProductId', 'ASC']] })).map((row) => ({
    ProductId: row.ProductId,
    quantity: row.quantity,
    limitPerUser: row.limitPerUser
  }))
  assert.ok(stored.length > 1)
  assert.ok(stored.some((row) => row.limitPerUser !== null))
}, { timeout: 60000 })

void describe('GET /api/Quantitys inventory disclosure', () => {
  void it('refuses the full inventory list to an anonymous caller', async () => {
    const res = await request(app).get('/api/Quantitys')
    assertInventoryRefused(res)
  })

  void it('refuses the trailing-slash list used by QuantityService.getAll', async () => {
    const res = await request(app).get('/api/Quantitys/')
    assertInventoryRefused(res)
  })

  void it('refuses a ProductId filter on the list to an anonymous caller', async () => {
    const res = await request(app).get('/api/Quantitys').query({ ProductId: stored[0].ProductId })
    assertInventoryRefused(res)
  })

  void it('refuses a limitPerUser filter on the list to an anonymous caller', async () => {
    const capped = stored.find((row) => row.limitPerUser !== null)
    assert.ok(capped)
    const res = await request(app).get('/api/Quantitys').query({ limitPerUser: capped.limitPerUser })
    assertInventoryRefused(res)
  })

  void it('refuses a quantity sort of the list to an anonymous caller', async () => {
    const res = await request(app).get('/api/Quantitys').query({ sort: 'quantity' })
    assertInventoryRefused(res)
  })

  void it('refuses the list when count is set, instead of returning every row', async () => {
    const res = await request(app).get('/api/Quantitys').query({ count: 1 })
    assertInventoryRefused(res)
  })

  void it('refuses a search query on the list to an anonymous caller', async () => {
    const res = await request(app).get('/api/Quantitys').query({ q: '1' })
    assertInventoryRefused(res)
  })

  void it('refuses the trailing-slash list with a ProductId filter to an anonymous caller', async () => {
    const res = await request(app).get('/api/Quantitys/').query({ ProductId: stored[0].ProductId })
    assertInventoryRefused(res)
  })

  for (const role of [security.roles.customer, security.roles.deluxe, security.roles.admin]) {
    void it(`refuses the inventory list to a ${role} token`, async () => {
      const res = await request(app)
        .get('/api/Quantitys')
        .set('Authorization', 'Bearer ' + security.authorize({ data: { role } }))
      assertInventoryRefused(res)
    })
  }

  void it('refuses a customer token that filters the list by ProductId', async () => {
    const res = await request(app)
      .get('/api/Quantitys')
      .query({ ProductId: stored[0].ProductId })
      .set('Authorization', 'Bearer ' + security.authorize({ data: { role: security.roles.customer } }))
    assertInventoryRefused(res)
  })

  void it('does not return inventory for a non-bearer authorization header', async () => {
    const res = await request(app)
      .get('/api/Quantitys')
      .set('Authorization', 'Token placeholder')
    assertInventoryRefused(res)
  })

  void it('does not return inventory for a malformed bearer token', async () => {
    const res = await request(app)
      .get('/api/Quantitys')
      .set('Authorization', 'Bearer not-a-token')
    assert.deepEqual(
      {
        ok: res.status === 200,
        inventory: inventoryIn(res.body),
        mentionsStockFields: mentionsStockFields(res.body)
      },
      {
        ok: false,
        inventory: [],
        mentionsStockFields: false
      }
    )
  })

  void it('returns every stored quantity row to an accounting token', async () => {
    const res = await request(app)
      .get('/api/Quantitys')
      .set('Authorization', 'Bearer ' + security.authorize({ data: { role: security.roles.accounting } }))
    assert.equal(res.status, 200)
    assert.deepEqual(inventoryIn(res.body), stored)
  })

  void it('treats an accounting token as accounting on the per-id route and still withholds the row', async () => {
    const res = await request(app)
      .get('/api/Quantitys/1')
      .set('Authorization', 'Bearer ' + security.authorize({ data: { role: security.roles.accounting } }))
    assert.equal(res.status, 403)
    assert.notEqual((res.body as { error?: string }).error, 'Malicious activity detected')
    assert.equal(mentionsStockFields(res.body), false)
    assert.deepEqual(inventoryIn(res.body), [])
  })
})
