/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express

const placeholderPassword = 'placeholder-password'
const productName = 'OrphanStockJuice'
const productDescription = 'Created without a stock row'
const productPrice = 1.5

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('product create without a quantity row', () => {
  void it('does not leave a customer-created product visible in search without a stock row for that product', async () => {
    const email = `quantity-gap-customer@${config.get<string>('application.domain')}`
    await register(app, { email, password: placeholderPassword })
    const { token } = await login(app, { email, password: placeholderPassword })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const payload = security.decode(token)
    assert.equal(payload.data.role, 'customer')

    const beforeProducts = await request(app).get('/api/Products')
    assert.equal(beforeProducts.status, 200)
    const beforeIds = new Set((beforeProducts.body.data as Array<{ id: number }>).map((product) => product.id))

    const created = await request(app)
      .post('/api/Products')
      .set(authHeader)
      .send({
        name: productName,
        description: productDescription,
        price: productPrice
      })

    const afterProducts = await request(app).get('/api/Products')
    const search = await request(app)
      .get('/rest/products/search')
      .query({ q: '' })
      .set(authHeader)
    const quantities = await request(app)
      .get('/api/Quantitys/')
      .set(authHeader)

    assert.equal(afterProducts.status, 200)
    assert.equal(search.status, 200)
    assert.equal(quantities.status, 200)

    const newProducts = (afterProducts.body.data as Array<{ id: number, name: string }>).filter((product) => !beforeIds.has(product.id))
    const newSearchHits = (search.body.data as Array<{ id: number }>).filter((product) => !beforeIds.has(product.id))
    const accepted = created.status >= 200 && created.status < 300

    if (accepted) {
      assert.equal(newProducts.length, 1)
      assert.equal(newSearchHits.length, 1)
      assert.equal(Number(newSearchHits[0].id), Number(newProducts[0].id))
      assert.equal(newProducts[0].name, productName)
      const stock = (quantities.body.data as Array<{ id: number, ProductId: number, quantity: number }>)
        .filter((row) => Number(row.ProductId) === Number(newProducts[0].id))
      assert.equal(stock.length, 1)
      assert.equal(typeof stock[0].id, 'number')
      assert.equal(Number.isFinite(stock[0].quantity), true)
    } else {
      assert.equal(newProducts.length, 0)
      assert.equal(newSearchHits.length, 0)
    }
  })
})
