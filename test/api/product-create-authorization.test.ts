/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface CatalogRow {
  name: string
  description: string | null
  price: unknown
  deluxePrice: unknown
  image: string | null
  deletedAt: string | Date | null
}

function rowShape (product: CatalogRow) {
  return {
    name: product.name,
    description: product.description,
    price: product.price,
    deluxePrice: product.deluxePrice,
    image: product.image,
    deletedAt: product.deletedAt ?? null
  }
}

function matchingRows (body: { data?: CatalogRow[] }, name: string) {
  const data = Array.isArray(body?.data) ? body.data : []
  return data.filter((product) => product.name === name).map(rowShape)
}

async function registerAndLogin (role: 'customer' | 'deluxe' | 'accounting') {
  const email = `${role}.catalog.probe@example.test`
  const password = 'placeholder-password'
  const body: { email: string, password: string, passwordRepeat: string, role?: string } = {
    email,
    password,
    passwordRepeat: password
  }
  if (role !== 'customer') {
    body.role = role
  }
  const created = await request(app)
    .post('/api/Users/')
    .set(jsonHeader)
    .send(body)
  assert.ok(created.status === 201 || created.status === 200, `register ${role} returned ${created.status}`)
  const { token } = await login(app, { email, password })
  const payload = security.decode(token) as { data?: { role?: string, email?: string } }
  assert.equal(payload?.data?.role, role)
  assert.equal(payload?.data?.email, email)
  return token
}

async function catalogAfterPost (authorization: string | undefined, path: string, name: string) {
  const probe = {
    name,
    description: '',
    price: 7.25,
    deluxePrice: 3.5,
    image: `${name}.jpg`
  }
  const post = request(app).post(path).set(jsonHeader).send(probe)
  if (authorization !== undefined) {
    void post.set('Authorization', authorization)
  }
  const res = await post
  const stored = await ProductModel.findAll({ where: { name }, paranoid: false })
  const stock = stored.length === 0
    ? []
    : await QuantityModel.findAll({ where: { ProductId: stored.map((product) => product.id) } })
  const searchAll = await request(app).get('/rest/products/search?q=')
  const searchName = await request(app).get('/rest/products/search').query({ q: name })
  const list = await request(app).get('/api/Products')
  const listSlash = await request(app).get('/api/Products/')
  let anonymousRead: CatalogRow | null = null
  const createdId = res.body?.data?.id
  if (createdId !== undefined && createdId !== null) {
    const read = await request(app).get(`/api/Products/${createdId}`)
    if (read.status === 200 && read.body?.data) {
      anonymousRead = rowShape(read.body.data)
    }
  }
  const refused = res.status === 401 || res.status === 403
  return {
    actual: {
      refused,
      status: res.status,
      stored: stored.map((product) => rowShape(product)),
      stockRows: stock.map((quantity) => ({ ProductId: quantity.ProductId, quantity: quantity.quantity })),
      searchAll: matchingRows(searchAll.body, name),
      searchName: matchingRows(searchName.body, name),
      productList: matchingRows(list.body, name),
      productListSlash: matchingRows(listSlash.body, name),
      anonymousRead
    },
    expected: {
      refused: true,
      status: refused ? res.status : 403,
      stored: [],
      stockRows: [],
      searchAll: [],
      searchName: [],
      productList: [],
      productListSlash: [],
      anonymousRead: null
    }
  }
}

void describe('product catalog creation', { concurrency: 1 }, () => {
  for (const role of ['customer', 'deluxe', 'accounting'] as const) {
    void it(`does not let a signed-in ${role} insert a product into the catalog`, async () => {
      const token = await registerAndLogin(role)
      const authorization = 'Bearer ' + token
      const created = await catalogAfterPost(authorization, '/api/Products', `CatalogProbe${role}`)
      assert.deepEqual(created.actual, created.expected)
      const slashed = await catalogAfterPost(authorization, '/api/Products/', `CatalogProbe${role}Slash`)
      assert.deepEqual(slashed.actual, slashed.expected)
    })
  }

  void it('does not let an anonymous caller insert a product into the catalog', async () => {
    const created = await catalogAfterPost(undefined, '/api/Products', 'CatalogProbeAnonymous')
    assert.deepEqual(created.actual, created.expected)
  })
})
