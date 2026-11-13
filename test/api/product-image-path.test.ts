/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

const SHOP_PAGE = 'http://127.0.0.1:3000/#/search'
const PRODUCT_IMAGE_DIR = '/assets/public/images/products/'
const ALLOWLISTED_REDIRECT = 'https://github.com/juice-shop/juice-shop'
const EXTERNAL_TARGET = `https://example.invalid/owned?marker=${ALLOWLISTED_REDIRECT}`
const SAFE_IMAGE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:png|jpe?g|gif|webp|svg)$/
const jsonHeader = { 'content-type': 'application/json' }

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
}, { timeout: 60000 })

function catalogUrl (image: string): URL {
  return new URL('assets/public/images/products/' + image, SHOP_PAGE)
}

async function assertShopperImageStaysInCatalog (image: string) {
  const bound = catalogUrl(image)
  const filename = bound.pathname.startsWith(PRODUCT_IMAGE_DIR)
    ? bound.pathname.slice(PRODUCT_IMAGE_DIR.length)
    : ''
  let req = request(app).get(bound.pathname).redirects(0)
  if (bound.search !== '') {
    req = req.query(bound.search.slice(1))
  }
  const res = await req
  const location = typeof res.headers.location === 'string' ? res.headers.location : ''
  const target = location === '' ? null : new URL(location, SHOP_PAGE)
  assert.equal(
    target?.origin ?? bound.origin,
    bound.origin,
    `stored image ${JSON.stringify(image)} is requested as ${bound.href} and redirects to ${location}`
  )
  assert.equal(bound.pathname, PRODUCT_IMAGE_DIR + filename)
  assert.equal(filename.includes('/'), false)
  assert.equal(bound.search, '')
  assert.equal(bound.hash, '')
  assert.match(filename, SAFE_IMAGE_NAME)
  assert.equal(image, filename)
}

async function productImage (id: number): Promise<string> {
  const res = await request(app).get('/api/Products/' + id)
  assert.equal(res.status, 200)
  return res.body.data.image
}

async function searchedImage (id: number): Promise<string> {
  const res = await request(app).get('/rest/products/search').query({ q: '' })
  assert.equal(res.status, 200)
  const product = res.body.data.find((entry: { id: number }) => entry.id === id)
  assert.ok(product)
  return product.image
}

void describe('product image URLs', () => {
  void it('anonymous product update cannot point a catalog image at the public redirect', async () => {
    const id = 1
    const original = await productImage(id)
    const payload = `../../../../redirect?to=${EXTERNAL_TARGET}`
    const update = await request(app)
      .put('/api/Products/' + id)
      .set(jsonHeader)
      .send({ image: payload })
    const stored = await productImage(id)
    const listed = await searchedImage(id)
    const basket = await request(app)
      .get('/rest/basket/1')
      .set(authHeader)
    const basketProduct = basket.body.data?.Products?.find((entry: { id: number }) => entry.id === id)

    await assertShopperImageStaysInCatalog(stored)
    await assertShopperImageStaysInCatalog(listed)
    assert.equal(basket.status, 200)
    assert.equal(basketProduct.image, original)
    assert.equal(stored, original)
    assert.equal(listed, original)
    assert.equal(update.status, 401)
  })

  void it('authenticated product update rejects an image name that walks out of the products folder', async () => {
    const id = 2
    const original = await productImage(id)
    const payload = `../../../../redirect?to=${EXTERNAL_TARGET}`
    const update = await request(app)
      .put('/api/Products/' + id)
      .set(authHeader)
      .send({ image: payload })
    const stored = await productImage(id)

    await assertShopperImageStaysInCatalog(stored)
    assert.equal(stored, original)
    assert.ok(update.status >= 400 && update.status < 500)
  })

  void it('authenticated product update rejects backslash parent segments in the image name', async () => {
    const id = 3
    const original = await productImage(id)
    const payload = `..\\..\\..\\..\\redirect?to=${EXTERNAL_TARGET}`
    const update = await request(app)
      .put('/api/Products/' + id)
      .set(authHeader)
      .send({ image: payload })
    const stored = await productImage(id)

    await assertShopperImageStaysInCatalog(stored)
    assert.equal(stored, original)
    assert.ok(update.status >= 400 && update.status < 500)
  })

  void it('authenticated product update rejects percent-encoded parent segments in the image name', async () => {
    const id = 4
    const original = await productImage(id)
    const payload = `%2e%2e/%2e%2e/%2e%2e/%2e%2e/redirect?to=${EXTERNAL_TARGET}`
    const update = await request(app)
      .put('/api/Products/' + id)
      .set(authHeader)
      .send({ image: payload })
    const stored = await productImage(id)

    await assertShopperImageStaysInCatalog(stored)
    assert.equal(stored, original)
    assert.ok(update.status >= 400 && update.status < 500)
  })

  void it('authenticated product creation rejects an image name that leaves the products folder', async () => {
    const name = 'zz-image-path-probe'
    const payload = `../../../../redirect?to=${EXTERNAL_TARGET}`
    const create = await request(app)
      .post('/api/Products')
      .set(authHeader)
      .send({
        name,
        description: 'probe',
        price: 1,
        image: payload
      })
    const search = await request(app).get('/rest/products/search').query({ q: name })
    assert.equal(search.status, 200)
    for (const created of search.body.data) {
      await assertShopperImageStaysInCatalog(created.image)
    }
    assert.equal(search.body.data.length, 0)
    assert.ok(create.status >= 400 && create.status < 500)
  })

  void it('authenticated product update can store a single catalog file name', async () => {
    const id = 5
    const original = await productImage(id)
    assert.match(original, SAFE_IMAGE_NAME)
    const update = await request(app)
      .put('/api/Products/' + id)
      .set(authHeader)
      .send({ image: original })
    const stored = await productImage(id)

    assert.equal(update.status, 200)
    await assertShopperImageStaysInCatalog(stored)
    assert.equal(stored, original)
  })
})
