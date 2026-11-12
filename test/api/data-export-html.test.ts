/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { ProductModel } from '../../models/product'

const markup = "<img src=x onerror=document.documentElement.setAttribute('data-x',localStorage.token)>"
const email = 'export-html-spec@example.test'
const password = 'placeholder-password'
const enPath = path.resolve('i18n/en.json')
const enSource = path.resolve('data/static/i18n/en.json')

let app: Express
let token = ''
let basketId = 0
let productId = 0
let originalName = ''
const ftpBefore = new Set<string>()

before(async () => {
  for (const name of fs.readdirSync('ftp')) ftpBefore.add(name)
  const result = await createTestApp()
  app = result.app
  await register(app, { email, password })
  const auth = await login(app, { email, password })
  token = auth.token
  basketId = auth.bid
  const listed = await request(app).get('/api/Products')
  productId = listed.body.data[0].id
  const product = await ProductModel.findByPk(productId)
  originalName = String(product?.get('name'))
}, { timeout: 60000 })

after(() => {
  if (fs.existsSync(enSource)) fs.copyFileSync(enSource, enPath)
  for (const name of fs.readdirSync('ftp')) {
    if (!ftpBefore.has(name) && name.startsWith('order_')) fs.unlinkSync(path.join('ftp', name))
  }
})

async function restoreProductName () {
  const product = await ProductModel.findByPk(productId)
  if (product != null && product.get('name') !== originalName) {
    product.set('name', originalName)
    await product.save()
  }
}

void describe('data export HTML', () => {
  void it('does not persist an HTML event handler submitted as a product name', async () => {
    try {
      await request(app)
        .put('/api/Products/' + productId)
        .set('content-type', 'application/json')
        .send({ name: markup })

      const stored = await ProductModel.findByPk(productId)
      const storedName = String(stored?.get('name'))
      const anyRaw = await ProductModel.findAll()
      assert.equal(storedName.includes('<'), false)
      assert.equal(anyRaw.some((product) => String(product.get('name')).includes(markup)), false)
    } finally {
      await restoreProductName()
    }
  })

  void it('does not place a product-name event handler into the data export a customer downloads', async () => {
    try {
      await request(app)
        .put('/api/Products/' + productId)
        .set('content-type', 'application/json')
        .send({ name: markup })

      const basket = await request(app)
        .post('/api/BasketItems')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
        .send({ BasketId: basketId, ProductId: productId, quantity: 1 })
      assert.equal(basket.status, 200)

      const checkout = await request(app)
        .post('/rest/basket/' + basketId + '/checkout')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      assert.equal(checkout.status, 200)

      const exported = await request(app)
        .post('/rest/user/data-export')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
        .send({ format: '1' })
      assert.equal(exported.status, 200)
      const userData = String(exported.body.userData)
      assert.equal(userData.includes(markup), false)
      assert.equal(userData.includes('<img'), false)
    } finally {
      await restoreProductName()
      if (fs.existsSync(enSource)) fs.copyFileSync(enSource, enPath)
    }
  })

  void it('does not place a forged review event handler into the data export', async () => {
    const reviewEmail = 'export-html-review@example.test'
    await register(app, { email: reviewEmail, password })
    const reviewUser = await login(app, { email: reviewEmail, password })

    await request(app)
      .put('/rest/products/' + productId + '/reviews')
      .set('content-type', 'application/json')
      .send({ message: markup, author: reviewEmail })

    const exported = await request(app)
      .post('/rest/user/data-export')
      .set({ Authorization: 'Bearer ' + reviewUser.token, 'content-type': 'application/json' })
      .send({ format: '1' })
    assert.equal(exported.status, 200)
    const userData = String(exported.body.userData)
    assert.equal(userData.includes(markup), false)
    assert.equal(userData.includes('<img'), false)
  })
})
