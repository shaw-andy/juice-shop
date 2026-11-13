/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import yaml from 'js-yaml'
import i18n from 'i18n'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const localeDir = path.resolve('i18n')
const localeSourceDir = path.resolve('data/static/i18n')

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let ftpBefore: Set<string>

before(async () => {
  const result = await createTestApp()
  app = result.app
  const seedUsers = yaml.load(fs.readFileSync(path.resolve('data/static/users.yml'), 'utf8')) as Array<{ email: string, password: string, key: string }>
  const customer = seedUsers.find((user) => user.key === 'jim')
  if (customer == null) {
    throw new Error('seed user jim is missing')
  }
  const domain = config.get<string>('application.domain')
  const { token } = await login(app, { email: `${customer.email}@${domain}`, password: customer.password })
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  ftpBefore = new Set(fs.readdirSync(path.resolve('ftp')))
}, { timeout: 60000 })

after(() => {
  for (const name of fs.readdirSync(localeSourceDir)) {
    if (name.endsWith('.json')) {
      fs.copyFileSync(path.join(localeSourceDir, name), path.join(localeDir, name))
    }
  }
  for (const name of fs.readdirSync(path.resolve('ftp'))) {
    if (!ftpBefore.has(name) && name.startsWith('order_') && name.endsWith('.pdf')) {
      fs.unlinkSync(path.resolve('ftp', name))
    }
  }
})

interface CatalogSnapshot {
  keys: Set<string>
  sha256: string
}

function localePath (locale: string): string {
  return path.join(localeDir, `${locale}.json`)
}

function snapshot (locale: string): CatalogSnapshot {
  const catalog = i18n.getCatalog(locale) as Record<string, unknown>
  return {
    keys: new Set(Object.keys(catalog)),
    sha256: crypto.createHash('sha256').update(fs.readFileSync(localePath(locale))).digest('hex')
  }
}

function assertCatalogUnchanged (before: CatalogSnapshot, locale: string, phrases: string[]) {
  const after = snapshot(locale)
  const added = [...after.keys].filter((key) => !before.keys.has(key))
  const fileRewritten = after.sha256 !== before.sha256
  assert.equal(
    added.length,
    0,
    `${locale} translation catalog gained ${added.length} key(s): ${JSON.stringify(added.slice(0, 3))}; locale file rewritten: ${fileRewritten}`
  )
  assert.equal(fileRewritten, false, `${locale} locale file was rewritten`)
  for (const phrase of phrases) {
    assert.equal(after.keys.has(phrase), false)
    const onDisk = JSON.parse(fs.readFileSync(localePath(locale), 'utf8')) as Record<string, unknown>
    assert.equal(Object.hasOwn(onDisk, phrase), false)
  }
}

function phrase (label: string): string {
  return `product-catalog-${label}-${crypto.randomBytes(8).toString('hex')}`
}

async function updateProduct (id: number, body: { name?: string, description?: string }) {
  const res = await request(app)
    .put('/api/Products/' + id)
    .set(jsonHeader)
    .send(body)
  assert.equal(res.status, 200)
  return res
}

void describe('product text is not stored in the translation catalog', { concurrency: 1 }, () => {
  void it('anonymous description updates stay out of the catalog until and after a public product list', async () => {
    const first = phrase('list-description-a')
    const second = phrase('list-description-b')
    const before = snapshot('en')

    await updateProduct(1, { description: first })
    assertCatalogUnchanged(before, 'en', [first])

    const listed = await request(app).get('/api/Products')
    assert.equal(listed.status, 200)
    const listedProduct = listed.body.data.find((product: { id: number }) => product.id === 1)
    assert.equal(listedProduct.description, first)
    assertCatalogUnchanged(before, 'en', [first])

    await updateProduct(1, { description: second })
    const listedAgain = await request(app).get('/api/Products')
    assert.equal(listedAgain.status, 200)
    assertCatalogUnchanged(before, 'en', [first, second])
  })

  void it('a public product read does not record the stored description', async () => {
    const description = phrase('read-description')
    const before = snapshot('en')
    await updateProduct(2, { description })

    const res = await request(app).get('/api/Products/2')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.description, description)
    assertCatalogUnchanged(before, 'en', [description])
  })

  void it('a public product search does not record the stored description', async () => {
    const description = phrase('search-description')
    const before = snapshot('en')
    await updateProduct(3, { description })

    const res = await request(app).get('/rest/products/search').query({ q: description })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].description, description)
    assertCatalogUnchanged(before, 'en', [description])
  })

  void it('a public product list does not record the stored name', async () => {
    const name = phrase('list-name')
    const before = snapshot('en')
    await updateProduct(4, { name })

    const listed = await request(app).get('/api/Products')
    assert.equal(listed.status, 200)
    const listedProduct = listed.body.data.find((product: { id: number }) => product.id === 4)
    assert.equal(listedProduct.name, name)
    assertCatalogUnchanged(before, 'en', [name])
  })

  void it('a public product read does not record the stored name', async () => {
    const name = phrase('read-name')
    const before = snapshot('en')
    await updateProduct(5, { name })

    const res = await request(app).get('/api/Products/5')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.name, name)
    assertCatalogUnchanged(before, 'en', [name])
  })

  void it('a public product search does not record the stored name', async () => {
    const name = phrase('search-name')
    const before = snapshot('en')
    await updateProduct(6, { name })

    const res = await request(app).get('/rest/products/search').query({ q: name })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].name, name)
    assertCatalogUnchanged(before, 'en', [name])
  })

  void it('an authenticated basket read does not record the stored product name', async () => {
    const name = phrase('basket-name')
    const before = snapshot('en')
    await updateProduct(1, { name })

    const res = await request(app).get('/rest/basket/1').set(authHeader)
    assert.equal(res.status, 200)
    const product = res.body.data.Products.find((item: { id: number }) => item.id === 1)
    assert.equal(product.name, name)
    assertCatalogUnchanged(before, 'en', [name])
  })

  void it('checkout does not record the stored product name', async () => {
    const name = phrase('checkout-name')
    const before = snapshot('en')
    await updateProduct(3, { name })

    const res = await request(app).post('/rest/basket/5/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation)
    assertCatalogUnchanged(before, 'en', [name])
  })

  void it('a non-default locale does not gain the description either', async () => {
    const description = phrase('german-description')
    const before = snapshot('de_DE')
    const englishBefore = snapshot('en')
    await updateProduct(8, { description })

    const res = await request(app)
      .get('/api/Products')
      .set('Cookie', 'language=de_DE')
    assert.equal(res.status, 200)
    const product = res.body.data.find((item: { id: number }) => item.id === 8)
    assert.equal(product.description, description)
    assertCatalogUnchanged(before, 'de_DE', [description])
    assertCatalogUnchanged(englishBefore, 'en', [description])
  })

  void it('repeated unique descriptions do not grow the catalog or the locale file', async () => {
    const before = snapshot('en')
    const descriptions = [phrase('grow-a'), phrase('grow-b'), phrase('grow-c')]
    for (const description of descriptions) {
      await updateProduct(9, { description })
      const res = await request(app).get('/api/Products/9')
      assert.equal(res.status, 200)
      assert.equal(res.body.data.description, description)
    }
    assertCatalogUnchanged(before, 'en', descriptions)
  })

  void it('a description longer than the declared varchar length is not added to the catalog', async () => {
    const description = `${'long-description-'.repeat(40)}${phrase('long')}`
    assert.ok(description.length > 255)
    const before = snapshot('en')
    const updated = await updateProduct(7, { description })
    assert.equal(updated.body.data.description, description)

    const res = await request(app).get('/api/Products/7')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.description, description)
    assertCatalogUnchanged(before, 'en', [description])
  })
})
