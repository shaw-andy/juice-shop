/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

const localeDir = path.resolve('data/static/i18n')

function sentenceKey (file: string, startsWith: string): string {
  const catalog = JSON.parse(readFileSync(path.join(localeDir, file), 'utf8')) as Record<string, string>
  const key = Object.keys(catalog).find((entry) => entry.startsWith(startsWith))
  assert.ok(key, `missing locale key starting with ${startsWith} in ${file}`)
  return key
}

const persistedWithoutFrontend = sentenceKey(
  'en.json',
  'Perform a <i>persisted</i> XSS attack with <code>&lt;iframe src="javascript:alert(`xss`)"&gt;</code> without using the frontend'
)
const persistedClientSide = sentenceKey(
  'en.json',
  'Perform a <i>persisted</i> XSS attack with <code>&lt;iframe src="javascript:alert(`xss`)"&gt;</code> bypassing a <i>client-side</i>'
)

const liveJavascriptIframe = /<iframe\b[^>]*\bsrc\s*=\s*["']javascript:/i

let app: Express
let productIds: number[] = []

before(async () => {
  const result = await createTestApp()
  app = result.app
  const res = await request(app).get('/api/Products')
  assert.equal(res.status, 200)
  productIds = res.body.data.map((product: { id: number }) => product.id)
  assert.ok(productIds.length >= 4)
}, { timeout: 60000 })

async function setDescription (productId: number, description: string) {
  return await request(app)
    .put('/api/Products/' + productId)
    .set('content-type', 'application/json')
    .send({ description })
}

async function descriptionsFor (productId: number, language: string) {
  const cookie = 'language=' + language
  const search = await request(app).get('/rest/products/search?q=').set('Cookie', cookie)
  const list = await request(app).get('/api/Products').set('Cookie', cookie)
  const read = await request(app).get('/api/Products/' + productId).set('Cookie', cookie)
  assert.equal(search.status, 200)
  assert.equal(list.status, 200)
  assert.equal(read.status, 200)
  const fromSearch = search.body.data.find((product: { id: number }) => product.id === productId)
  const fromList = list.body.data.find((product: { id: number }) => product.id === productId)
  assert.ok(fromSearch, 'product missing from search')
  assert.ok(fromList, 'product missing from list')
  return {
    search: fromSearch.description as string,
    list: fromList.description as string,
    read: read.body.data.description as string
  }
}

function assertDescriptionsAreNotJavascriptIframes (descriptions: Record<string, string>, language: string) {
  const failures = Object.entries(descriptions)
    .filter(([, description]) => liveJavascriptIframe.test(description))
    .map(([where, description]) => `${where} ${language} returned a javascript iframe: ${description}`)
  assert.equal(failures.length, 0, failures.join('\n'))
}

void describe('translated product descriptions', () => {
  void it('does not turn the persisted XSS sentence into a javascript iframe for Polish shoppers', async () => {
    const productId = productIds[0]
    await setDescription(productId, persistedWithoutFrontend)
    const descriptions = await descriptionsFor(productId, 'pl_PL')
    assertDescriptionsAreNotJavascriptIframes({
      'GET /rest/products/search': descriptions.search,
      'GET /api/Products': descriptions.list,
      'GET /api/Products/:id': descriptions.read
    }, 'pl_PL')
  })

  void it('does not turn the persisted XSS sentence into a javascript iframe for Traditional Chinese shoppers', async () => {
    const productId = productIds[1]
    await setDescription(productId, persistedWithoutFrontend)
    const descriptions = await descriptionsFor(productId, 'zh_TW')
    assertDescriptionsAreNotJavascriptIframes({
      'GET /rest/products/search': descriptions.search,
      'GET /api/Products': descriptions.list,
      'GET /api/Products/:id': descriptions.read
    }, 'zh_TW')
  })

  void it('does not turn the client-side persisted XSS sentence into a javascript iframe for Brazilian Portuguese shoppers', async () => {
    const productId = productIds[2]
    await setDescription(productId, persistedClientSide)
    const descriptions = await descriptionsFor(productId, 'pt_BR')
    assertDescriptionsAreNotJavascriptIframes({
      'GET /rest/products/search': descriptions.search,
      'GET /api/Products': descriptions.list,
      'GET /api/Products/:id': descriptions.read
    }, 'pt_BR')
  })

  void it('keeps the persisted XSS sentence escaped for English shoppers', async () => {
    const productId = productIds[3]
    await setDescription(productId, persistedWithoutFrontend)
    const descriptions = await descriptionsFor(productId, 'en')
    assertDescriptionsAreNotJavascriptIframes({
      'GET /rest/products/search': descriptions.search,
      'GET /api/Products': descriptions.list,
      'GET /api/Products/:id': descriptions.read
    }, 'en')
  })
})
