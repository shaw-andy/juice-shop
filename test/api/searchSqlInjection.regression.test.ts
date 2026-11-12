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
import { UserModel } from '../../models/user'
import { CardModel } from '../../models/card'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { ProductModel } from '../../models/product'

let app: Express

const userUnion = '\')) union select id, \'2\', \'3\', email, password, \'6\', \'7\', \'8\', \'9\' from Users--'
const cardUnion = '\')) union select id, fullName, cardNum, expMonth, expYear, \'6\', \'7\', \'8\', \'9\' from Cards--'
const answerUnion = '\')) union select id, \'2\', answer, \'4\', \'5\', \'6\', \'7\', \'8\', \'9\' from SecurityAnswers--'
const schemaUnion = '\')) union select sql, \'2\', \'3\', \'4\', \'5\', \'6\', \'7\', \'8\', \'9\' from sqlite_master--'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function search (q: string): Promise<Response> {
  return await request(app).get('/rest/products/search?q=' + encodeURIComponent(q))
}

function bodyText (res: Response): string {
  return `${res.text}\n${JSON.stringify(res.body ?? {})}`
}

async function assertStoredValuesAbsent (raw: string) {
  const users = await UserModel.findAll({ paranoid: false })
  for (const user of users) {
    const email = String(user.email ?? '')
    const password = String(user.password ?? '')
    if (email.length > 0) {
      assert.equal(raw.includes(email), false, 'response included a user email')
    }
    if (password.length > 0) {
      assert.equal(raw.includes(password), false, 'response included a password hash')
    }
  }
  const cards = await CardModel.findAll()
  for (const card of cards) {
    const cardNum = String(card.cardNum ?? '')
    const fullName = String(card.fullName ?? '')
    if (cardNum.length > 0) {
      assert.equal(raw.includes(cardNum), false, 'response included a card number')
    }
    if (fullName.length > 0) {
      assert.equal(raw.includes(fullName), false, 'response included a cardholder name')
    }
  }
  const answers = await SecurityAnswerModel.findAll()
  for (const answer of answers) {
    const value = String(answer.answer ?? '')
    if (value.length > 0) {
      assert.equal(raw.includes(value), false, 'response included a security answer')
    }
  }
}

async function assertLiteralSearch (q: string) {
  assert.ok(q.length > 0)
  const res = await search(q)
  const raw = bodyText(res)
  assert.equal(res.status, 200)
  assert.equal(raw.includes('SQLITE_ERROR'), false)
  assert.equal(raw.toLowerCase().includes('syntax error'), false)
  assert.equal(raw.includes('CREATE TABLE'), false)
  assert.equal(Array.isArray(res.body?.data) ? res.body.data.length : -1, 0)
  await assertStoredValuesAbsent(raw)
}

void describe('unauthenticated product search query binding', () => {
  void it('returns a normal product for a literal search with no credentials', async () => {
    const res = await search('o-saft')
    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.equal(res.body.data.length, 1)
  })

  void it('treats a quote as data instead of returning the database driver message', async () => {
    const res = await search('\';')
    const raw = bodyText(res)
    assert.equal(res.status, 200)
    assert.equal(raw.includes('SQLITE_ERROR'), false)
    assert.equal(raw.toLowerCase().includes('syntax error'), false)
    assert.equal(res.body.data.length, 0)
  })

  void it('finds a product whose name contains a quote', async () => {
    const marker = 'quote-search-marker'
    await ProductModel.create({
      name: "O'Brien Juice",
      description: marker,
      price: 1.11,
      deluxePrice: 1.11,
      image: 'quote-search.png'
    })
    const res = await search("O'Brien")
    assert.equal(res.status, 200)
    assert.equal(bodyText(res).includes('SQLITE_ERROR'), false)
    assert.equal(res.body.data.some((row: { description?: string }) => row.description === marker), true)
  })

  void it('does not union user emails or password hashes into the search response', async () => {
    assert.ok(userUnion.length <= 200)
    await assertLiteralSearch(userUnion)
  })

  void it('does not union card rows into the search response', async () => {
    assert.ok(cardUnion.length <= 200)
    await assertLiteralSearch(cardUnion)
  })

  void it('does not union security answers into the search response', async () => {
    assert.ok(answerUnion.length <= 200)
    await assertLiteralSearch(answerUnion)
  })

  void it('does not union sqlite_master into the search response', async () => {
    assert.ok(schemaUnion.length <= 200)
    await assertLiteralSearch(schemaUnion)
  })

  void it('still rejects a user union when the breakout is inside the 200 character truncation', async () => {
    const q = userUnion + 'A'.repeat(250)
    assert.ok(q.length > 200)
    assert.ok(q.slice(0, 200).includes('union select'))
    await assertLiteralSearch(q)
  })

  void it('does not return a deleted product when the search term closes the quote and comments out the rest', async () => {
    const deleted = (await ProductModel.findAll({ paranoid: false })).find((product) => product.getDataValue('deletedAt') != null)
    assert.ok(deleted)
    const res = await search(`${deleted.name}'))--`)
    const names = Array.isArray(res.body?.data) ? res.body.data.map((row: { name?: string }) => row.name) : []
    assert.equal(res.status, 200)
    assert.equal(bodyText(res).includes('SQLITE_ERROR'), false)
    assert.equal(names.includes(deleted.name), false)
    assert.equal(names.length, 0)
  })

  void it('does not return every product when the search term closes the quote and adds OR 1=1', async () => {
    const deleted = (await ProductModel.findAll({ paranoid: false })).find((product) => product.getDataValue('deletedAt') != null)
    assert.ok(deleted)
    const res = await search('\')) OR 1=1--')
    const names = Array.isArray(res.body?.data) ? res.body.data.map((row: { name?: string }) => row.name) : []
    assert.equal(res.status, 200)
    assert.equal(names.includes(deleted.name), false)
    assert.equal(names.length, 0)
    await assertStoredValuesAbsent(bodyText(res))
  })
})
