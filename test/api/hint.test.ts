/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Hints', () => {
  void it('GET all hints still succeeds after a hint text is cleared to null', async () => {
    const update = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ text: null })
    assert.equal(update.status, 200)

    const list = await request(app).get('/api/Hints')
    assert.equal(list.status, 200)
    assert.ok(Array.isArray(list.body.data))
    assert.ok(list.body.data.length > 1)
    const cleared = list.body.data.find((hint: { id: number }) => hint.id === 1)
    assert.equal(cleared.text, '')
  })
})
