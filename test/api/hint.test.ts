/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { HintModel } from '../../models/hint'
import * as security from '../../lib/insecurity'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const replacementText = 'not-a-hint'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function isUnlocked (value: unknown): boolean {
  return value === true || value === 1
}

function exposesText (value: unknown, text: string): boolean {
  if (typeof value === 'string') {
    return text.length > 0 && value.includes(text)
  }
  if (Array.isArray(value)) {
    return value.some(item => exposesText(item, text))
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value).some(item => exposesText(item, text))
  }
  return false
}

async function lockedHints () {
  const hints = await HintModel.findAll()
  return hints.filter(hint => !isUnlocked(hint.unlocked) && hint.text.length > 0)
}

async function fullyLockedGroup () {
  const hints = await HintModel.findAll()
  const groups = new Map<number, typeof hints>()
  for (const hint of hints) {
    const list = groups.get(hint.ChallengeId) ?? []
    list.push(hint)
    groups.set(hint.ChallengeId, list)
  }
  for (const list of groups.values()) {
    const sorted = [...list].sort((a, b) => a.order - b.order)
    if (sorted.length >= 2 && sorted.every(hint => !isUnlocked(hint.unlocked) && hint.text.length > 0)) {
      return sorted
    }
  }
  throw new Error('expected a challenge with at least two locked hints')
}

async function assertRowHidden (body: { data?: Array<Record<string, unknown>> }, hint: { id: number, text: string, order: number, ChallengeId: number }) {
  assert.ok(Array.isArray(body.data))
  const row = body.data.find(item => item.id === hint.id)
  assert.ok(row)
  assert.equal(row.ChallengeId, hint.ChallengeId)
  assert.equal(row.order, hint.order)
  assert.equal(isUnlocked(row.unlocked), false)
  assert.equal(exposesText(row, hint.text), false)
}

async function assertStored (hint: { id: number, text: string, order: number, ChallengeId: number, unlocked: boolean }) {
  const stored = await HintModel.findByPk(hint.id)
  assert.ok(stored)
  assert.equal(isUnlocked(stored.unlocked), isUnlocked(hint.unlocked))
  assert.equal(stored.order, hint.order)
  assert.equal(stored.ChallengeId, hint.ChallengeId)
  assert.equal(stored.text === hint.text, true)
}

void describe('/api/Hints', { concurrency: false }, () => {
  void it('omits locked hint text from the anonymous list', async () => {
    const hints = await lockedHints()
    assert.ok(hints.length > 0)

    for (const path of ['/api/Hints/', '/api/Hints']) {
      const res = await request(app).get(path)
      assert.equal(res.status, 200)
      for (const hint of hints) {
        await assertRowHidden(res.body, hint)
      }
    }
  })

  void it('omits locked hint text when the list is filtered to locked rows', async () => {
    const hints = await lockedHints()
    assert.ok(hints.length > 0)
    const res = await request(app).get('/api/Hints').query({ unlocked: false })
    assert.equal(res.status, 200)
    for (const hint of hints) {
      await assertRowHidden(res.body, hint)
    }
  })

  void it('omits locked hint text when the list is sorted', async () => {
    const hints = await lockedHints()
    assert.ok(hints.length > 0)
    const res = await request(app).get('/api/Hints').query({ sort: 'order' })
    assert.equal(res.status, 200)
    for (const hint of hints) {
      await assertRowHidden(res.body, hint)
    }
  })

  void it('omits locked hint text when the list is searched', async () => {
    const hint = (await lockedHints())[0]
    assert.ok(hint)
    const res = await request(app).get('/api/Hints').query({ q: hint.text })
    assert.equal(res.status, 200)
    await assertRowHidden(res.body, hint)
  })

  void it('rejects an anonymous JSON update and leaves the hint locked for a later reader', async () => {
    const hint = (await fullyLockedGroup())[0]
    const res = await request(app)
      .put('/api/Hints/' + hint.id)
      .set(jsonHeader)
      .send({ unlocked: true, text: replacementText, order: hint.order + 1 })
    const again = await request(app).get('/api/Hints/')
    assert.equal(again.status, 200)
    const row = again.body.data.find((item: { id: number }) => item.id === hint.id)
    assert.ok(row)
    assert.equal(isUnlocked(row.unlocked), false)
    assert.equal(exposesText(row, hint.text), false)
    assert.equal(exposesText(again.body, replacementText), false)
    await assertStored(hint)
    assert.equal(res.status, 401)
  })

  void it('rejects an anonymous form update and leaves every column unchanged', async () => {
    const hint = (await fullyLockedGroup())[0]
    const res = await request(app)
      .put('/api/Hints/' + hint.id)
      .type('form')
      .send({ unlocked: 'true', text: replacementText, order: String(hint.order + 1) })
    await assertStored(hint)
    assert.equal(res.status, 401)
  })

  void it('rejects a logged-in update of a later hint even when the body and query name the next hint', async () => {
    const [nextHint, laterHint] = await fullyLockedGroup()
    const res = await request(app)
      .put('/api/Hints/' + laterHint.id)
      .query({ id: String(nextHint.id) })
      .set(authHeader)
      .send({ id: nextHint.id, unlocked: true, text: replacementText })
    await assertStored(laterHint)
    await assertStored(nextHint)
    assert.ok(res.status === 400 || res.status === 403)
  })

  void it('lets a logged-in user unlock only the next hint named by the path', async () => {
    const [nextHint, laterHint] = await fullyLockedGroup()
    const res = await request(app)
      .put('/api/Hints/' + nextHint.id)
      .query({ id: String(laterHint.id) })
      .set(authHeader)
      .send({ id: laterHint.id, unlocked: true })
    assert.equal(res.status, 200)
    const storedNext = await HintModel.findByPk(nextHint.id)
    const storedLater = await HintModel.findByPk(laterHint.id)
    assert.ok(storedNext)
    assert.ok(storedLater)
    assert.equal(isUnlocked(storedNext.unlocked), true)
    assert.equal(storedNext.text === nextHint.text, true)
    assert.equal(isUnlocked(storedLater.unlocked), false)
    assert.equal(storedLater.text === laterHint.text, true)
    assert.equal(storedLater.order, laterHint.order)
    assert.equal(storedLater.ChallengeId, laterHint.ChallengeId)
  })

  void it('does not create, read, or delete one hint without authorization', async () => {
    const before = await HintModel.findAll()
    const hint = before[0]
    const created = await request(app)
      .post('/api/Hints')
      .set(jsonHeader)
      .send({ ChallengeId: hint.ChallengeId, text: replacementText, order: 1, unlocked: true })
    const read = await request(app).get('/api/Hints/' + hint.id)
    const removed = await request(app).delete('/api/Hints/' + hint.id).set(authHeader)
    const patched = await request(app)
      .patch('/api/Hints/' + hint.id)
      .set(jsonHeader)
      .send({ unlocked: true, text: replacementText })
    const after = await HintModel.findByPk(hint.id)
    const count = await HintModel.count()

    assert.equal(created.status, 401)
    assert.equal(exposesText(created.body, hint.text), false)
    assert.equal(read.status, 401)
    assert.equal(exposesText(read.body, hint.text), false)
    assert.equal(removed.status, 401)
    assert.equal(count, before.length)
    assert.ok(after)
    assert.equal(after.text === hint.text, true)
    assert.equal(isUnlocked(after.unlocked), isUnlocked(hint.unlocked))
    assert.equal(patched.body?.data?.text === replacementText, false)
  })
})
