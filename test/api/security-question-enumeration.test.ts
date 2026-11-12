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

let app: Express
let questionTexts: string[]

const domain = config.get<string>('application.domain')
const registeredWithAnswer = `jim@${domain}`
const otherRegisteredWithAnswer = `bender@${domain}`
const registeredWithoutAnswer = `testing@${domain}`
const customDomainWithoutAnswer = 'bjoern.kimminich@gmail.com'
const unknownEmail = 'not-registered@invalid.test'

before(async () => {
  const result = await createTestApp()
  app = result.app
  const catalog = await request(app).get('/api/SecurityQuestions')
  assert.equal(catalog.status, 200)
  assert.ok(Array.isArray(catalog.body.data))
  questionTexts = catalog.body.data.map((item: { question: string }) => item.question)
  assert.ok(questionTexts.length > 0)
  assert.ok(questionTexts.every((question) => question.length > 10))
}, { timeout: 60000 })

async function lookup (email: string) {
  return await request(app)
    .get(`/rest/user/security-question?email=${encodeURIComponent(email)}`)
}

void describe('GET /rest/user/security-question email oracle', { concurrency: false }, () => {
  void it('returns the same response whether or not the email is registered', async () => {
    const unknown = await lookup(unknownEmail)
    const candidates = [
      registeredWithAnswer,
      otherRegisteredWithAnswer,
      registeredWithoutAnswer,
      customDomainWithoutAnswer,
      registeredWithAnswer.toUpperCase(),
      ` ${registeredWithAnswer}`
    ]

    for (const email of candidates) {
      const response = await lookup(email)
      assert.deepEqual(
        { status: response.status, body: response.body },
        { status: unknown.status, body: unknown.body },
        email
      )
    }

    const serialized = JSON.stringify(unknown.body)
    for (const question of questionTexts) {
      assert.equal(serialized.includes(question), false)
    }
  })

  void it('rejects a list of address probes from one client', { timeout: 60000 }, async () => {
    const { app: probeApp } = await createTestApp()
    for (let i = 1; i <= 100; i++) {
      await request(probeApp)
        .get(`/rest/user/security-question?email=${encodeURIComponent(`probe-${i}@invalid.test`)}`)
        .set('X-Forwarded-For', `203.0.113.${i}`)
    }

    const blocked = await request(probeApp)
      .get(`/rest/user/security-question?email=${encodeURIComponent(registeredWithAnswer)}`)
      .set('X-Forwarded-For', '203.0.113.200')
    assert.equal(blocked.status, 429)

    const blockedAgain = await request(probeApp)
      .get('/rest/user/security-question?email=another-probe@invalid.test')
      .set('X-Forwarded-For', '198.51.100.8')
    assert.equal(blockedAgain.status, 429)

    const blockedText = `${JSON.stringify(blocked.body)} ${blocked.text}`
    for (const question of questionTexts) {
      assert.equal(blockedText.includes(question), false)
    }
  })
})
