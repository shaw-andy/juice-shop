/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'

let app: Express

const uploadLimitBytes = 200000
const responseBudgetMs = 1000

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/file-upload passwd detection', { concurrency: false }, () => {
  void it('still recognizes a short passwd-shaped line', () => {
    assert.equal(utils.matchesEtcPasswdFile('test:x:0:0:test:/test:/usr/bin/zsh\n'), true)
    assert.equal(utils.matchesEtcPasswdFile('a'.repeat(64)), false)
  })

  void it('does not stall the event loop on an unauthenticated long-word complaint', async () => {
    // Outside Docker and Heroku this challenge is stored with no disabledEnv, which is what enables the check.
    challenges.deprecatedInterfaceChallenge.disabledEnv = null
    assert.equal(utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge), true)
    assert.equal(challenges.xxeFileDisclosureChallenge.solved, false)

    const opening = '<?xml version="1.0"?><complaint>'
    const closing = '</complaint>'
    const xml = opening + 'a'.repeat(199000 - opening.length - closing.length) + closing
    assert.equal(Buffer.byteLength(xml), 199000)
    assert.ok(Buffer.byteLength(xml) < uploadLimitBytes)

    let ticks = 0
    const timer = setInterval(() => { ticks++ }, 100)
    const started = process.hrtime.bigint()
    try {
      const res = await request(app)
        .post('/file-upload')
        .attach('file', Buffer.from(xml), 'complaint.xml')
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6

      assert.equal(res.status, 410)
      assert.match(res.text, /B2B customer complaints via file upload have been deprecated for security reasons:/)
      assert.ok(res.text.includes('a'.repeat(80)))
      assert.equal(challenges.xxeFileDisclosureChallenge.solved, false)
      assert.ok(elapsedMs < responseBudgetMs, `upload took ${Math.round(elapsedMs)}ms`)
      assert.ok(ticks + 1 >= elapsedMs / 400, `event loop produced ${ticks} ticks in ${Math.round(elapsedMs)}ms`)
    } finally {
      clearInterval(timer)
    }
  }, { timeout: 90000 })
})
