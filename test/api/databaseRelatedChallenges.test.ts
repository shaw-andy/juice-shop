/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import { type ChallengeKey } from '../../models/challenge'

const repeatedRoutes = [
  '/rest/captcha',
  '/rest/languages',
  '/rest/continue-code',
  '/rest/products/search?q=juice',
  '/api/Products',
  '/api/Feedbacks',
  '/api/Challenges',
  '/metrics',
  '/contact',
  '/score-board'
]

const checksThatScanOnEachRequest: ChallengeKey[] = [
  'changeProductChallenge',
  'feedbackChallenge',
  'knownVulnerableComponentChallenge',
  'weirdCryptoChallenge',
  'typosquattingNpmChallenge',
  'typosquattingAngularChallenge',
  'hiddenImageChallenge',
  'supplyChainAttackChallenge',
  'dlpPastebinDataLeakChallenge',
  'csafChallenge',
  'leakedApiKeyChallenge',
  'vulnerableDockerImageChallenge',
  'systemPromptExtractionChallenge'
]

const requestsPerRoute = 6
const patternQueriesInOnePass = 40
const fiveStarQueriesInOnePass = 2

let app: Express
let sequelize: Sequelize
const sqlLog: string[] = []

function delay (ms: number) {
  return new Promise(resolve => { setTimeout(resolve, ms) })
}

async function settleQueries () {
  let previous = -1
  for (let attempt = 0; attempt < 200; attempt++) {
    const current = sqlLog.length
    if (current === previous) {
      await delay(30)
      if (sqlLog.length === current) return
    }
    previous = sqlLog.length
    await delay(15)
  }
  throw new Error('database queries did not settle')
}

function scanCounts (sql: string[]) {
  let complaintLoads = 0
  let patternScans = 0
  let fiveStarScans = 0
  let productReloads = 0
  for (const statement of sql) {
    const complaint = /from `Complaints`/i.test(statement)
    const feedback = /from `Feedbacks`/i.test(statement)
    const hasWhere = / where /i.test(statement)
    if (complaint && !hasWhere) complaintLoads++
    if ((complaint || feedback) && / like /i.test(statement)) patternScans++
    if (feedback && /`rating` = 5/.test(statement)) fiveStarScans++
    if (/from `Products` as `Product`/i.test(statement) && /`Product`\.`id` = /.test(statement)) productReloads++
  }
  return { complaintLoads, patternScans, fiveStarScans, productReloads }
}

function assertScansDoNotFollowRequests (route: string, requestCount: number, counts: ReturnType<typeof scanCounts>) {
  const summary = `${route}: ${requestCount} anonymous requests produced ${counts.complaintLoads} full complaint loads, ${counts.patternScans} feedback/complaint pattern scans, ${counts.fiveStarScans} five-star feedback scans, ${counts.productReloads} product reloads`
  assert.ok(counts.complaintLoads <= 1, summary)
  assert.ok(counts.patternScans <= patternQueriesInOnePass, summary)
  assert.ok(counts.fiveStarScans <= fiveStarQueriesInOnePass, summary)
  assert.ok(counts.productReloads <= 1, summary)
}

async function timeDelivery () {
  const started = Date.now()
  const response = await request(app).get('/api/Deliverys')
  return { ms: Date.now() - started, status: response.status }
}

before(async () => {
  const created = await createTestApp()
  app = created.app
  sequelize = created.sequelize
  sequelize.options.logging = (sql: string) => {
    sqlLog.push(sql)
  }
  await settleQueries()
  sqlLog.length = 0
}, { timeout: 60000 })

void describe('databaseRelatedChallenges on anonymous requests', { concurrency: 1 }, () => {
  void it('starts from the fresh-install state where these checks are still unsolved', () => {
    for (const key of checksThatScanOnEachRequest) {
      assert.equal(challenges[key].solved, false, key)
    }
  })

  for (const route of repeatedRoutes) {
    void it(`does not repeat challenge table scans for every anonymous GET ${route}`, async () => {
      await settleQueries()
      sqlLog.length = 0
      const responses = []
      for (let i = 0; i < requestsPerRoute; i++) {
        responses.push(await request(app).get(route))
      }
      await settleQueries()
      for (const response of responses) {
        assert.notEqual(response.status, 401)
        assert.ok(response.status < 500, `${route} returned ${response.status}`)
      }
      assertScansDoNotFollowRequests(route, requestsPerRoute, scanCounts(sqlLog))
    })
  }

  void it('does not repeat challenge table scans when an anonymous handler responds 401', async () => {
    await settleQueries()
    sqlLog.length = 0
    const responses = []
    for (let i = 0; i < requestsPerRoute; i++) {
      responses.push(await request(app).get('/rest/image-captcha'))
    }
    await settleQueries()
    for (const response of responses) {
      assert.equal(response.status, 401)
    }
    assertScansDoNotFollowRequests('/rest/image-captcha', requestsPerRoute, scanCounts(sqlLog))
  })

  void it('does not let a burst of anonymous captcha requests stall an ordinary database read', async () => {
    const baselineSamples = []
    for (let i = 0; i < 5; i++) {
      const sample = await timeDelivery()
      assert.equal(sample.status, 200)
      baselineSamples.push(sample.ms)
    }
    const baseline = baselineSamples.sort((a, b) => a - b)[2]

    await settleQueries()
    sqlLog.length = 0
    const alone = await timeDelivery()
    await settleQueries()
    const deliveryQueries = scanCounts(sqlLog)
    assert.equal(deliveryQueries.complaintLoads, 0)
    assert.equal(deliveryQueries.patternScans, 0)
    assert.equal(deliveryQueries.fiveStarScans, 0)
    assert.equal(alone.status, 200)

    const floodSize = 40
    const flood = Promise.all(Array.from({ length: floodSize }, async () => {
      return await request(app).get('/rest/captcha')
    }))
    const during = await timeDelivery()
    const floodResponses = await flood
    await settleQueries()
    for (const response of floodResponses) {
      assert.equal(response.status, 200)
    }
    assert.equal(during.status, 200)
    assert.ok(
      during.ms < Math.max(baseline * 20, 250),
      `GET /api/Deliverys took ${during.ms}ms during ${floodSize} anonymous GET /rest/captcha requests (baseline ${baseline}ms)`
    )
    assertScansDoNotFollowRequests('/rest/captcha flood', floodSize, scanCounts(sqlLog))
  })
})
