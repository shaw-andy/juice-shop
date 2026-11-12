/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import request from 'supertest'
import config from 'config'
import yaml from 'js-yaml'
import type { Express } from 'express'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

// Same orderLinesData value the API suite already sends for this route.
const nestedOrderLines = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
const stallLimitMs = 1000

interface StaticUser {
  key: string
  email: string
  password: string
  role: string
}

let app: Express
let customerAuthorization: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const users = yaml.load(fs.readFileSync('data/static/users.yml', 'utf8')) as StaticUser[]
  const customer = users.find((user) => user.key === 'jim' && user.role === 'customer')
  if (customer == null) {
    throw new Error('customer fixture missing')
  }
  const domain = config.get<string>('application.domain')
  const email = customer.email.includes('@') ? customer.email : `${customer.email}@${domain}`
  const authentication = await login(app, { email, password: customer.password })
  customerAuthorization = 'Bearer ' + authentication.token
}, { timeout: 60000 })

void describe('POST /b2b/v2/orders orderLinesData', () => {
  void it('does not evaluate a nested regular expression on the request thread', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.rceChallenge), true)
    assert.equal(utils.isChallengeEnabled(challenges.rceOccupyChallenge), true)
    challenges.rceOccupyChallenge.solved = false
    await challenges.rceOccupyChallenge.save()

    const agent = request.agent(app)
    const ticks = [Date.now()]
    const timer = setInterval(() => {
      ticks.push(Date.now())
    }, 25)
    const orderStarted = Date.now()
    const probeStarted = Date.now()
    let orderMs = 0
    let probeMs = 0
    let orderStatus = 0
    let orderText = ''
    let probeStatus = 0
    try {
      const orderPromise = agent
        .post('/b2b/v2/orders')
        .set('Authorization', customerAuthorization)
        .set('content-type', 'application/json')
        .send({ orderLinesData: nestedOrderLines })
        .then((res) => {
          orderMs = Date.now() - orderStarted
          orderStatus = res.status
          orderText = res.text
        })
      const probePromise = agent
        .get('/rest/admin/application-version')
        .then((res) => {
          probeMs = Date.now() - probeStarted
          probeStatus = res.status
        })
      await Promise.all([orderPromise, probePromise])
    } finally {
      clearInterval(timer)
      ticks.push(Date.now())
    }

    let maxGapMs = 0
    for (let i = 1; i < ticks.length; i++) {
      maxGapMs = Math.max(maxGapMs, ticks[i] - ticks[i - 1])
    }

    const problems: string[] = []
    if (orderStatus === 503) problems.push(`order status ${orderStatus}`)
    if (orderText.includes('temporarily not available')) problems.push('order body reports the stall response')
    if (orderMs >= stallLimitMs) problems.push(`order took ${orderMs}ms`)
    if (maxGapMs >= stallLimitMs) problems.push(`event loop gap ${maxGapMs}ms`)
    if (probeMs >= stallLimitMs) problems.push(`concurrent version request took ${probeMs}ms`)
    if (probeStatus !== 200) problems.push(`concurrent version status ${probeStatus}`)
    if (challenges.rceOccupyChallenge.solved) problems.push('occupy challenge solved')
    assert.deepEqual(problems, [])
  }, { timeout: 15000 })

  void it('does not evaluate the same pattern from a form body on the request thread', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.rceChallenge), true)
    assert.equal(utils.isChallengeEnabled(challenges.rceOccupyChallenge), true)
    challenges.rceOccupyChallenge.solved = false
    await challenges.rceOccupyChallenge.save()

    const agent = request.agent(app)
    const ticks = [Date.now()]
    const timer = setInterval(() => {
      ticks.push(Date.now())
    }, 25)
    const orderStarted = Date.now()
    let orderMs = 0
    let orderStatus = 0
    let orderText = ''
    try {
      await agent
        .post('/b2b/v2/orders')
        .set('Authorization', customerAuthorization)
        .type('form')
        .send({ orderLinesData: nestedOrderLines })
        .then((res) => {
          orderMs = Date.now() - orderStarted
          orderStatus = res.status
          orderText = res.text
        })
    } finally {
      clearInterval(timer)
      ticks.push(Date.now())
    }

    let maxGapMs = 0
    for (let i = 1; i < ticks.length; i++) {
      maxGapMs = Math.max(maxGapMs, ticks[i] - ticks[i - 1])
    }

    const problems: string[] = []
    if (orderStatus === 503) problems.push(`order status ${orderStatus}`)
    if (orderText.includes('temporarily not available')) problems.push('order body reports the stall response')
    if (orderMs >= stallLimitMs) problems.push(`order took ${orderMs}ms`)
    if (maxGapMs >= stallLimitMs) problems.push(`event loop gap ${maxGapMs}ms`)
    if (challenges.rceOccupyChallenge.solved) problems.push('occupy challenge solved')
    assert.deepEqual(problems, [])
  }, { timeout: 15000 })
})
