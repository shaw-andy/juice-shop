/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import { redirectAllowlist } from '../../lib/insecurity'

const attackerOrigin = 'https://attacker.example'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function queryEmbedded (allowedUrl: string) {
  return `${attackerOrigin}/phish?next=${allowedUrl}`
}

function pathEmbedded (allowedUrl: string) {
  return `${attackerOrigin}/go/${allowedUrl}`
}

function fragmentEmbedded (allowedUrl: string) {
  return `${attackerOrigin}/phish#${allowedUrl}`
}

async function requestRedirect (to: string) {
  return await request(app)
    .get('/redirect')
    .query({ to })
    .redirects(0)
}

function assertRefused (res: { status: number, headers: Record<string, string | undefined> }, to: string) {
  assert.equal(
    res.status,
    406,
    `expected /redirect to refuse ${to}, got ${res.status} location=${String(res.headers.location)}`
  )
  const location = res.headers.location
  if (location !== undefined) {
    const target = new URL(location, 'http://127.0.0.1')
    assert.notEqual(target.origin, attackerOrigin, `Location sent the browser to ${location}`)
    assert.notEqual(target.href, to)
  }
  assert.equal(challenges.redirectChallenge.solved, false)
}

void describe('/redirect allow-list substring', () => {
  void it('still redirects when the target equals an allow-listed URL', async () => {
    const allowed = 'https://github.com/juice-shop/juice-shop'
    const res = await requestRedirect(allowed)
    assert.equal(res.status, 302)
    assert.equal(res.headers.location, allowed)
    assert.equal(challenges.redirectChallenge.solved, false)
  })

  for (const allowedUrl of redirectAllowlist) {
    void it(`refuses an external URL whose query string contains ${allowedUrl}`, async () => {
      const to = queryEmbedded(allowedUrl)
      challenges.redirectChallenge.solved = false
      const res = await requestRedirect(to)
      assertRefused(res, to)
    })
  }

  void it('refuses an external URL whose path contains an allow-listed URL', async () => {
    const to = pathEmbedded('https://github.com/juice-shop/juice-shop')
    challenges.redirectChallenge.solved = false
    const res = await requestRedirect(to)
    assertRefused(res, to)
  })

  void it('refuses an external URL whose fragment contains an allow-listed URL', async () => {
    const to = fragmentEmbedded('http://leanpub.com/juice-shop')
    challenges.redirectChallenge.solved = false
    const res = await requestRedirect(to)
    assertRefused(res, to)
  })

  void it('refuses the same external target when it is placed in the request target unencoded', async () => {
    const to = queryEmbedded('https://github.com/juice-shop/juice-shop')
    challenges.redirectChallenge.solved = false
    const res = await request(app)
      .get(`/redirect?to=${to}`)
      .redirects(0)
    assertRefused(res, to)
  })
})
