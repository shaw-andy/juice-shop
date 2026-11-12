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
import { redirectAllowlist } from '../../lib/insecurity'

const allowedGitHub = 'https://github.com/juice-shop/juice-shop'
const allowedLeanpub = 'http://leanpub.com/juice-shop'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('GET /redirect allow-list', () => {
  void it('redirects only when the target origin and path are exactly an allow-listed value', async () => {
    for (const url of redirectAllowlist) {
      const res = await request(app)
        .get('/redirect')
        .query({ to: url })
        .redirects(0)
      assert.equal(res.status, 302, url)
      assert.equal(res.headers.location, url)
    }
  })

  void it('does not redirect to an attacker host whose query contains an allow-listed URL', async () => {
    await assertRejected(app, `https://evil.example/phish?next=${allowedGitHub}`)
  })

  void it('does not redirect to an attacker host whose path contains an allow-listed URL', async () => {
    await assertRejected(app, `https://evil.example/${allowedGitHub}`)
  })

  void it('does not redirect to an attacker host whose fragment contains an allow-listed URL', async () => {
    await assertRejected(app, `https://evil.example/phish#${allowedGitHub}`)
  })

  void it('does not redirect to an attacker host that contains a different allow-listed URL', async () => {
    await assertRejected(app, `https://evil.example/phish?next=${allowedLeanpub}`)
  })

  void it('does not redirect to a userinfo host that merely contains an allow-listed URL', async () => {
    await assertRejected(app, `https://user:${allowedGitHub}@evil.example/`)
  })

  void it('does not redirect when the target only extends an allow-listed path', async () => {
    await assertRejected(app, `${allowedGitHub}/issues`)
    await assertRejected(app, `${allowedGitHub}.evil.example`)
    await assertRejected(app, `${allowedGitHub}@evil.example`)
  })

  void it('does not redirect a relative URL that contains an allow-listed URL', async () => {
    await assertRejected(app, `/score-board?satisfyIndexOf=${allowedGitHub}`)
    await assertRejected(app, `//evil.example/landing?next=${allowedGitHub}`)
  })

  void it('does not redirect an unexpected scheme that contains an allow-listed URL', async () => {
    await assertRejected(app, `javascript:alert(1)//${allowedGitHub}`)
    await assertRejected(app, `data:text/html,${allowedGitHub}`)
  })
})

async function assertRejected (app: Express, target: string) {
  const res = await request(app)
    .get('/redirect')
    .query({ to: target })
    .redirects(0)
  assertNoRedirect(res, target)
}

function assertNoRedirect (res: Response, target: string) {
  const location = res.headers.location
  const redirected = res.status >= 300 && res.status < 400
  assert.equal(
    redirected,
    false,
    `redirected ${res.status} to ${String(location)} for target ${target}`
  )
  assert.equal(location, undefined, `Location set for target ${target}`)
}
