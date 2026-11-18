/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { performRedirect } from '../../routes/redirect'
import { type Challenge } from '@juice-shop/data/types'

void describe('order confirmation print redirect', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { query: {} }
    res = { redirect: mock.fn(), status: mock.fn() }
    next = mock.fn()
    challenges.redirectChallenge = { solved: false, save () { return { then () {} } } } as unknown as Challenge
  })

  void it('does not redirect when the target only contains an allow-listed url', () => {
    req.query.to = 'http://attacker.example/#https://github.com/juice-shop/juice-shop.pdf'

    performRedirect()(req, res, next)

    assert.equal(res.redirect.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.equal(challenges.redirectChallenge.solved, false)
  })

  void it('does not redirect when the target extends an allow-listed url', () => {
    req.query.to = 'https://github.com/juice-shop/juice-shop.attacker.example'

    performRedirect()(req, res, next)

    assert.equal(res.redirect.mock.calls.length, 0)
    assert.equal(challenges.redirectChallenge.solved, false)
  })

  void it('does not redirect when an allow-listed url is only a prefix of the target', () => {
    req.query.to = 'https://github.com/juice-shop/juice-shop/issues'

    performRedirect()(req, res, next)

    assert.equal(res.redirect.mock.calls.length, 0)
    assert.equal(challenges.redirectChallenge.solved, false)
  })
})
