/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { type Challenge } from '@juice-shop/data/types'
import { continueCode } from '../../routes/continueCode'
import { decrypt } from '../../lib/continueCodes'
import Hashids from 'hashids/cjs'

const hashids = new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')

void describe('continueCode', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = {}
    res = { json: mock.fn() }
  })

  void it('should be empty when no challenges are solved', () => {
    challenges.scoreBoardChallenge = { solved: false } as unknown as Challenge
    challenges.adminSectionChallenge = { solved: false } as unknown as Challenge

    continueCode()(req, res)
    assert.equal(res.json.mock.calls.length, 1)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { continueCode: undefined })
  })

  void it('should be an encrypted code of the IDs of solved challenges', () => {
    challenges.scoreBoardChallenge = { id: 1, solved: true } as unknown as Challenge
    challenges.adminSectionChallenge = { id: 2, solved: true } as unknown as Challenge
    challenges.continueCodeChallenge = { id: 3, solved: false } as unknown as Challenge

    continueCode()(req, res)
    assert.equal(res.json.mock.calls.length, 1)
    const code = res.json.mock.calls[0].arguments[0].continueCode
    assert.match(code, /^[a-zA-Z0-9]+$/)
    assert.deepEqual(decrypt('hacking', hashids.decodeHex(code)), [1, 2])
    assert.deepEqual(decrypt('fixIt', hashids.decodeHex(code)), [])
  })

  void it('should not accept a tampered code', () => {
    challenges.scoreBoardChallenge = { id: 1, solved: true } as unknown as Challenge

    continueCode()(req, res)
    const hex = hashids.decodeHex(res.json.mock.calls[0].arguments[0].continueCode)
    const tampered = hex.slice(0, -1) + (hex.endsWith('0') ? '1' : '0')
    assert.deepEqual(decrypt('hacking', tampered), [])
  })
})
