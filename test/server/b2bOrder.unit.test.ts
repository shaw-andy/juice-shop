/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { type Challenge } from '@juice-shop/data/types'
import { b2bOrder } from '../../routes/b2bOrder'

void describe('b2bOrder', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: mock.fn(), status: mock.fn() }
    next = mock.fn()
    save = () => ({
      then () { }
    })
    challenges.rceChallenge = { solved: false, save } as unknown as Challenge
    challenges.rceOccupyChallenge = { solved: false, save } as unknown as Challenge
  })

  void it('infinite loop payload is rejected without being evaluated', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res, next)

    assert.equal(res.status.mock.calls[0].arguments[0], 400)
    assert.equal(next.mock.calls.length, 1)
    assert.equal(res.json.mock.calls.length, 0)
    assert.equal(challenges.rceChallenge.solved, false)
  })

  void it('nested regular expression payload is rejected without being evaluated', () => {
    req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
    const started = Date.now()

    b2bOrder()(req, res, next)

    assert.ok(Date.now() - started < 1000)
    assert.equal(res.status.mock.calls[0].arguments[0], 400)
    assert.equal(challenges.rceOccupyChallenge.solved, false)
  })

  void it('non-string order lines are rejected', () => {
    req.body.orderLinesData = ['/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")']

    b2bOrder()(req, res, next)

    assert.equal(res.status.mock.calls[0].arguments[0], 400)
    assert.equal(res.json.mock.calls.length, 0)
  })

  void it('JSON as documented in Swagger is accepted', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res, next)

    assert.equal(res.json.mock.calls.length, 1)
    assert.equal(next.mock.calls.length, 0)
  })

  void it('arbitrary JSON is accepted', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res, next)

    assert.equal(res.json.mock.calls.length, 1)
  })

  void it('missing order lines are accepted', () => {
    b2bOrder()(req, res, next)

    assert.equal(res.json.mock.calls.length, 1)
  })

  void it('broken JSON is rejected', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res, next)

    assert.equal(res.status.mock.calls[0].arguments[0], 400)
    assert.equal(res.json.mock.calls.length, 0)
  })
})
