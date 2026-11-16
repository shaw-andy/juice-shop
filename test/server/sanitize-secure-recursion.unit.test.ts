/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as security from '../../lib/insecurity'

// One "<" plus "/div>" is one layer. sanitize-html 1.4.2 consumes a single
// layer per call and leaves the same shape behind, so sanitizeSecure recurses
// once per layer.
function nestedClosingDivs (layers: number) {
  return '<p>' + '<'.repeat(layers) + '/div>'.repeat(layers) + 'x</p>'
}

const STACK_LAYERS = 14000
const BUDGET_MS = 500

void describe('sanitizeSecure recursion bound', () => {
  void it('returns stable harmless markup unchanged', () => {
    assert.equal(security.sanitizeSecure('<p>hello</p>'), '<p>hello</p>')
    assert.equal(security.sanitizeSecure('plain text'), 'plain text')
  })

  void it('finishes a stack-sized nested fragment without overflowing or blocking', () => {
    const input = nestedClosingDivs(STACK_LAYERS)
    const started = Date.now()
    let error: Error | undefined
    try {
      security.sanitizeSecure(input)
    } catch (err) {
      error = err as Error
    }
    const elapsed = Date.now() - started
    assert.ok(elapsed < BUDGET_MS, `sanitizeSecure blocked the caller for ${elapsed}ms`)
    if (error) {
      assert.notEqual(error.name, 'RangeError')
      assert.equal(error.message.includes('Maximum call stack size exceeded'), false)
    }
  })
})
