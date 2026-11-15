/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request, { type Response } from 'supertest'
import type { Express } from 'express'

// Contract for POST /rest/web3/submitKey:
// stretch the recovery phrase at most once for the process, and answer 429
// from the sixth anonymous submission on, even when each submission sends a
// different X-Forwarded-For value. These assertions fail while every request
// derives a wallet and the route has no such limit.

const submissionsBeforeRefusal = 5
const forwardedAddresses = [
  '203.0.113.1',
  '203.0.113.2',
  '203.0.113.3',
  '203.0.113.4',
  '203.0.113.5',
  '203.0.113.6'
]
const rejectedKeyMessage = 'Looks like you entered a non-Ethereum private key to access me.'

let stretchingCalls = 0
let fromPhraseCalls = 0
let restoreEthers: (() => void) | undefined

async function instrumentEthers (): Promise<void> {
  const { HDNodeWallet, Mnemonic } = await import('ethers')
  const originalComputeSeed = Mnemonic.prototype.computeSeed
  const originalFromPhrase = HDNodeWallet.fromPhrase
  Mnemonic.prototype.computeSeed = function () {
    stretchingCalls += 1
    return originalComputeSeed.call(this)
  }
  HDNodeWallet.fromPhrase = function (phrase, password, path, wordlist) {
    fromPhraseCalls += 1
    return originalFromPhrase.call(this, phrase, password, path, wordlist)
  } as typeof originalFromPhrase
  restoreEthers = () => {
    Mnemonic.prototype.computeSeed = originalComputeSeed
    HDNodeWallet.fromPhrase = originalFromPhrase
  }
}

interface SubmissionResult {
  status: number
  message: string | undefined
  stretchingCalls: number
  fromPhraseCalls: number
}

let results: SubmissionResult[] = []

void describe('POST /rest/web3/submitKey wallet stretching', () => {
  before(async () => {
    await instrumentEthers()
    const { createTestApp } = await import('./helpers/setup')
    const { app } = await createTestApp()
    results = []
    for (let i = 0; i < forwardedAddresses.length; i++) {
      const res = await submitKey(app, forwardedAddresses[i], i)
      results.push({
        status: res.status,
        message: typeof res.body?.message === 'string' ? res.body.message : undefined,
        stretchingCalls,
        fromPhraseCalls
      })
    }
  }, { timeout: 60000 })

  after(() => {
    restoreEthers?.()
  })

  void it('derives the wallet at most once for anonymous submissions, including an empty body', () => {
    assert.equal(results.length, forwardedAddresses.length)
    assert.equal(results[0].status, 401)
    assert.equal(results[0].message, rejectedKeyMessage)
    assert.ok(results[0].stretchingCalls <= 1, `recovery-phrase stretching ran ${results[0].stretchingCalls} times before the first response`)
    assert.ok(stretchingCalls <= 1, `recovery-phrase stretching ran ${stretchingCalls} times across ${results.length} submissions`)
    assert.ok(fromPhraseCalls <= 1, `HDNodeWallet.fromPhrase ran ${fromPhraseCalls} times across ${results.length} submissions`)
    for (const result of results) {
      if (result.status === 401) {
        assert.equal(result.message, rejectedKeyMessage)
      }
    }
  })

  void it('refuses the sixth submission even when X-Forwarded-For changes on every request', () => {
    assert.equal(results.length, forwardedAddresses.length)
    const refused = results[submissionsBeforeRefusal]
    assert.equal(refused.status, 429)
    assert.equal(
      refused.stretchingCalls,
      results[submissionsBeforeRefusal - 1].stretchingCalls,
      'the refused submission stretched the recovery phrase again'
    )
    for (let i = 0; i < submissionsBeforeRefusal; i++) {
      assert.notEqual(results[i].status, 429, `submission ${i + 1} was refused before the limit`)
    }
  })
})

async function submitKey (app: Express, forwardedFor: string, index: number): Promise<Response> {
  const req = request(app)
    .post('/rest/web3/submitKey')
    .set('X-Forwarded-For', forwardedFor)
  if (index === 1) {
    return await req
  }
  const body = index === 2 ? { privateKey: 'placeholder-not-a-key' } : {}
  return await req.set('Content-Type', 'application/json').send(body)
}
