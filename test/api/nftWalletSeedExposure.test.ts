/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import { createTestApp } from './helpers/setup'

const entities = new Entities()

function twelveWordPhrases (text: string): string[] {
  const decoded = entities.decode(text).toLowerCase()
  const words = decoded.match(/[a-z]+/g) ?? []
  const phrases = new Set<string>()
  for (let i = 0; i + 12 <= words.length; i++) {
    phrases.add(words.slice(i, i + 12).join(' '))
  }
  return [...phrases]
}

void describe('NFT wallet recovery phrase exposure', () => {
  let app: Express

  before(async () => {
    const result = await createTestApp()
    app = result.app
  }, { timeout: 60000 })

  void it('public feedback must not yield the NFT unlock key or the wallet published on the testnet page', async () => {
    const beforeUnlock = await request(app).get('/rest/web3/nftUnlocked')
    assert.equal(beforeUnlock.status, 200)
    assert.equal(beforeUnlock.body.status, false)

    const bodies: string[] = []
    for (const listPath of ['/api/Feedbacks', '/api/Feedbacks/']) {
      const res = await request(app).get(listPath)
      assert.equal(res.status, 200)
      assert.equal(res.body.status, 'success')
      assert.ok(Array.isArray(res.body.data))
      bodies.push(JSON.stringify(res.body.data))
    }

    const nftPage = [
      readFileSync(path.resolve('frontend/src/app/nft-unlock/nft-unlock.component.html'), 'utf8'),
      readFileSync(path.resolve('frontend/src/app/nft-unlock/nft-unlock.component.ts'), 'utf8')
    ].join('\n')
    const publishedAddresses = new Set(
      [...nftPage.matchAll(/0x[a-fA-F0-9]{40}/g)].map((match) => match[0].toLowerCase())
    )
    const publishesOnPublicTestnet = nftPage.includes('testnets.opensea.io')

    const { HDNodeWallet } = await import('ethers')
    const phrases = new Set<string>()
    for (const body of bodies) {
      for (const phrase of twelveWordPhrases(body)) {
        phrases.add(phrase)
      }
    }

    let accepted = false
    let matchesPublishedAddress = false
    for (const phrase of phrases) {
      let wallet: { privateKey: string, address: string }
      try {
        wallet = HDNodeWallet.fromPhrase(phrase)
      } catch {
        continue
      }
      if (publishesOnPublicTestnet && publishedAddresses.has(wallet.address.toLowerCase())) {
        matchesPublishedAddress = true
      }
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.privateKey })
      if (res.status === 200 && res.body?.success === true) {
        accepted = true
      }
    }

    const afterUnlock = await request(app).get('/rest/web3/nftUnlocked')
    const solved = afterUnlock.status === 200 && afterUnlock.body?.status === true
    const reasons: string[] = []
    if (accepted) reasons.push('unlock route accepted a key derived from public feedback')
    if (solved) reasons.push('unlock challenge was marked solved')
    if (matchesPublishedAddress) reasons.push('derived address is published on the NFT testnet page')
    if (reasons.length > 0) {
      throw new Error(reasons.join('; '))
    }
  })
})
