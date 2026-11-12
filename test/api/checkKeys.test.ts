/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { HDNodeWallet } from 'ethers'
import { createTestApp } from './helpers/setup'

let app: Express
let wallet: HDNodeWallet

void describe('Web3 Key Derivation & NFT Unlock', () => {
  before(async () => {
    const { Wallet, HDNodeWallet } = await import('ethers')
    const mnemonic = Wallet.createRandom().mnemonic?.phrase
    assert.ok(mnemonic)
    process.env.NFT_UNLOCK_MNEMONIC = mnemonic
    wallet = HDNodeWallet.fromPhrase(mnemonic)
    const result = await createTestApp()
    app = result.app
  }, { timeout: 60000 })

  after(() => {
    delete process.env.NFT_UNLOCK_MNEMONIC
  })

  void describe('/rest/web3/submitKey', () => {
    void it('POST missing key in request body gets rejected as non-Ethereum key', async () => {
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .send({})

      assert.equal(res.status, 401)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
    })

    void it('POST arbitrary string in request body gets rejected as non-Ethereum key', async () => {
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: 'lalalala' })

      assert.equal(res.status, 401)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
    })

    void it('POST public wallet key in request body gets rejected as such', async () => {
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.publicKey })

      assert.equal(res.status, 401)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Looks like you entered the public key of my ethereum wallet!')
    })

    void it('POST wallet address in request body gets rejected as such', async () => {
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.address })

      assert.equal(res.status, 401)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Looks like you entered the public address of my ethereum wallet!')
    })

    void it('POST private key in request body gets accepted', async () => {
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.privateKey })

      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, true)
      assert.equal(res.body.message, 'Challenge successfully solved')
    })

    void it('POST private key of the configured wallet gets rejected once the configured phrase is removed', async () => {
      delete process.env.NFT_UNLOCK_MNEMONIC
      try {
        const res = await request(app)
          .post('/rest/web3/submitKey')
          .send({ privateKey: wallet.privateKey })

        assert.equal(res.status, 401)
        assert.equal(res.body.success, false)
      } finally {
        process.env.NFT_UNLOCK_MNEMONIC = wallet.mnemonic?.phrase
      }
    })
  })

  void describe('/rest/web3/nftUnlocked', () => {
    void it('GET solution status of "Unlock NFT" challenge', async () => {
      const res = await request(app)
        .get('/rest/web3/nftUnlocked')

      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(typeof res.body.status, 'boolean')
    })
  })
})
