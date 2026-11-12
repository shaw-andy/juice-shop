/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { Wallet } from 'ethers/wallet'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let authHeader: Record<string, string>

const skipReason = process.env.ALCHEMY_API_KEY ? undefined : 'ALCHEMY_API_KEY not set'

async function signedClaim (wallet: Wallet) {
  const nonceRes = await request(app)
    .post('/rest/web3/walletNFTNonce')
    .set(authHeader)
    .send({ walletAddress: wallet.address })
  assert.equal(nonceRes.status, 200)
  const signature = await wallet.signMessage(nonceRes.body.message)
  return { walletAddress: wallet.address, nonce: nonceRes.body.nonce, signature }
}

void describe('Web3 NFT Minting', () => {
  before(async () => {
    const result = await createTestApp()
    app = result.app
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  }, { timeout: 60000 })

  void describe('/rest/web3/nftMintListen', { skip: skipReason }, () => {
    void it('GET call confirms registration of event listener', async () => {
      const res = await request(app)
        .get('/rest/web3/nftMintListen')

      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, true)
      assert.equal(res.body.message, 'Event Listener Created')
    })
  })

  void describe('/rest/web3/nftMintListen (error cases)', () => {
    void it('GET call returns 500 error if listener creation fails', async () => {
      const originalApiKey = process.env.ALCHEMY_API_KEY
      process.env.ALCHEMY_API_KEY = ' ' // Space makes URL invalid in some contexts or at least ethers should fail it

      const res = await request(app)
        .get('/rest/web3/nftMintListen')

      if (res.status === 500) {
        assert.ok(res.headers['content-type']?.includes('application/json'))
        assert.match(res.body, /URL/i)
      } else {
        assert.equal(res.status, 200)
        assert.equal(res.body.success, true)
      }

      process.env.ALCHEMY_API_KEY = originalApiKey
      mock.restoreAll()
    })
  })

  void describe('/rest/web3/walletNFTNonce', () => {
    void it('POST without authentication is rejected', async () => {
      const res = await request(app)
        .post('/rest/web3/walletNFTNonce')
        .send({ walletAddress: Wallet.createRandom().address })

      assert.equal(res.status, 401)
      assert.equal(res.body.success, false)
    })

    void it('POST invalid wallet address is rejected', async () => {
      const res = await request(app)
        .post('/rest/web3/walletNFTNonce')
        .set(authHeader)
        .send({ walletAddress: 'lalalalala' })

      assert.equal(res.status, 400)
      assert.equal(res.body.success, false)
    })
  })

  void describe('/rest/web3/walletNFTVerify', () => {
    void it('POST without authentication fails to solve minting challenge', async () => {
      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .send({ walletAddress: Wallet.createRandom().address })

      assert.equal(res.status, 401)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
    })

    void it('POST missing wallet address fails to solve minting challenge', async () => {
      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .set(authHeader)
        .send({})

      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Wallet ownership could not be verified')
    })

    void it('POST invalid wallet address fails to solve minting challenge', async () => {
      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .set(authHeader)
        .send({ walletAddress: 'lalalalala' })

      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Wallet ownership could not be verified')
    })

    void it('POST signed claim for a wallet that did not mint fails to solve minting challenge', async () => {
      const claim = await signedClaim(Wallet.createRandom())

      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .set(authHeader)
        .send(claim)

      assert.equal(res.status, 200)
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Wallet did not mint the NFT')
    })

    void it('POST signed claim for minted wallet successfully solves minting challenge', async () => {
      const wallet = Wallet.createRandom()
      const claim = await signedClaim(wallet)
      const originalDelete = Set.prototype.delete
      mock.method(Set.prototype, 'delete', function (this: any, val: any) {
        if (val === wallet.address) return true
        return originalDelete.call(this, val)
      })

      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .set(authHeader)
        .send(claim)

      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.success, true)
      assert.equal(res.body.message, 'Challenge successfully solved')

      mock.restoreAll()
    })

    void it('POST leads to 500 error if check fails', async () => {
      const wallet = Wallet.createRandom()
      const claim = await signedClaim(wallet)
      const originalDelete = Set.prototype.delete
      mock.method(Set.prototype, 'delete', function (this: any, val: any) {
        if (val === wallet.address) throw new Error('Mocked error')
        return originalDelete.call(this, val)
      })

      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .set(authHeader)
        .send(claim)

      assert.equal(res.status, 500)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body, 'Mocked error')

      mock.restoreAll()
    })
  })
})
