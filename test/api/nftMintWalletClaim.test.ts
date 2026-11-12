/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { Contract } from 'ethers/contract'
import { Interface } from 'ethers/abi'
import { Wallet } from 'ethers/wallet'
import { getAddress } from 'ethers/address'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { challenges } from '../../data/datacache'
import { ChallengeModel } from '../../models/challenge'
import { nftABI } from '../../data/static/contractABIs'

const password = 'placeholder'
const jsonHeader = { 'content-type': 'application/json' }

interface MintLog {
  data: string
  topics: readonly string[]
}

const mintLogListeners: Array<(log: MintLog) => void> = []

class RecordingWebSocketProvider {
  websocket: { onerror: ((error: unknown) => void) | null }
  constructor (url: string) {
    this.websocket = { onerror: null }
    this.url = url
  }

  url: string

  get provider () {
    return this
  }

  on (_filter: unknown, listener: (log: MintLog) => void) {
    mintLogListeners.push(listener)
    return Promise.resolve(this)
  }

  off () {
    return Promise.resolve(this)
  }
}

mock.module('ethers', {
  cache: true,
  namedExports: {
    Contract,
    WebSocketProvider: RecordingWebSocketProvider
  }
})

const mintInterface = new Interface(nftABI)
let app: Express
let ownerId = 0
let otherId = 0
let ownerToken = ''
let otherToken = ''

function bearer (token: string) {
  return { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}

// EIP-191 personal_sign payload. The server must recover the signer of this exact string.
function mintClaimMessage (userId: number, walletAddress: string, nonce: string) {
  return `juice-shop nft mint\nuserId:${userId}\nwallet:${walletAddress}\nnonce:${nonce}`
}

async function waitForMintSubscription () {
  const started = Date.now()
  while (mintLogListeners.length === 0) {
    if (Date.now() - started > 2000) {
      throw new Error('NFTMinted subscription was not registered')
    }
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  return mintLogListeners[0]
}

async function recordMint (walletAddress: string) {
  const listener = await waitForMintSubscription()
  const fragment = mintInterface.getEvent('NFTMinted')
  assert.ok(fragment)
  const encoded = mintInterface.encodeEventLog(fragment, [walletAddress, 1])
  listener({ data: encoded.data, topics: encoded.topics })
  await new Promise(resolve => setTimeout(resolve, 30))
}

async function assertMintUnsolved () {
  assert.equal(challenges.nftMintChallenge.solved, false)
  const started = Date.now()
  while (Date.now() - started < 250) {
    const row = await ChallengeModel.findOne({ where: { key: 'nftMintChallenge' } })
    assert.equal(row?.solved, false)
    assert.equal(row?.get('solvedByUserId') ?? null, null)
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

async function issueNonce (token: string, walletAddress: string) {
  const res = await request(app)
    .post('/rest/web3/walletNFTNonce')
    .set(bearer(token))
    .send({ walletAddress })
  assert.equal(res.status, 200)
  assert.equal(typeof res.body.nonce, 'string')
  assert.notEqual(res.body.nonce, '')
  assert.notEqual(res.body.nonce, walletAddress)
  return res.body.nonce as string
}

async function claimMint (token: string, userId: number, wallet: Wallet, decoyAddress: string) {
  const walletAddress = getAddress(wallet.address)
  const nonce = await issueNonce(token, walletAddress)
  const signature = await wallet.signMessage(mintClaimMessage(userId, walletAddress, nonce))
  const res = await request(app)
    .post('/rest/web3/walletNFTVerify')
    .set(bearer(token))
    .send({
      walletAddress,
      nonce,
      signature,
      address: decoyAddress,
      metamaskAddress: decoyAddress,
      minter: decoyAddress
    })
  assert.equal(res.status, 200)
  assert.equal(res.body.success, true)
  assert.equal(res.body.solvedForUserId, userId)
  assert.equal(res.body.status.solved, true)
  assert.equal(res.body.status.solvedByUserId, userId)
  const listed = await request(app).get('/api/Challenges/?key=nftMintChallenge')
  assert.equal(listed.status, 200)
  const row = (listed.body.data as Array<{ key: string, solved: boolean, solvedByUserId: number }>).find(item => item.key === 'nftMintChallenge')
  assert.ok(row)
  assert.equal(row.solved, true)
  assert.equal(row.solvedByUserId, userId)
  return res
}

void describe('nft mint claim authorization', { concurrency: 1 }, () => {
  before(async () => {
    delete process.env.ALCHEMY_API_KEY
    const loaded = await import('ethers')
    assert.equal(loaded.WebSocketProvider, RecordingWebSocketProvider)
    const result = await createTestApp()
    app = result.app
    const owner = await register(app, { email: 'mint-owner@example.test', password })
    const other = await register(app, { email: 'mint-other@example.test', password })
    ownerId = owner.body.data.id
    otherId = other.body.data.id
    ownerToken = (await login(app, { email: 'mint-owner@example.test', password })).token
    otherToken = (await login(app, { email: 'mint-other@example.test', password })).token
    const listen = await request(app).get('/rest/web3/nftMintListen')
    assert.equal(listen.status, 200)
    assert.equal(listen.body.success, true)
    await waitForMintSubscription()
  }, { timeout: 60000 })

  beforeEach(async () => {
    challenges.nftMintChallenge.solved = false
    await challenges.nftMintChallenge.save()
  })

  void it('submitting a recorded address with no server nonce does not solve or consume the mint', async () => {
    const wallet = Wallet.createRandom()
    const walletAddress = getAddress(wallet.address)
    const decoy = getAddress(Wallet.createRandom().address)
    await recordMint(walletAddress)
    const signature = await wallet.signMessage(mintClaimMessage(ownerId, walletAddress, 'client-chosen-nonce'))
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(jsonHeader)
      .send({
        walletAddress,
        nonce: 'client-chosen-nonce',
        signature,
        address: decoy,
        metamaskAddress: decoy
      })
    assert.equal(res.body.success, false)
    await assertMintUnsolved()
    await claimMint(ownerToken, ownerId, wallet, decoy)
  })

  void it('a logged-in caller whose address is recorded still needs a signature over the server nonce', async () => {
    const wallet = Wallet.createRandom()
    const walletAddress = getAddress(wallet.address)
    const decoy = getAddress(Wallet.createRandom().address)
    await recordMint(walletAddress)
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(bearer(ownerToken))
      .send({ walletAddress, address: decoy, metamaskAddress: decoy })
    assert.equal(res.body.success, false)
    await assertMintUnsolved()
    await claimMint(ownerToken, ownerId, wallet, decoy)
  })

  void it('a signature over a nonce the server did not issue does not solve or consume the mint', async () => {
    const wallet = Wallet.createRandom()
    const walletAddress = getAddress(wallet.address)
    const decoy = getAddress(Wallet.createRandom().address)
    await recordMint(walletAddress)
    const nonce = 'client-chosen-nonce'
    const signature = await wallet.signMessage(mintClaimMessage(ownerId, walletAddress, nonce))
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(bearer(ownerToken))
      .send({ walletAddress, nonce, signature, address: decoy, metamaskAddress: decoy })
    assert.equal(res.body.success, false)
    await assertMintUnsolved()
    await claimMint(ownerToken, ownerId, wallet, decoy)
  })

  void it('a signature from a different wallet does not solve or consume the recorded mint', async () => {
    const minted = Wallet.createRandom()
    const signer = Wallet.createRandom()
    const walletAddress = getAddress(minted.address)
    const decoy = getAddress(signer.address)
    await recordMint(walletAddress)
    const nonce = await issueNonce(ownerToken, walletAddress)
    const signature = await signer.signMessage(mintClaimMessage(ownerId, walletAddress, nonce))
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(bearer(ownerToken))
      .send({ walletAddress, nonce, signature, address: decoy, metamaskAddress: decoy })
    assert.equal(res.body.success, false)
    await assertMintUnsolved()
    await claimMint(ownerToken, ownerId, minted, decoy)
  })

  void it('proof for the recorded wallet does not consume a different address in the same body', async () => {
    const minted = Wallet.createRandom()
    const otherMinted = Wallet.createRandom()
    const walletAddress = getAddress(minted.address)
    const otherAddress = getAddress(otherMinted.address)
    await recordMint(walletAddress)
    await recordMint(otherAddress)
    const nonce = await issueNonce(ownerToken, walletAddress)
    const signature = await minted.signMessage(mintClaimMessage(ownerId, walletAddress, nonce))
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(bearer(ownerToken))
      .send({
        walletAddress: otherAddress,
        address: walletAddress,
        metamaskAddress: otherAddress,
        minter: walletAddress,
        nonce,
        signature
      })
    assert.equal(res.body.success, false)
    await assertMintUnsolved()
    challenges.nftMintChallenge.solved = false
    await challenges.nftMintChallenge.save()
    await claimMint(ownerToken, ownerId, minted, otherAddress)
    challenges.nftMintChallenge.solved = false
    await challenges.nftMintChallenge.save()
    await claimMint(otherToken, otherId, otherMinted, walletAddress)
  })

  void it('a nonce issued to one account cannot be redeemed by another account', async () => {
    const wallet = Wallet.createRandom()
    const walletAddress = getAddress(wallet.address)
    const decoy = getAddress(Wallet.createRandom().address)
    await recordMint(walletAddress)
    const nonce = await issueNonce(ownerToken, walletAddress)
    const signature = await wallet.signMessage(mintClaimMessage(ownerId, walletAddress, nonce))
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(bearer(otherToken))
      .send({ walletAddress, nonce, signature, address: decoy, metamaskAddress: decoy })
    assert.equal(res.body.success, false)
    await assertMintUnsolved()
    await claimMint(ownerToken, ownerId, wallet, decoy)
  })

  void it('the account that signed the server nonce is the account the solved challenge is bound to', async () => {
    const wallet = Wallet.createRandom()
    const decoyWallet = Wallet.createRandom()
    const decoy = getAddress(decoyWallet.address)
    await recordMint(getAddress(wallet.address))
    await recordMint(decoy)
    await claimMint(ownerToken, ownerId, wallet, decoy)
    const anonymous = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set(jsonHeader)
      .send({ walletAddress: decoy })
    assert.equal(anonymous.body.success, false)
    assert.equal(challenges.nftMintChallenge.solvedByUserId, ownerId)
    challenges.nftMintChallenge.solved = false
    await challenges.nftMintChallenge.save()
    await claimMint(otherToken, otherId, decoyWallet, getAddress(wallet.address))
  })
})
