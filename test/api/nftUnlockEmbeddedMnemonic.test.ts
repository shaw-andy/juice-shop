/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import request from 'supertest'
import { HDNodeWallet, verifyMessage } from 'ethers'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const sourceExtensions = new Set(['.ts', '.js', '.mjs', '.cjs', '.yml', '.yaml', '.json', '.html', '.hbs', '.pug', '.sol'])
const skippedDirectories = new Set(['node_modules', '.git', 'dist', 'coverage', 'build', 'test'])
const mnemonicLengths = new Set([12, 15, 18, 21, 24])
const addressMessage = 'Looks like you entered the public address of my ethereum wallet!'
const publicKeyMessage = 'Looks like you entered the public key of my ethereum wallet!'

let app: Express

function listSourceFiles (directory: string, files: string[] = []): string[] {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (skippedDirectories.has(entry.name)) continue
    const fullPath = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      listSourceFiles(fullPath, files)
    } else if (sourceExtensions.has(path.extname(entry.name)) && !entry.name.endsWith('.spec.ts')) {
      files.push(fullPath)
    }
  }
  return files
}

function mnemonicLiterals (source: string): string[] {
  const literals: string[] = []
  const pattern = /(['"`])((?:\\.|(?!\1).)*?)\1/g
  let match: RegExpExecArray | null
  while ((match = pattern.exec(source)) !== null) {
    const words = match[2].trim().split(/\s+/)
    if (!mnemonicLengths.has(words.length)) continue
    if (!words.every((word) => /^[a-z]+$/.test(word))) continue
    literals.push(words.join(' '))
  }
  return literals
}

function embeddedMnemonics (): string[] {
  const phrases = new Set<string>()
  const files = listSourceFiles(repoRoot)
  for (const file of files) {
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) continue
    let source: string
    try {
      source = fs.readFileSync(file, 'utf8')
    } catch {
      continue
    }
    for (const phrase of mnemonicLiterals(source)) {
      try {
        HDNodeWallet.fromPhrase(phrase)
        phrases.add(phrase)
      } catch {
        // Not a phrase this route's helper accepts.
      }
    }
  }
  return [...phrases]
}

void describe('NFT unlock embedded wallet seed', () => {
  before(async () => {
    const result = await createTestApp()
    app = result.app
  }, { timeout: 60000 })

  void it('does not solve the NFT unlock challenge from a mnemonic literal embedded in the application', async () => {
    const phrases = embeddedMnemonics()
    if (phrases.length === 0) {
      const rejected = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: 'placeholder-not-a-wallet-key' })
      const unlocked = await request(app).get('/rest/web3/nftUnlocked')
      assert.equal(rejected.body.success, false)
      assert.equal(unlocked.body.status, false)
      return
    }

    const recognized: string[] = []
    for (const phrase of phrases) {
      const wallet = HDNodeWallet.fromPhrase(phrase)
      const message = 'nft-unlock-control'
      const recovered = verifyMessage(message, wallet.signMessageSync(message))
      if (recovered !== wallet.address) {
        throw new Error('derived signing key does not recover the wallet address')
      }

      const privateKeyResponse = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.privateKey })
      if (privateKeyResponse.status === 200 || privateKeyResponse.body?.success === true) {
        recognized.push('privateKey')
      }

      const addressResponse = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.address })
      if (addressResponse.body?.message === addressMessage) recognized.push('address')

      const publicKeyResponse = await request(app)
        .post('/rest/web3/submitKey')
        .send({ privateKey: wallet.publicKey })
      if (publicKeyResponse.body?.message === publicKeyMessage) recognized.push('publicKey')
    }

    const unlocked = await request(app).get('/rest/web3/nftUnlocked')
    if (unlocked.body.status === true) recognized.push('challenge-solved')

    assert.deepEqual(
      { embeddedMnemonicLiterals: phrases.length, recognizedBySubmitKey: recognized },
      { embeddedMnemonicLiterals: 0, recognizedBySubmitKey: [] }
    )
  })
})
