/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { MissingSigningSecretsError, SIGNING_SECRET_ENV } from '../../lib/hardenedProfile'
import { createApp } from '../../server'

function clearProfileEnv () {
  delete process.env.JUICESHOP_PROFILE
  for (const name of Object.values(SIGNING_SECRET_ENV)) {
    delete process.env[name]
  }
  security.loadHardenedSecrets()
}

after(() => {
  clearProfileEnv()
})

void describe('hardened profile', () => {
  void it('does not build an app when signing secrets are missing', async () => {
    clearProfileEnv()
    process.env.JUICESHOP_PROFILE = 'hardened'
    await assert.rejects(() => createApp({ inMemoryDb: true }), (error: unknown) => {
      assert.ok(error instanceof MissingSigningSecretsError)
      assert.match(error.message, /JUICESHOP_JWT_PRIVATE_KEY/)
      assert.match(error.message, /JUICESHOP_JWT_PUBLIC_KEY/)
      assert.match(error.message, /JUICESHOP_COOKIE_SECRET/)
      assert.match(error.message, /JUICESHOP_HMAC_KEY/)
      return true
    })
  })

  void describe('exposed file mounts', () => {
    let app: Express

    before(async () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
      })
      process.env.JUICESHOP_PROFILE = 'hardened'
      process.env[SIGNING_SECRET_ENV.jwtPrivateKey] = privateKey
      process.env[SIGNING_SECRET_ENV.jwtPublicKey] = publicKey
      process.env[SIGNING_SECRET_ENV.cookieSecret] = crypto.randomBytes(32).toString('hex')
      process.env[SIGNING_SECRET_ENV.hmacKey] = crypto.randomBytes(32).toString('hex')
      app = (await createApp({ inMemoryDb: true })).app
    }, { timeout: 60000 })

    const files = [
      { url: '/ftp/acquisitions.md', disk: 'ftp/acquisitions.md' },
      { url: '/encryptionkeys/jwt.pub', disk: 'encryptionkeys/jwt.pub' },
      { url: '/encryptionkeys/premium.key', disk: 'encryptionkeys/premium.key' },
      { url: '/infrastructure/terraform/main.tf', disk: 'infrastructure/terraform/main.tf' },
      { url: '/.well-known/csaf/provider-metadata.json', disk: '.well-known/csaf/provider-metadata.json' }
    ]

    for (const file of files) {
      void it(`GET ${file.url} returns no file contents`, async () => {
        const contents = fs.readFileSync(file.disk, 'utf8')
        const res = await request(app).get(file.url)
        assert.equal(res.status, 404)
        assert.equal(res.text ?? '', '')
        assert.equal((res.text ?? '').includes(contents.slice(0, 40)), false)
      })
    }

    void it('GET directory listings return no index', async () => {
      for (const url of ['/ftp', '/ftp/', '/encryptionkeys', '/support/logs', '/infrastructure', '/.well-known']) {
        const res = await request(app).get(url)
        assert.equal(res.status, 404)
        assert.equal(res.text ?? '', '')
        assert.equal((res.text ?? '').includes('listing directory'), false)
      }
    })

    void it('GET /.well-known/security.txt still returns the generated policy', async () => {
      const res = await request(app).get('/.well-known/security.txt')
      assert.equal(res.status, 200)
      assert.match(res.text, /Contact:/)
    })

    void it('GET /api/Products still responds for the shop', async () => {
      const res = await request(app).get('/api/Products')
      assert.equal(res.status, 200)
      assert.ok(Array.isArray(res.body.data))
    })
  })
})
