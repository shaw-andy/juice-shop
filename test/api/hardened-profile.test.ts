/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import type { Express } from 'express'
import { EXPOSED_FILE_MOUNTS, SIGNING_SECRET_ENV } from '../../lib/hardenedProfile'

const verifyWith = (token: string, key: string) => (jws.verify as unknown as (token: string, key: string) => boolean)(token, key)

/* The profile and its secrets must be in place before server.ts and lib/insecurity.ts are loaded, so those are imported lazily below. */
const generateKeyPair = () => crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
})
const keys = generateKeyPair()
const hmacKey = crypto.randomBytes(16).toString('hex')

process.env.JUICESHOP_PROFILE = 'hardened'
process.env[SIGNING_SECRET_ENV.jwtPrivateKey] = keys.privateKey
process.env[SIGNING_SECRET_ENV.jwtPublicKey] = keys.publicKey
process.env[SIGNING_SECRET_ENV.cookieSecret] = crypto.randomBytes(16).toString('hex')
process.env[SIGNING_SECRET_ENV.hmacKey] = hmacKey

let app: Express
let security: typeof import('../../lib/insecurity')

before(async () => {
  security = await import('../../lib/insecurity')
  const { createTestApp } = await import('./helpers/setup')
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const blockedPaths = [
  ...EXPOSED_FILE_MOUNTS,
  '/ftp/legal.md',
  '/ftp/quarantine/juicy_malware_linux_amd_64.url',
  '/FTP/legal.md',
  '/encryptionkeys/jwt.pub',
  '/encryptionkeys/premium.key',
  '/support/logs/access.log',
  '/infrastructure/terraform',
  '/.well-known/csaf/provider-metadata.json',
  '/.well-known/csaf/index.txt'
]

void describe('Hardened profile', () => {
  void describe('exposed file mounts', () => {
    for (const path of blockedPaths) {
      void it(`GET ${path} returns an empty 404`, async () => {
        const res = await request(app).get(path)
        assert.equal(res.status, 404)
        assert.equal(res.text, '')
      })
    }

    void it('GET /.well-known/security.txt is still generated, without the CSAF pointer', async () => {
      const res = await request(app).get('/.well-known/security.txt')
      assert.equal(res.status, 200)
      assert.ok(res.headers['content-type']?.includes('text/plain'))
      assert.ok(res.text.includes('Contact: '))
      assert.ok(!res.text.includes('Csaf: '))
    })

    void it('GET / still serves the Angular client', async () => {
      const res = await request(app).get('/')
      assert.equal(res.status, 200)
      assert.ok(res.text.includes('main.js'))
    })
  })

  void describe('signing secrets', () => {
    void it('issues login tokens signed with the environment-provided key', async () => {
      const res = await request(app)
        .post('/rest/user/login')
        .set('content-type', 'application/json')
        .send({ email: 'jim@juice-sh.op', password: 'ncc-1701' })
      assert.equal(res.status, 200)
      const token: string = res.body.authentication.token
      assert.equal(verifyWith(token, keys.publicKey), true)
      assert.equal(verifyWith(token, fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')), false)
      assert.equal(jws.decode(token)?.payload?.data?.email, 'jim@juice-sh.op')
    })

    void it('rejects tokens signed with any other key', () => {
      const otherKeys = generateKeyPair()
      const forged = jwt.sign({ data: { email: 'admin@juice-sh.op' } }, otherKeys.privateKey, { algorithm: 'RS256' })
      assert.equal(security.verify(forged), false)
      assert.equal(security.verify(security.authorize({ data: { email: 'jim@juice-sh.op' } })), true)
    })

    void it('derives HMACs from the environment-provided key', () => {
      const expected = crypto.createHmac('sha256', hmacKey).update('admin123').digest('hex')
      assert.equal(security.hmac('admin123'), expected)
      assert.notEqual(security.hmac('admin123'), '6be13e2feeada221f29134db71c0ab0be0e27eccfc0fb436ba4096ba73aafb20')
    })

    void it('exposes the environment-provided cookie secret instead of the training one', () => {
      assert.equal(security.cookieSecret, process.env[SIGNING_SECRET_ENV.cookieSecret])
      assert.notEqual(security.cookieSecret, 'kekse')
    })
  })
})
