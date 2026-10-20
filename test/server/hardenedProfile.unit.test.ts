/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import path from 'node:path'
import { afterEach, describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../../lib/insecurity'
import { blockExposedFileMounts, MissingSigningSecretsError, SIGNING_SECRET_ENV } from '../../lib/hardenedProfile'

const TRAINING_HMAC = '6be13e2feeada221f29134db71c0ab0be0e27eccfc0fb436ba4096ba73aafb20'

function clearProfileEnv () {
  delete process.env.JUICESHOP_PROFILE
  for (const name of Object.values(SIGNING_SECRET_ENV)) {
    delete process.env[name]
  }
}

function restoreTrainingSecrets () {
  clearProfileEnv()
  security.loadHardenedSecrets()
}

afterEach(() => {
  restoreTrainingSecrets()
})

void describe('hardened profile signing secrets', () => {
  void it('keeps the training cookie secret and HMAC when the profile is off', () => {
    security.loadHardenedSecrets()
    assert.equal(security.cookieSecret(), 'kekse')
    assert.equal(security.hmac('admin123'), TRAINING_HMAC)
  })

  void it('refuses to load when the hardened profile is missing signing secrets', () => {
    process.env.JUICESHOP_PROFILE = 'hardened'
    const canary = 'canary-cookie-secret-do-not-log'
    process.env[SIGNING_SECRET_ENV.cookieSecret] = canary
    assert.throws(() => { security.loadHardenedSecrets() }, (error: unknown) => {
      assert.ok(error instanceof MissingSigningSecretsError)
      assert.match(error.message, /JUICESHOP_JWT_PRIVATE_KEY/)
      assert.match(error.message, /JUICESHOP_JWT_PUBLIC_KEY/)
      assert.match(error.message, /JUICESHOP_HMAC_KEY/)
      assert.equal(error.message.includes(canary), false)
      return true
    })
    assert.equal(security.cookieSecret(), 'kekse')
    assert.equal(security.hmac('admin123'), TRAINING_HMAC)
  })

  void it('signs with the environment keypair and HMAC on the hardened profile', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    })
    process.env.JUICESHOP_PROFILE = 'hardened'
    process.env[SIGNING_SECRET_ENV.jwtPrivateKey] = privateKey.replace(/\n/g, '\\n')
    process.env[SIGNING_SECRET_ENV.jwtPublicKey] = publicKey
    process.env[SIGNING_SECRET_ENV.cookieSecret] = 'hardened-cookie-secret'
    process.env[SIGNING_SECRET_ENV.hmacKey] = 'hardened-hmac-secret'
    security.loadHardenedSecrets()

    const token = security.authorize({ id: 1 })
    assert.equal(security.verify(token), true)
    assert.equal(security.cookieSecret(), 'hardened-cookie-secret')
    assert.notEqual(security.hmac('admin123'), TRAINING_HMAC)
    assert.equal(security.publicKey.includes('BEGIN RSA PUBLIC KEY'), true)
    assert.equal(security.publicKey.includes(privateKey), false)
  })

  void it('exits during startup when the hardened profile is missing signing secrets', () => {
    const env = { ...process.env, NODE_ENV: 'production', JUICESHOP_PROFILE: 'hardened' }
    const canary = 'canary-cookie-secret-do-not-log'
    env[SIGNING_SECRET_ENV.cookieSecret] = canary
    delete env[SIGNING_SECRET_ENV.jwtPrivateKey]
    delete env[SIGNING_SECRET_ENV.jwtPublicKey]
    delete env[SIGNING_SECRET_ENV.hmacKey]
    const result = spawnSync(process.execPath, [
      '--import', 'tsx',
      '--input-type=module',
      '--eval', 'import "./server.ts"'
    ], {
      cwd: path.resolve('.'),
      env,
      encoding: 'utf8',
      timeout: 60000
    })
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
    assert.equal(result.status, 1, output)
    assert.match(output, /JUICESHOP_JWT_PRIVATE_KEY/)
    assert.equal(output.includes(canary), false)
    assert.equal(output.includes('BEGIN RSA PRIVATE KEY'), false)
  })
})

void describe('blockExposedFileMounts', () => {
  const mounts = ['/ftp', '/ftp/acquisitions.md', '/encryptionkeys', '/encryptionkeys/jwt.pub', '/support/logs', '/support/logs/access.log', '/infrastructure', '/infrastructure/terraform/main.tf', '/.well-known', '/.well-known/csaf/provider-metadata.json']

  for (const pathname of mounts) {
    void it(`returns an empty 404 for ${pathname}`, () => {
      const res: any = {
        status (code: number) { res.statusCode = code; return res },
        type () { return res },
        end: mock.fn()
      }
      const next = mock.fn<NextFunction>()
      blockExposedFileMounts()({ path: pathname } as Request, res as Response, next)
      assert.equal(res.statusCode, 404)
      assert.equal(res.end.mock.calls.length, 1)
      assert.equal(res.end.mock.calls[0].arguments.length, 0)
      assert.equal(next.mock.calls.length, 0)
    })
  }

  void it('leaves unrelated paths alone', () => {
    const res: any = {
      status: mock.fn(),
      end: mock.fn()
    }
    const next = mock.fn<NextFunction>()
    blockExposedFileMounts()({ path: '/rest/user/login' } as Request, res as Response, next)
    assert.equal(next.mock.calls.length, 1)
    assert.equal(res.end.mock.calls.length, 0)
  })
})
