/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { isHardened, signingSecretsFromEnv, MissingSigningSecretsError, SIGNING_SECRET_ENV, EXPOSED_FILE_MOUNTS } from '../../lib/hardenedProfile'

const completeEnv = {
  JUICESHOP_JWT_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----',
  JUICESHOP_JWT_PUBLIC_KEY: '-----BEGIN PUBLIC KEY-----\\ndef\\n-----END PUBLIC KEY-----',
  JUICESHOP_COOKIE_SECRET: 'cookie-secret',
  JUICESHOP_HMAC_KEY: 'hmac-key'
}

void describe('hardenedProfile', () => {
  void describe('isHardened', () => {
    void it('is false when JUICESHOP_PROFILE is not set', () => {
      assert.equal(isHardened({}), false)
    })

    void it('is false for any other profile value', () => {
      assert.equal(isHardened({ JUICESHOP_PROFILE: 'training' }), false)
      assert.equal(isHardened({ JUICESHOP_PROFILE: 'Hardened' }), false)
    })

    void it('is true for JUICESHOP_PROFILE=hardened', () => {
      assert.equal(isHardened({ JUICESHOP_PROFILE: 'hardened' }), true)
    })
  })

  void describe('signingSecretsFromEnv', () => {
    void it('returns all secrets with escaped line breaks restored', () => {
      const secrets = signingSecretsFromEnv(completeEnv)
      assert.equal(secrets.jwtPrivateKey, '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----')
      assert.equal(secrets.jwtPublicKey, '-----BEGIN PUBLIC KEY-----\ndef\n-----END PUBLIC KEY-----')
      assert.equal(secrets.cookieSecret, 'cookie-secret')
      assert.equal(secrets.hmacKey, 'hmac-key')
    })

    void it('throws naming every missing variable when none are set', () => {
      assert.throws(() => signingSecretsFromEnv({}), (err: unknown) => {
        assert.ok(err instanceof MissingSigningSecretsError)
        assert.deepEqual(err.missing, Object.values(SIGNING_SECRET_ENV))
        for (const name of Object.values(SIGNING_SECRET_ENV)) {
          assert.ok(err.message.includes(name))
        }
        return true
      })
    })

    void it('throws naming only the missing or blank variables', () => {
      const env = { ...completeEnv, JUICESHOP_HMAC_KEY: '   ', JUICESHOP_COOKIE_SECRET: undefined }
      assert.throws(() => signingSecretsFromEnv(env), (err: unknown) => {
        assert.ok(err instanceof MissingSigningSecretsError)
        assert.deepEqual(err.missing, ['JUICESHOP_COOKIE_SECRET', 'JUICESHOP_HMAC_KEY'])
        return true
      })
    })

    void it('never echoes secret values in the error message', () => {
      const env = { ...completeEnv, JUICESHOP_HMAC_KEY: '' }
      assert.throws(() => signingSecretsFromEnv(env), (err: Error) => {
        assert.ok(!err.message.includes('cookie-secret'))
        assert.ok(!err.message.includes('abc'))
        return true
      })
    })
  })

  void describe('EXPOSED_FILE_MOUNTS', () => {
    void it('covers every mount the hardened profile must stop serving', () => {
      assert.deepEqual([...EXPOSED_FILE_MOUNTS], ['/ftp', '/encryptionkeys', '/support/logs', '/infrastructure', '/.well-known'])
    })
  })

  void describe('lib/insecurity on the hardened profile', () => {
    const loadInsecurity = (env: NodeJS.ProcessEnv) => spawnSync(process.execPath, ['--import', 'tsx', '-e', 'import("./lib/insecurity.ts")'], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH, NODE_ENV: 'test', ...env },
      encoding: 'utf8'
    })

    void it('fails closed when signing secrets are missing', { timeout: 30000 }, () => {
      const result = loadInsecurity({ JUICESHOP_PROFILE: 'hardened' })
      assert.notEqual(result.status, 0)
      assert.ok(result.stderr.includes('MissingSigningSecretsError'))
      assert.ok(result.stderr.includes('JUICESHOP_JWT_PRIVATE_KEY'))
    })

    void it('loads with training keys when the profile is not hardened', { timeout: 30000 }, () => {
      const result = loadInsecurity({})
      assert.equal(result.status, 0, result.stderr)
    })
  })
})
