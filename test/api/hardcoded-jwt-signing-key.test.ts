/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import request from 'supertest'
import type { Express, Request } from 'express'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

const forgedAdminEmail = 'forged-admin@example.test'
const forgedDeluxeEmail = 'forged-deluxe@example.test'
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const skippedDirectories = new Set(['node_modules', '.git', 'coverage', 'dist', 'build'])

interface EmbeddedKey {
  pem: string
  sources: string[]
}

function unescapePem (raw: string) {
  if (!raw.includes('\\n')) {
    return raw
  }
  return raw.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n').replace(/\\r/g, '\r')
}

function walkFiles (dir: string, out: string[]) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (skippedDirectories.has(entry.name)) {
      continue
    }
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      walkFiles(full, out)
    } else if (entry.isFile()) {
      out.push(full)
    }
  }
}

function loadEmbeddedKeys (): EmbeddedKey[] {
  const files: string[] = []
  walkFiles(repositoryRoot, files)
  files.sort()
  const byPem = new Map<string, string[]>()
  const pemPattern = /-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |ENCRYPTED )?PRIVATE KEY-----/g
  for (const file of files) {
    const buf = fs.readFileSync(file)
    if (buf.length > 2_000_000 || buf.includes(0)) {
      continue
    }
    const text = buf.toString('utf8')
    if (!text.includes('PRIVATE KEY')) {
      continue
    }
    pemPattern.lastIndex = 0
    for (const match of text.matchAll(pemPattern)) {
      const pem = unescapePem(match[0])
      try {
        crypto.createPrivateKey(pem)
      } catch {
        continue
      }
      const sources = byPem.get(pem) ?? []
      sources.push(path.relative(repositoryRoot, file))
      byPem.set(pem, sources)
    }
  }
  return [...byPem.entries()].map(([pem, sources]) => ({ pem, sources }))
}

function attackerKey (): EmbeddedKey {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  const exported = privateKey.export({ type: 'pkcs1', format: 'pem' })
  const pem = typeof exported === 'string' ? exported : exported.toString('utf8')
  return { pem, sources: [] }
}

const embeddedKeys = loadEmbeddedKeys()

function keysUnderTest (): EmbeddedKey[] {
  return embeddedKeys.length > 0 ? embeddedKeys : [attackerKey()]
}

function sourceLabel (key: EmbeddedKey) {
  return key.sources.length > 0 ? key.sources.join(', ') : 'generated signing key'
}

function signRs256 (pem: string, data: Record<string, unknown>) {
  const token = jwt.sign({ data }, pem, { algorithm: 'RS256' })
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString()) as { alg?: string }
  assert.equal(header.alg, 'RS256')
  return token
}

function publicPem (privatePem: string) {
  const exported = crypto.createPublicKey(privatePem).export({ type: 'pkcs1', format: 'pem' })
  return typeof exported === 'string' ? exported : exported.toString('utf8')
}

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('hardcoded RSA session signing key', { concurrency: false }, () => {
  void it('rejects RS256 admin tokens signed with a private key found in the repository', async () => {
    const issued = security.authorize({ data: { role: security.roles.admin, email: 'server-issued@example.test' } })
    const allowed = await request(app).get('/api/Users').set('Authorization', `Bearer ${issued}`)
    assert.equal(allowed.status, 200)

    const published = await request(app).get('/encryptionkeys/jwt.pub')
    assert.equal(published.status, 200)

    const failures: string[] = []
    for (const key of keysUnderTest()) {
      const token = signRs256(key.pem, { role: security.roles.admin, email: forgedAdminEmail, id: 1 })
      const label = sourceLabel(key)
      for (const route of ['/api/Users', '/api/Complaints', '/rest/user/authentication-details']) {
        const res = await request(app).get(route).set('Authorization', `Bearer ${token}`)
        if (res.status !== 401) {
          failures.push(`${label} was accepted by ${route} with status ${res.status}`)
        }
      }
      if (jws.verify(token, published.text)) {
        failures.push(`${label} verifies with the public key served at /encryptionkeys/jwt.pub`)
      }
      if (security.verify(token)) {
        failures.push(`${label} was accepted by security.verify`)
      }
    }
    assert.equal(failures.length, 0, failures.join('\n'))
  })

  void it('does not install a forged RS256 token as the logged-in user', async () => {
    const failures: string[] = []
    for (const key of keysUnderTest()) {
      const token = signRs256(key.pem, { role: security.roles.admin, email: forgedAdminEmail, id: 1 })
      const label = sourceLabel(key)
      await request(app).get('/api/Users').set('Authorization', `Bearer ${token}`)
      if (security.authenticatedUsers.get(token)?.data?.role === security.roles.admin) {
        failures.push(`${label} was stored as an admin session`)
      }
      const who = await request(app)
        .get('/rest/user/whoami')
        .query({ fields: 'role,email' })
        .set('Cookie', `token=${token}`)
      const user = who.body?.user as { role?: string, email?: string } | undefined
      if (user?.role === security.roles.admin || user?.email === forgedAdminEmail) {
        failures.push(`${label} was returned by /rest/user/whoami`)
      }
    }
    assert.equal(failures.length, 0, failures.join('\n'))
  })

  void it('does not treat a deluxe proof built from a repository private key as deluxe', async () => {
    const failures: string[] = []
    for (const key of keysUnderTest()) {
      const deluxeToken = crypto.createHmac('sha256', key.pem).update(forgedDeluxeEmail + security.roles.deluxe).digest('hex')
      const token = signRs256(key.pem, {
        role: security.roles.deluxe,
        email: forgedDeluxeEmail,
        deluxeToken
      })
      const label = sourceLabel(key)
      const res = await request(app).get('/rest/deluxe-membership').set('Authorization', `Bearer ${token}`)
      if (res.body?.error !== 'You are not eligible for deluxe membership!') {
        failures.push(`${label} was treated as deluxe (${String(res.status)})`)
      }
      if (security.isDeluxe({ headers: { authorization: `Bearer ${token}` } } as Request)) {
        failures.push(`${label} passed security.isDeluxe`)
      }
    }
    assert.equal(failures.length, 0, failures.join('\n'))
  })

  void it('rejects accounting tokens signed with a repository private key', async () => {
    const failures: string[] = []
    for (const key of keysUnderTest()) {
      const token = signRs256(key.pem, { role: security.roles.accounting, email: 'forged-accounting@example.test' })
      const label = sourceLabel(key)
      let nextCalled = false
      const accountingResponse = {
        status: (_code: number) => accountingResponse,
        json: () => {}
      }
      security.isAccounting()(
        { headers: { authorization: `Bearer ${token}` } } as Request,
        accountingResponse as unknown as Parameters<ReturnType<typeof security.isAccounting>>[1],
        () => { nextCalled = true }
      )
      if (nextCalled) {
        failures.push(`${label} was authorized by isAccounting`)
      }
      const res = await request(app).get('/api/Quantitys/1').set('Authorization', `Bearer ${token}`)
      if (res.status !== 403 || res.body?.error !== 'Malicious activity detected') {
        failures.push(`${label} was not refused by the accounting route (${String(res.status)})`)
      }
    }
    assert.equal(failures.length, 0, failures.join('\n'))
  })

  void it('does not sign session tokens with a private key found in the repository', () => {
    const failures: string[] = []
    for (const key of keysUnderTest()) {
      const issued = security.authorize({ data: { role: security.roles.admin, email: forgedAdminEmail } })
      if (jws.verify(issued, publicPem(key.pem))) {
        failures.push(`authorize() signed a session token with ${sourceLabel(key)}`)
      }
    }
    assert.equal(failures.length, 0, failures.join('\n'))
  })
})
