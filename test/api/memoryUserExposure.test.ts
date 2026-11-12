/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { MemoryModel } from '../../models/memory'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const FIXTURE_EMAIL = 'memory-exposure-fixture@example.test'
const FIXTURE_PASSWORD = 'placeholder-password'
const FIXTURE_TOTP = 'placeholder-totp-secret'
const FIXTURE_CAPTION = 'memory-exposure-fixture'
const CREDENTIAL_FIELDS = ['password', 'totpSecret']

let app: Express
let storedPassword: string | undefined
let storedTotp: string | undefined

before(async () => {
  const result = await createTestApp()
  app = result.app
  const created = await UserModel.create({
    email: FIXTURE_EMAIL,
    password: FIXTURE_PASSWORD,
    totpSecret: FIXTURE_TOTP
  })
  const stored = await UserModel.findByPk(created.id)
  storedPassword = stored?.password
  storedTotp = stored?.totpSecret
  await MemoryModel.create({
    caption: FIXTURE_CAPTION,
    imagePath: 'assets/public/images/uploads/memory-exposure-fixture.png',
    UserId: created.id
  })
}, { timeout: 60000 })

function credentialPaths (value: unknown, path = ''): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => credentialPaths(item, `${path}[${index}]`))
  }
  if (value !== null && typeof value === 'object') {
    const found: string[] = []
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = path === '' ? key : `${path}.${key}`
      if (CREDENTIAL_FIELDS.includes(key)) found.push(childPath)
      found.push(...credentialPaths(child, childPath))
    }
    return found
  }
  return []
}

function assertMemoriesHideCredentials (res: Response) {
  assert.equal(res.status, 200)
  const memories: unknown = res.body?.data
  assert.ok(Array.isArray(memories))
  assert.ok(memories.length > 1)
  const fixture = memories.find((memory: { caption?: string }) => memory.caption === FIXTURE_CAPTION) as { User?: Record<string, unknown> } | undefined
  assert.ok(fixture, 'fixture memory is returned')
  const user = fixture.User
  const paths = credentialPaths(memories)
  const passwordMatchesStored = user != null && Object.hasOwn(user, 'password') && user.password === storedPassword
  const totpMatchesStored = user != null && Object.hasOwn(user, 'totpSecret') && user.totpSecret === storedTotp
  const storedPasswordIsHash = storedPassword === security.hash(FIXTURE_PASSWORD)
  assert.equal(
    paths.length,
    0,
    `paths=${paths.join('|')} passwordMatchesStored=${passwordMatchesStored} totpMatchesStored=${totpMatchesStored} storedPasswordIsHash=${storedPasswordIsHash} memoryCount=${memories.length}`
  )
}

void describe('/rest/memories user exposure', () => {
  void it('anonymous GET /rest/memories does not include password hashes or TOTP secrets', async () => {
    const res = await request(app).get('/rest/memories')
    assertMemoriesHideCredentials(res)
  })

  void it('anonymous GET /rest/memories/ does not include password hashes or TOTP secrets', async () => {
    const res = await request(app).get('/rest/memories/')
    assertMemoriesHideCredentials(res)
  })

  void it('authorized GET /rest/memories does not include password hashes or TOTP secrets', async () => {
    const res = await request(app)
      .get('/rest/memories')
      .set('Authorization', 'Bearer ' + security.authorize())
    assertMemoriesHideCredentials(res)
  })
})
