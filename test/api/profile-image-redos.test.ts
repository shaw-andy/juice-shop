/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'
import * as datacache from '../../data/datacache'

const RESPONSE_BUDGET_MS = 1000
const SCRIPT_SRC_SEGMENT = ';script-src'
const UPLOAD_MARKER = 'solve/challenges/server-side'
// 20_000 segments is about 220KB, under busboy's default 1MB field limit.
// The profile-page expression is quadratic, so this size is several seconds.
const PROFILE_REPETITIONS = 20000
// Long enough for the upload expression to exceed the budget when the marker is absent.
const UPLOAD_STALL_LENGTH = 60000

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function repeatedScriptSrcImage () {
  return SCRIPT_SRC_SEGMENT.repeat(PROFILE_REPETITIONS) + UPLOAD_MARKER
}

function benignImageOfLength (length: number) {
  return 'b'.repeat(length - UPLOAD_MARKER.length) + UPLOAD_MARKER
}

async function openCustomerAccount (label: string) {
  const domain = config.get<string>('application.domain')
  const email = `${label}-${Date.now()}@${domain}`
  const password = 'placeholder-password'
  await register(app, { email, password })
  const { token } = await login(app, { email, password })
  await request(app)
    .post('/profile')
    .set('Cookie', `token=${token}`)
    .type('form')
    .send({ username: 'shop-customer' })
    .redirects(0)
  return { email, token }
}

async function postImageUrl (token: string, imageUrl: string) {
  const started = performance.now()
  const res = await request(app)
    .post('/profile/image/url')
    .set('Cookie', `token=${token}`)
    .field('imageUrl', imageUrl)
    .redirects(0)
  return { res, elapsedMs: performance.now() - started }
}

async function timeProfile (token: string) {
  const started = performance.now()
  try {
    const res = await request(app)
      .get('/profile')
      .set('Cookie', `token=${token}`)
    return { status: String(res.status), elapsedMs: performance.now() - started }
  } catch (error) {
    // The stored value is copied into Content-Security-Policy. Node's client
    // parser rejects that header once it passes the default limit, after the
    // server has already finished the profile-page check.
    const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'error'
    return { status: code, elapsedMs: performance.now() - started }
  }
}

function assertWithinBudget (elapsedMs: number, detail: string) {
  assert.ok(
    elapsedMs < RESPONSE_BUDGET_MS,
    `${detail} took ${elapsedMs.toFixed(0)}ms, budget is ${RESPONSE_BUDGET_MS}ms`
  )
}

void describe('profile image quadratic regular expressions', { concurrency: false }, () => {
  void it('GET /profile returns within one second after a stored repeated script-src image URL', async () => {
    const malicious = repeatedScriptSrcImage()
    const benign = benignImageOfLength(malicious.length)
    const { email, token } = await openCustomerAccount('profile-redos')
    const challenge = datacache.challenges.usernameXssChallenge
    assert.ok(challenge)
    challenge.solved = false

    const benignUpload = await postImageUrl(token, benign)
    assertWithinBudget(benignUpload.elapsedMs, `POST /profile/image/url for a benign image URL (status ${benignUpload.res.status})`)

    const benignProfile = await timeProfile(token)
    assertWithinBudget(benignProfile.elapsedMs, `GET /profile for a benign stored image URL (status ${benignProfile.status})`)

    const maliciousUpload = await postImageUrl(token, malicious)
    assertWithinBudget(maliciousUpload.elapsedMs, `POST /profile/image/url for a repeated script-src image URL (status ${maliciousUpload.res.status})`)

    const saved = await UserModel.findOne({ where: { email } })
    const maliciousProfile = await timeProfile(token)
    assertWithinBudget(
      maliciousProfile.elapsedMs,
      `GET /profile after saving profileImage length ${saved?.profileImage?.length ?? 0} of ${malicious.length} (status ${maliciousProfile.status})`
    )
  }, { timeout: 60000 })

  void it('GET /profile returns within one second when the username challenge is disabled and the username is set', async (t) => {
    const malicious = repeatedScriptSrcImage()
    const { email, token } = await openCustomerAccount('profile-redos-safe')
    const challenge = datacache.challenges.usernameXssChallenge
    assert.ok(challenge)
    challenge.solved = false
    const originalDisabledEnv = challenge.disabledEnv
    const originalGet = config.get.bind(config)
    t.mock.method(config, 'get', (setting: string) => {
      if (setting === 'challenges.safetyMode') {
        return 'enabled'
      }
      return originalGet(setting)
    })
    challenge.disabledEnv = 'Docker'

    try {
      const upload = await postImageUrl(token, malicious)
      assertWithinBudget(upload.elapsedMs, `POST /profile/image/url while the username challenge is disabled (status ${upload.res.status})`)
      const saved = await UserModel.findOne({ where: { email } })
      const profile = await timeProfile(token)
      assertWithinBudget(
        profile.elapsedMs,
        `GET /profile with the username challenge disabled after saving profileImage length ${saved?.profileImage?.length ?? 0} of ${malicious.length} (status ${profile.status})`
      )
    } finally {
      challenge.disabledEnv = originalDisabledEnv
    }
  }, { timeout: 60000 })

  void it('POST /profile/image/url returns within one second for a long image URL that omits the server-side marker', async () => {
    const { token } = await openCustomerAccount('upload-redos')
    const control = benignImageOfLength(UPLOAD_STALL_LENGTH)
    const stall = 'b'.repeat(UPLOAD_STALL_LENGTH)

    const controlUpload = await postImageUrl(token, control)
    assertWithinBudget(controlUpload.elapsedMs, `POST /profile/image/url for a long image URL that contains the marker (status ${controlUpload.res.status})`)

    const stallUpload = await postImageUrl(token, stall)
    assertWithinBudget(
      stallUpload.elapsedMs,
      `POST /profile/image/url for a ${stall.length}-character image URL without the marker (status ${stallUpload.res.status})`
    )
  }, { timeout: 60000 })
})
