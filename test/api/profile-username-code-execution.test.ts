/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'
import isHeroku from '../../lib/is-heroku'
import * as utils from '../../lib/utils'

const probe = '__profileUsernameEvalProbe'
const placeholderPassword = 'placeholder-password'

let app: Express
let userSerial = 0

function resetProbe (): void {
  globalThis[probe] = 0
}

function readProbe (): unknown {
  return globalThis[probe]
}

function directUsername (): string {
  return `#{(globalThis.${probe} = globalThis.process.pid)}`
}

function sideEffectThenThrowUsername (): string {
  return `#{(globalThis.${probe} = globalThis.process.pid, null.profileUsernameEvalBoom)}`
}

function unalignedUsername (): string {
  return `AB(globalThis.${probe}=globalThis.process.pid,'#{1}')Z`
}

function compiledResultUsername (): string {
  return `#{String.fromCharCode(35,123)+'(globalThis.${probe}=globalThis.process.pid)'+String.fromCharCode(125)}`
}

function displayedUsername (html: string): string | undefined {
  const match = /text-align:\s*center;?">([^<]*)</.exec(html)
  return match?.[1]
}

function storedUsername (html: string): string | undefined {
  const match = /id="username"[^>]*value="([^"]*)"/.exec(html)
  return match?.[1]
}

async function registerAndLogin (username?: string): Promise<string> {
  userSerial += 1
  const email = `profile-eval-${userSerial}@juice-sh.op`
  const body: { email: string, password: string, passwordRepeat: string, username?: string } = {
    email,
    password: placeholderPassword,
    passwordRepeat: placeholderPassword
  }
  if (username !== undefined) {
    body.username = username
  }
  const created = await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send(body)
  assert.equal(created.status, 201)
  if (username !== undefined) {
    assert.equal(created.body.data.username, username)
  }
  const { token } = await login(app, { email, password: placeholderPassword })
  return token as string
}

async function updateUsername (token: string, username: string): Promise<void> {
  const res = await request(app)
    .post('/profile')
    .set('Cookie', `token=${token}`)
    .type('form')
    .send({ username })
    .redirects(0)
  assert.equal(res.status, 302)
  assert.equal(readProbe(), 0)
}

async function renderProfile (token: string, username: string): Promise<void> {
  const res = await request(app)
    .get('/profile')
    .set('Cookie', `token=${token}`)

  assert.equal(readProbe(), 0)
  assert.equal(res.status, 200)
  assert.equal(storedUsername(res.text), username)
  assert.equal(displayedUsername(res.text), username)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  assert.equal(isHeroku(), false)
  assert.equal(utils.isDocker(), false)
  assert.equal(utils.isChallengeEnabled(challenges.usernameXssChallenge), true)
  assert.equal(utils.isChallengeEnabled(challenges.persistedXssUserChallenge), true)
}, { timeout: 60000 })

void describe('profile username is text, not code', () => {
  void it('GET /profile does not execute a hash-brace username saved by POST /profile', async () => {
    const username = directUsername()
    assert.ok(username.length < 255)
    resetProbe()
    const token = await registerAndLogin()
    await updateUsername(token, username)
    await renderProfile(token, username)
  })

  void it('GET /profile does not keep a side effect when evaluation of the username throws', async () => {
    const username = sideEffectThenThrowUsername()
    assert.ok(username.length < 255)
    resetProbe()
    const token = await registerAndLogin()
    await updateUsername(token, username)
    await renderProfile(token, username)
  })

  void it('GET /profile does not execute a hash-brace expression that does not start at the first character', async () => {
    const username = unalignedUsername()
    assert.ok(username.length < 255)
    resetProbe()
    const token = await registerAndLogin()
    await updateUsername(token, username)
    await renderProfile(token, username)
  })

  void it('GET /profile does not compile an evaluated username back into the profile template', async () => {
    const username = compiledResultUsername()
    assert.ok(username.length < 255)
    resetProbe()
    const token = await registerAndLogin()
    await updateUsername(token, username)
    await renderProfile(token, username)
  })

  void it('GET /profile does not execute a hash-brace username stored when the user is registered', async () => {
    const username = directUsername()
    assert.ok(username.length < 255)
    resetProbe()
    const token = await registerAndLogin(username)
    assert.equal(readProbe(), 0)
    await renderProfile(token, username)
  })
})
