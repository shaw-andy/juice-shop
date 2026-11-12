/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import { saveLoginIp } from '../../routes/saveLoginIp'
import { UserModel } from '../../models/user'

const placeholderPassword = 'placeholder-password'
const challengePayload = '<iframe src="javascript:alert(`xss`)">'
const scriptPayload = '<script>marker</script><img src="x" onerror="marker">'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function hasMarkup (value: unknown): boolean {
  const text = String(value ?? '')
  return /[<>]/.test(text) || /onerror/i.test(text) || /javascript:/i.test(text)
}

async function storedLastLoginIp (email: string): Promise<string | undefined> {
  const user = await UserModel.findOne({ where: { email } })
  return user?.lastLoginIp
}

async function loginTokenLastLoginIp (email: string): Promise<unknown> {
  const authentication = await login(app, { email, password: placeholderPassword })
  const decoded = security.decode(authentication.token) as { data?: { lastLoginIp?: unknown } } | undefined
  return decoded?.data?.lastLoginIp
}

void describe('last login IP header must not be stored or reissued as HTML', () => {
  void it('requires the HTTP-header XSS challenge to be enabled, which is the default outside Docker and Heroku', () => {
    assert.equal(utils.isChallengeEnabled(challenges.httpHeaderXssChallenge), true)
  })

  void it('does not keep a True-Client-IP markup value on the authorized user or copy it into the next login token', async () => {
    const email = 'login-ip-header@example.test'
    const bystander = 'login-ip-bystander@example.test'
    await register(app, { email, password: placeholderPassword })
    await register(app, { email: bystander, password: placeholderPassword })
    const bystanderBefore = await storedLastLoginIp(bystander)
    const first = await login(app, { email, password: placeholderPassword })

    const saved = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + first.token,
        'true-client-ip': challengePayload
      })

    const stored = await storedLastLoginIp(email)
    const bystanderAfter = await storedLastLoginIp(bystander)
    assert.equal(bystanderAfter, bystanderBefore)
    assert.equal(hasMarkup(saved.body?.lastLoginIp), false, JSON.stringify(saved.body?.lastLoginIp))
    assert.equal(hasMarkup(stored), false, JSON.stringify(stored))

    const issued = await loginTokenLastLoginIp(email)
    assert.equal(hasMarkup(issued), false, JSON.stringify(issued))
  })

  void it('does not keep a script or event-handler header on the authorized user or copy it into the next login token', async () => {
    const email = 'login-ip-script@example.test'
    await register(app, { email, password: placeholderPassword })
    const first = await login(app, { email, password: placeholderPassword })

    const saved = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + first.token,
        'true-client-ip': scriptPayload
      })

    const stored = await storedLastLoginIp(email)
    assert.equal(hasMarkup(saved.body?.lastLoginIp), false, JSON.stringify(saved.body?.lastLoginIp))
    assert.equal(hasMarkup(stored), false, JSON.stringify(stored))

    const issued = await loginTokenLastLoginIp(email)
    assert.equal(hasMarkup(issued), false, JSON.stringify(issued))
  })

  void it('does not keep markup when Node joins repeated True-Client-IP headers into one value', async () => {
    const email = 'login-ip-joined@example.test'
    await register(app, { email, password: placeholderPassword })
    const first = await login(app, { email, password: placeholderPassword })
    const joined = `${challengePayload}, ${scriptPayload}`

    const saved = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + first.token,
        'true-client-ip': joined
      })

    const stored = await storedLastLoginIp(email)
    assert.equal(hasMarkup(saved.body?.lastLoginIp), false, JSON.stringify(saved.body?.lastLoginIp))
    assert.equal(hasMarkup(stored), false, JSON.stringify(stored))
    assert.equal(hasMarkup(await loginTokenLastLoginIp(email)), false)
  })

  void it('does not keep markup from the first value when True-Client-IP is an array', async () => {
    const email = 'login-ip-array@example.test'
    const bystander = 'login-ip-array-bystander@example.test'
    await register(app, { email, password: placeholderPassword })
    await register(app, { email: bystander, password: placeholderPassword })
    const bystanderBefore = await storedLastLoginIp(bystander)
    const first = await login(app, { email, password: placeholderPassword })
    const handler = saveLoginIp()
    let failure: unknown
    const response: { body?: { lastLoginIp?: unknown }, status?: number } = {}

    await handler(
      {
        headers: {
          authorization: 'Bearer ' + first.token,
          'true-client-ip': [scriptPayload, '203.0.113.10']
        },
        socket: { remoteAddress: '127.0.0.1' }
      } as never,
      {
        json (body: { lastLoginIp?: unknown }) { response.body = body },
        sendStatus (status: number) { response.status = status }
      } as never,
      (error: unknown) => { failure = error }
    )

    if (failure instanceof Error) {
      throw failure
    }
    const stored = await storedLastLoginIp(email)
    assert.equal(await storedLastLoginIp(bystander), bystanderBefore)
    assert.equal(hasMarkup(response.body?.lastLoginIp), false, JSON.stringify(response.body?.lastLoginIp))
    assert.equal(hasMarkup(stored), false, JSON.stringify(stored))
    assert.equal(hasMarkup(await loginTokenLastLoginIp(email)), false)
  })
})
