/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'

const bypassUsername = '<<a|ascript>alert(`xss`)</script>'
const liveScript = '<script>alert(`xss`)</script>'
const encodedScript = '&lt;script&gt;alert(`xss`)&lt;/script&gt;'
const imageAddress = 'https://a.png; script-src \'unsafe-inline\' \'self\' \'unsafe-eval\''
const password = 'placeholder-password'
const fixedScriptSrc = 'script-src \'self\' \'unsafe-eval\''

let app: Express
let sequelize: Sequelize

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

function displayedUsername (html: string): string {
  const match = html.match(/<p style="margin-top: 8px;[^"]*">([\s\S]*?)<\/p>/)
  assert.ok(match, 'profile page did not render the username paragraph')
  return match[1]
}

function scriptSources (csp: string | undefined): string[] {
  return String(csp ?? '')
    .split(';')
    .map(part => part.trim())
    .filter(part => part === 'script-src' || part.startsWith('script-src '))
}

async function registerAndLogin (email: string, extra: Record<string, string> = {}) {
  const registered = await request(app)
    .post('/api/Users/')
    .set('content-type', 'application/json')
    .send({ email, password, passwordRepeat: password, ...extra })
  assert.equal(registered.status, 201)

  const loginRes = await request(app)
    .post('/rest/user/login')
    .set('content-type', 'application/json')
    .send({ email, password })
  assert.equal(loginRes.status, 200)
  return 'token=' + loginRes.body.authentication.token
}

void describe('stored script on the profile page', () => {
  void it('renders a saved username as that username', async () => {
    const cookie = await registerAndLogin('plain-profile@example.test')
    const updated = await request(app)
      .post('/profile')
      .set('Cookie', cookie)
      .type('form')
      .send({ username: 'Localhorst' })
      .redirects(0)

    assert.equal(updated.status, 302)
    const res = await request(app).get('/profile').set('Cookie', cookie)
    assert.equal(res.status, 200)
    assert.equal(displayedUsername(res.text), 'Localhorst')
  })

  void it('does not persist or render a bypassed username as a script element', async () => {
    const email = 'bypass-profile@example.test'
    const cookie = await registerAndLogin(email)
    const updated = await request(app)
      .post('/profile')
      .set('Cookie', cookie)
      .type('form')
      .send({ username: bypassUsername })
      .redirects(0)
    assert.equal(updated.status, 302)

    const image = await request(app)
      .post('/profile/image/url')
      .set('Cookie', cookie)
      .type('form')
      .send({ imageUrl: imageAddress })
      .redirects(0)
    assert.equal(image.status, 302)

    const stored = await UserModel.findOne({ where: { email } })
    assert.ok(stored)
    await stored.update({ role: 'admin' })
    await stored.reload()

    assert.equal(stored.username?.includes(liveScript), false)

    const res = await request(app).get('/profile').set('Cookie', cookie)
    assert.equal(res.status, 200)
    assert.equal(res.text.includes('value="admin"'), true)
    const shown = displayedUsername(res.text)
    assert.equal(shown.includes('<script'), false)
    assert.equal(shown.includes(liveScript), false)
    assert.deepEqual(scriptSources(res.headers['content-security-policy']), [fixedScriptSrc])
    assert.equal(String(res.headers['content-security-policy']).includes(imageAddress), false)
    assert.equal(String(res.headers['content-security-policy']).includes('unsafe-inline'), false)
  })

  void it('does not let a profile image address that cannot be fetched supply script-src', async () => {
    const cookie = await registerAndLogin('image-policy@example.test')
    const image = await request(app)
      .post('/profile/image/url')
      .set('Cookie', cookie)
      .type('form')
      .send({ imageUrl: imageAddress })
      .redirects(0)
    assert.equal(image.status, 302)

    const res = await request(app).get('/profile').set('Cookie', cookie)
    assert.equal(res.status, 200)
    assert.deepEqual(scriptSources(res.headers['content-security-policy']), [fixedScriptSrc])
    assert.equal(String(res.headers['content-security-policy']).includes(imageAddress), false)
    assert.equal(String(res.headers['content-security-policy']).includes('unsafe-inline'), false)
  })

  void it('encodes a stored script username when the profile page is rendered', async () => {
    const email = 'stored-script@example.test'
    const cookie = await registerAndLogin(email)
    await sequelize.query('UPDATE Users SET username = :username, profileImage = :profileImage WHERE email = :email', {
      replacements: { username: liveScript, profileImage: imageAddress, email }
    })

    const res = await request(app).get('/profile').set('Cookie', cookie)
    assert.equal(res.status, 200)
    assert.equal(displayedUsername(res.text), encodedScript)
    assert.equal(res.text.includes(liveScript), false)
    assert.deepEqual(scriptSources(res.headers['content-security-policy']), [fixedScriptSrc])
    assert.equal(String(res.headers['content-security-policy']).includes('unsafe-inline'), false)
  })

  void it('does not accept a script username or a script policy through registration', async () => {
    const email = 'register-script@example.test'
    const cookie = await registerAndLogin(email, {
      username: bypassUsername,
      profileImage: imageAddress
    })
    const stored = await UserModel.findOne({ where: { email } })
    assert.ok(stored)
    assert.equal(stored.username?.includes(liveScript), false)

    const res = await request(app).get('/profile').set('Cookie', cookie)
    assert.equal(res.status, 200)
    assert.equal(displayedUsername(res.text).includes('<script'), false)
    assert.deepEqual(scriptSources(res.headers['content-security-policy']), [fixedScriptSrc])
    assert.equal(String(res.headers['content-security-policy']).includes(imageAddress), false)
  })
})
