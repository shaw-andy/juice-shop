/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import { type AddressInfo } from 'node:net'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as datacache from '../../data/datacache'
import * as utils from '../../lib/utils'
import { UserModel } from '../../models/user'

const password = 'placeholder-password'
const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
const marker = 'csp-probe.example'

function callerImageUrl (suffix: string) {
  return `${suffix}; script-src 'unsafe-inline' http://${marker}`
}

function scriptSrcDirectives (csp: string | undefined) {
  return (csp ?? '').split(';').map((part) => part.trim()).filter((part) => part.toLowerCase().startsWith('script-src'))
}

function usernameParagraph (html: string) {
  const match = html.match(/<p style="margin-top: 8px;[^"]*">([\s\S]*?)<\/p>/)
  assert.ok(match, 'profile page should include the username paragraph')
  return match[1]
}

describe('profile image content security policy', { concurrency: 1 }, () => {
  let app: Express
  let imageServer: http.Server
  let imagePort: number
  let usernameChallengeEnv: string | null
  let persistedXssChallengeEnv: string | null

  before(async () => {
    const result = await createTestApp()
    app = result.app
    usernameChallengeEnv = datacache.challenges.usernameXssChallenge.disabledEnv
    persistedXssChallengeEnv = datacache.challenges.persistedXssUserChallenge.disabledEnv
    datacache.challenges.usernameXssChallenge.disabledEnv = null
    datacache.challenges.persistedXssUserChallenge.disabledEnv = null

    imageServer = http.createServer((req, res) => {
      const url = req.url ?? ''
      if (url.includes('non-ok')) {
        res.statusCode = 404
        res.end('missing')
        return
      }
      if (url.includes('no-body')) {
        res.statusCode = 204
        res.end()
        return
      }
      res.statusCode = 200
      res.setHeader('Content-Type', 'image/jpeg')
      res.end(Buffer.from('image-bytes'))
    })
    await new Promise<void>((resolve) => {
      imageServer.listen(0, '127.0.0.1', resolve)
    })
    imagePort = (imageServer.address() as AddressInfo).port
  }, { timeout: 60000 })

  after(async () => {
    datacache.challenges.usernameXssChallenge.disabledEnv = usernameChallengeEnv
    datacache.challenges.persistedXssUserChallenge.disabledEnv = persistedXssChallengeEnv
    await new Promise<void>((resolve, reject) => {
      imageServer.close((err) => { err != null ? reject(err) : resolve() })
    })
  })

  async function openAccount () {
    const email = `csp-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
    await register(app, { email, password })
    const auth = await login(app, { email, password })
    return { email, cookie: `token=${auth.token}` }
  }

  async function postImage (cookie: string, imageUrl: string) {
    return await request(app)
      .post('/profile/image/url')
      .set('Cookie', cookie)
      .type('form')
      .send({ imageUrl })
      .redirects(0)
  }

  async function storedImage (email: string) {
    const user = await UserModel.findOne({ where: { email } })
    assert.ok(user)
    return { id: user.id, profileImage: user.profileImage }
  }

  async function profilePage (cookie: string) {
    return await request(app).get('/profile').set('Cookie', cookie)
  }

  function assertCallerValueIsNotPolicy (csp: string | undefined, imageUrl: string) {
    const directives = scriptSrcDirectives(csp)
    assert.equal(directives.length, 1, 'profile policy must contain one script-src')
    assert.equal(directives[0].includes('unsafe-inline'), false, 'profile script-src must not allow unsafe-inline')
    assert.equal(directives[0].includes(marker), false, 'profile script-src must not list the caller host')
    assert.match(directives[0], /'self'/)
    assert.equal((csp ?? '').includes(imageUrl), false, 'profile policy must not contain the caller-supplied image value')
  }

  async function assertFailedFetchIsNotStored (imageUrl: string) {
    const account = await openAccount()
    const other = await openAccount()
    const before = fs.existsSync(uploadDir) ? fs.readdirSync(uploadDir).sort() : []

    const upload = await postImage(account.cookie, imageUrl)
    assert.equal(upload.status, 302)

    const stored = await storedImage(account.email)
    const otherStored = await storedImage(other.email)
    const after = fs.existsSync(uploadDir) ? fs.readdirSync(uploadDir).sort() : []
    assert.deepEqual(after, before)
    assert.equal(stored.profileImage.includes(marker), false, 'stored profile image contains the caller-supplied directive')
    assert.equal(stored.profileImage.includes(imageUrl), false, 'stored profile image is the caller-supplied URL')
    assert.equal(otherStored.profileImage.includes(imageUrl), false, 'another account received the caller-supplied URL')

    const page = await profilePage(account.cookie)
    assert.equal(page.status, 200)
    assertCallerValueIsNotPolicy(page.headers['content-security-policy'], imageUrl)

    const otherPage = await profilePage(other.cookie)
    assert.equal(String(otherPage.headers['content-security-policy']).includes(imageUrl), false)
    assert.equal(String(otherPage.headers['content-security-policy']).includes(marker), false)
  }

  void it('does not keep an unfetchable image URL or copy it into Content-Security-Policy', async () => {
    await assertFailedFetchIsNotStored(callerImageUrl('https://a.png'))
  })

  void it('does not keep an image URL that answers with a non-OK status', async () => {
    await assertFailedFetchIsNotStored(callerImageUrl(`http://127.0.0.1:${imagePort}/non-ok.jpg`))
  })

  void it('does not keep an image URL that answers with an empty body', async () => {
    await assertFailedFetchIsNotStored(callerImageUrl(`http://127.0.0.1:${imagePort}/no-body.jpg`))
  })

  void it('does not keep an image URL whose connection fails', async () => {
    await assertFailedFetchIsNotStored(callerImageUrl('http://127.0.0.1:1/nope.png'))
  })

  void it('does not keep an image URL when the fetched body cannot be saved', async () => {
    const imageUrl = callerImageUrl(`http://127.0.0.1:${imagePort}/ok.jpg`)
    const backup = `${uploadDir}-absent`
    const existed = fs.existsSync(uploadDir)
    if (existed) fs.renameSync(uploadDir, backup)
    try {
      await assertFailedFetchIsNotStored(imageUrl)
    } finally {
      if (fs.existsSync(uploadDir)) fs.rmSync(uploadDir, { recursive: true, force: true })
      if (existed) fs.renameSync(backup, uploadDir)
    }
  })

  void it('stores a generated filename after a successful image fetch', async () => {
    fs.mkdirSync(uploadDir, { recursive: true })
    const account = await openAccount()
    const imageUrl = `http://127.0.0.1:${imagePort}/photo.jpg`
    const upload = await postImage(account.cookie, imageUrl)
    assert.equal(upload.status, 302)

    const stored = await storedImage(account.email)
    assert.match(stored.profileImage, new RegExp(`uploads/${stored.id}\\.jpg$`))
    assert.equal(stored.profileImage.includes(imageUrl), false)
    assert.equal(fs.existsSync(path.join(uploadDir, `${stored.id}.jpg`)), true)

    const page = await profilePage(account.cookie)
    assertCallerValueIsNotPolicy(page.headers['content-security-policy'], imageUrl)
  })

  void it('encodes the username in the profile page while that challenge is enabled', async () => {
    assert.equal(utils.isChallengeEnabled(datacache.challenges.usernameXssChallenge), true)
    assert.equal(utils.isChallengeEnabled(datacache.challenges.persistedXssUserChallenge), true)

    const account = await openAccount()
    const imageUrl = callerImageUrl('https://a.png')
    await postImage(account.cookie, imageUrl)
    const update = await request(app)
      .post('/profile')
      .set('Cookie', account.cookie)
      .type('form')
      .send({ username: '<<a|ascript>alert(`xss`)</script>' })
      .redirects(0)
    assert.equal(update.status, 302)

    const sessionCookie = update.headers['set-cookie']?.[0]?.split(';')[0] ?? account.cookie
    const page = await profilePage(sessionCookie)
    assert.equal(page.status, 200)
    const shown = usernameParagraph(page.text)
    assert.equal(shown.includes('<script'), false, 'username markup was inserted as HTML')
    assert.equal(shown.includes('&lt;script&gt;'), true, 'username markup should be encoded in the profile page')
    assertCallerValueIsNotPolicy(page.headers['content-security-policy'], imageUrl)
  })
})
