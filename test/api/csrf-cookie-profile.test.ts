/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs/promises'
import request from 'supertest'
import type { Express } from 'express'
import type { AddressInfo } from 'node:net'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'
import { PrivacyRequestModel } from '../../models/privacyRequests'

const attackerOrigin = 'http://attacker.example'
const placeholderPassword = 'placeholder'
const plantedUsername = 'csrf-planted-name'
const evaluatedUsername = '#{7*7}'
const onePixelPng = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
)

let app: Express
let victim: { email: string, token: string, id: number, username: string, profileImage: string }
let bystander: { id: number, username: string }
let probe: http.Server
let probeUrl = ''
let probeHits = 0

function cookieFor (token: string) {
  return { Cookie: `token=${token}` }
}

async function reload (id: number) {
  return await UserModel.findByPk(id)
}

function uploadPathFor (id: number) {
  return `frontend/dist/frontend/assets/public/images/uploads/${id}.png`
}

async function uploadWasWritten (id: number) {
  try {
    await fs.access(uploadPathFor(id))
    return true
  } catch {
    return false
  }
}

async function resetVictim () {
  const row = await reload(victim.id)
  await row?.update({ username: victim.username, profileImage: victim.profileImage })
  await PrivacyRequestModel.destroy({ where: { UserId: victim.id } })
  await fs.rm(uploadPathFor(victim.id), { force: true })
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const victimEmail = 'csrf-victim@example.test'
  const bystanderEmail = 'csrf-bystander@example.test'
  await register(app, { email: victimEmail, password: placeholderPassword })
  await register(app, { email: bystanderEmail, password: placeholderPassword })
  const victimLogin = await login(app, { email: victimEmail, password: placeholderPassword })
  const victimRow = await UserModel.findOne({ where: { email: victimEmail } })
  const bystanderRow = await UserModel.findOne({ where: { email: bystanderEmail } })
  if (victimRow == null || bystanderRow == null) {
    throw new Error('registered users were not stored')
  }
  victim = {
    email: victimEmail,
    token: victimLogin.token,
    id: victimRow.id,
    username: victimRow.username ?? '',
    profileImage: victimRow.profileImage
  }
  bystander = {
    id: bystanderRow.id,
    username: bystanderRow.username ?? ''
  }
  await fs.mkdir('frontend/dist/frontend/assets/public/images/uploads', { recursive: true })

  probeHits = 0
  probe = http.createServer((_req, res) => {
    probeHits += 1
    res.setHeader('content-type', 'image/png')
    res.end(onePixelPng)
  })
  await new Promise<void>((resolve) => {
    probe.listen(0, '127.0.0.1', resolve)
  })
  const address = probe.address() as AddressInfo
  probeUrl = `http://127.0.0.1:${address.port}/portrait.png`
}, { timeout: 60000 })

after(async () => {
  if (probe !== undefined) {
    await new Promise<void>((resolve, reject) => {
      probe.close((error) => {
        if (error !== undefined) reject(error)
        else resolve()
      })
    })
  }
})

void describe('cross-site cookie profile updates', () => {
  void it('does not store a username posted from another origin', async () => {
    await resetVictim()
    const res = await request(app)
      .post('/profile')
      .set(cookieFor(victim.token))
      .set('Origin', attackerOrigin)
      .set('Referer', `${attackerOrigin}/change-name.html`)
      .type('form')
      .send({ username: plantedUsername, UserId: bystander.id, id: bystander.id })
      .redirects(0)

    const victimRow = await reload(victim.id)
    const bystanderRow = await reload(bystander.id)
    assert.equal(victimRow?.username ?? '', victim.username)
    assert.equal(bystanderRow?.username ?? '', bystander.username)
    assert.ok(res.status >= 400 && res.status < 500)
  })

  void it('does not store a username when only a foreign referer is present', async () => {
    await resetVictim()
    const res = await request(app)
      .post('/profile')
      .set(cookieFor(victim.token))
      .set('Referer', `${attackerOrigin}/change-name.html`)
      .type('form')
      .send({ username: `${plantedUsername}-referer` })
      .redirects(0)

    const victimRow = await reload(victim.id)
    assert.equal(victimRow?.username ?? '', victim.username)
    assert.ok(res.status >= 400 && res.status < 500)
  })

  void it('does not store a username posted from the CSRF challenge origin', async () => {
    await resetVictim()
    const challengeOrigin = config.get<string>('challenges.overwriteUrlForCsrfChallenge')
    const res = await request(app)
      .post('/profile')
      .set(cookieFor(victim.token))
      .set('Origin', challengeOrigin)
      .set('Referer', `${challengeOrigin}/`)
      .type('form')
      .send({ username: `${plantedUsername}-challenge-origin` })
      .redirects(0)

    const victimRow = await reload(victim.id)
    assert.equal(victimRow?.username ?? '', victim.username)
    assert.ok(res.status >= 400 && res.status < 500)
  })

  void it('does not evaluate a hash-brace username planted from another origin', async () => {
    await resetVictim()
    const res = await request(app)
      .post('/profile')
      .set(cookieFor(victim.token))
      .set('Origin', attackerOrigin)
      .type('form')
      .send({ username: evaluatedUsername })
      .redirects(0)

    const profile = await request(app)
      .get('/profile')
      .set(cookieFor(victim.token))

    const victimRow = await reload(victim.id)
    assert.equal(profile.text.includes('>49<'), false)
    assert.equal(victimRow?.username ?? '', victim.username)
    assert.ok(res.status >= 400 && res.status < 500)
  })

  void it('does not fetch or save a profile image URL posted from another origin', async () => {
    await resetVictim()
    probeHits = 0

    const res = await request(app)
      .post('/profile/image/url')
      .set(cookieFor(victim.token))
      .set('Origin', attackerOrigin)
      .set('Referer', `${attackerOrigin}/change-image.html`)
      .type('form')
      .send({ imageUrl: probeUrl })
      .redirects(0)

    const after = await reload(victim.id)
    const uploadWritten = await uploadWasWritten(victim.id)
    await fs.rm(uploadPathFor(victim.id), { force: true })

    assert.equal(probeHits, 0)
    assert.equal(uploadWritten, false)
    assert.equal(after?.profileImage, victim.profileImage)
    assert.ok(res.status >= 400 && res.status < 500)
  })

  void it('does not store a profile image file posted from another origin', async () => {
    await resetVictim()

    const res = await request(app)
      .post('/profile/image/file')
      .set(cookieFor(victim.token))
      .set('Origin', attackerOrigin)
      .set('Referer', `${attackerOrigin}/upload.html`)
      .attach('file', onePixelPng, { filename: 'portrait.png', contentType: 'image/png' })
      .redirects(0)

    const after = await reload(victim.id)
    const uploadWritten = await uploadWasWritten(victim.id)
    await fs.rm(uploadPathFor(victim.id), { force: true })

    assert.equal(uploadWritten, false)
    assert.equal(after?.profileImage, victim.profileImage)
    assert.ok(res.status >= 400 && res.status < 500)
  })

  void it('does not record a data-erasure request posted from another origin', async () => {
    await resetVictim()
    const before = await PrivacyRequestModel.count({ where: { UserId: victim.id } })
    const res = await request(app)
      .post('/dataerasure')
      .set(cookieFor(victim.token))
      .set('Origin', attackerOrigin)
      .set('Referer', `${attackerOrigin}/erase.html`)
      .type('form')
      .send({ email: victim.email, securityAnswer: 'placeholder' })
      .redirects(0)

    const after = await PrivacyRequestModel.count({ where: { UserId: victim.id } })
    assert.equal(after, before)
    assert.ok(res.status >= 400 && res.status < 500)
  })
})
