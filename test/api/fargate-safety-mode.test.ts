/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import './helpers/fargate-runtime-hook.mjs'
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { crc32 } from 'node:zlib'
import { pathToFileURL } from 'node:url'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { challenges } from '../../data/datacache'
import isDocker from '../../lib/is-docker'
import isHeroku from '../../lib/is-heroku'
import * as utils from '../../lib/utils'

const escapedZipPath = path.resolve('uploads/fargate-safety-marker.txt')
const xxeMarkerPath = path.resolve('uploads/fargate-xxe-marker.txt')
const xxeCanary = 'fargate-xxe-canary'
const yamlCanary = 'fargate-yaml-canary'
const headerCanary = '<iframe src="javascript:alert(`xss`)">'
const account = {
  email: 'fargate-safety@example.test',
  password: 'example-password'
}

let app: Express
let cookie: string
let bearer: string

function storedZip (name: string, content: Buffer) {
  const nameBuf = Buffer.from(name)
  const checksum = crc32(content)
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0)
  local.writeUInt16LE(20, 4)
  local.writeUInt16LE(0, 8)
  local.writeUInt32LE(checksum, 14)
  local.writeUInt32LE(content.length, 18)
  local.writeUInt32LE(content.length, 22)
  local.writeUInt16LE(nameBuf.length, 26)
  const localRecord = Buffer.concat([local, nameBuf, content])
  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0)
  central.writeUInt16LE(20, 4)
  central.writeUInt16LE(20, 6)
  central.writeUInt32LE(checksum, 16)
  central.writeUInt32LE(content.length, 20)
  central.writeUInt32LE(content.length, 24)
  central.writeUInt16LE(nameBuf.length, 28)
  central.writeUInt32LE(localRecord.length - content.length - nameBuf.length - 30, 42)
  const centralRecord = Buffer.concat([central, nameBuf])
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(1, 8)
  end.writeUInt16LE(1, 10)
  end.writeUInt32LE(centralRecord.length, 12)
  end.writeUInt32LE(localRecord.length, 16)
  return Buffer.concat([localRecord, centralRecord, end])
}

before(async () => {
  fs.mkdirSync(path.dirname(xxeMarkerPath), { recursive: true })
  fs.writeFileSync(xxeMarkerPath, xxeCanary)
  fs.rmSync(escapedZipPath, { force: true })
  const result = await createTestApp()
  app = result.app
  await register(app, account)
  const authentication = await login(app, account)
  bearer = authentication.token
  cookie = `token=${authentication.token}`
}, { timeout: 60000 })

after(() => {
  fs.rmSync(escapedZipPath, { force: true })
  fs.rmSync(xxeMarkerPath, { force: true })
})

void describe('Fargate safety mode', () => {
  void it('runs with the metadata variable set and without a Heroku environment', () => {
    assert.equal(isHeroku(), false)
    assert.equal(typeof process.env.ECS_CONTAINER_METADATA_URI_V4, 'string')
    assert.equal(config.has('challenges.safetyMode'), true)
  })

  void it('does not treat the Fargate runtime as a container that disables danger-zone challenges', () => {
    assert.equal(isDocker(), false)
    const watched = [
      challenges.fileWriteChallenge,
      challenges.deprecatedInterfaceChallenge,
      challenges.rceChallenge,
      challenges.rceOccupyChallenge,
      challenges.usernameXssChallenge,
      challenges.lfrChallenge,
      challenges.httpHeaderXssChallenge,
      challenges.noSqlCommandChallenge,
      challenges.reflectedXssChallenge,
      challenges.noSqlOrdersChallenge,
      challenges.persistedXssFeedbackChallenge,
      challenges.persistedXssUserChallenge,
      challenges.restfulXssChallenge,
      challenges.jwtForgedChallenge,
      challenges.sstiChallenge,
      challenges.xxeFileDisclosureChallenge,
      challenges.xxeDosChallenge,
      challenges.yamlBombChallenge,
      challenges.videoXssChallenge
    ]
    for (const challenge of watched) {
      assert.equal(utils.isChallengeEnabled(challenge), false, challenge.key)
    }
  })

  void it('does not write a zip entry outside the complaints directory', async () => {
    const zip = storedZip('../fargate-safety-marker.txt', Buffer.from('written-outside-complaints'))
    const res = await request(app)
      .post('/file-upload')
      .attach('file', zip, 'complaint.zip')

    assert.equal(res.status, 204)
    assert.equal(fs.existsSync(escapedZipPath), false)
  })

  void it('does not expand an external XML entity into the complaint response', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "${pathToFileURL(xxeMarkerPath).href}">]>
<foo>&xxe;</foo>`
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from(xml), 'complaint.xml')

    assert.equal(res.text.includes(xxeCanary), false)
    assert.equal(fs.readFileSync(xxeMarkerPath, 'utf8'), xxeCanary)
  })

  void it('does not parse attacker YAML into the complaint response', async () => {
    const yaml = `canary: ${yamlCanary}\n`
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from(yaml), 'complaint.yml')

    assert.equal(res.text.includes(yamlCanary), false)
  })

  void it('does not evaluate B2B order lines for a self-registered user', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set('Authorization', 'Bearer ' + bearer)
      .send({ orderLinesData: '(function dos() { while(true); })()' })

    assert.equal(res.status, 200)
    assert.equal(res.text.includes('Infinite loop detected'), false)
  })

  void it('does not evaluate a profile username expression for a self-registered user', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', cookie)
      .type('form')
      .send({ username: '#{7*7}' })
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set('Cookie', cookie)

    assert.equal(res.status, 200)
    assert.equal(res.text.includes('>49<'), false)
  })

  void it('does not reflect an unsanitized order id', async () => {
    const payload = 'order<script>alert(1)</script>'
    const res = await request(app)
      .get('/rest/track-order/' + encodeURIComponent(payload))

    assert.equal(res.status, 200)
    assert.equal(JSON.stringify(res.body).includes('<script>'), false)
  })

  void it('does not run attacker code from a product-review query', async () => {
    const globalObject = globalThis as typeof globalThis & { f?: number }
    delete globalObject.f
    await request(app)
      .put('/rest/products/1/reviews')
      .send({ message: 'hello', author: account.email })

    const res = await request(app)
      .get('/rest/products/' + encodeURIComponent('0||(global.f=1)') + '/reviews')

    assert.equal(res.status, 200)
    assert.equal(globalObject.f, undefined)
  })

  void it('does not store an unsanitized login IP header', async () => {
    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set('Authorization', 'Bearer ' + bearer)
      .set('true-client-ip', headerCanary)

    assert.equal(res.status, 200)
    assert.equal(String(res.body.lastLoginIp).includes('<iframe'), false)
  })

  void it('does not keep markup in a self-registered profile email', async () => {
    await request(app)
      .post('/api/Users')
      .send({
        email: 'fargate<iframe>@example.test',
        password: account.password,
        passwordRepeat: account.password
      })

    const listed = await request(app)
      .get('/api/Users')
      .set('Authorization', 'Bearer ' + bearer)
    assert.equal(JSON.stringify(listed.body).includes('<iframe'), false)
  })

  void it('does not keep markup in a product description created by a self-registered user', async () => {
    const created = await request(app)
      .post('/api/Products')
      .set('Authorization', 'Bearer ' + bearer)
      .send({
        name: 'Fargate Safety Probe',
        description: headerCanary,
        price: 1,
        image: 'apple_juice.jpg'
      })

    assert.equal(created.status < 500, true)
    const listed = await request(app).get('/api/Products')
    assert.equal(JSON.stringify(listed.body).includes('<iframe'), false)
  })
})
