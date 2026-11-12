/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'

const currentSecret = 'PLACEHOLDER_FORM_CURRENT'
const updatedSecret = 'PLACEHOLDER_FORM_UPDATED'
const omittedUpdatedSecret = 'PLACEHOLDER_OMIT_UPDATED'
const refusedCurrentSecret = 'PLACEHOLDER_REFUSED_CURRENT'
const refusedSecret = 'PLACEHOLDER_REFUSED_UPDATED'
const refererCurrentSecret = 'PLACEHOLDER_REFERER_CURRENT'
const refererSecret = 'PLACEHOLDER_REFERER_UPDATED'
const postedCurrentSecret = 'PLACEHOLDER_POST_CURRENT'
const postedUpdatedSecret = 'PLACEHOLDER_POST_UPDATED'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function accessLogPath () {
  return path.resolve('logs', 'access.log.' + utils.toISO8601(new Date()))
}

function responseText (res: Response) {
  if (typeof res.text === 'string' && res.text.length > 0) {
    return res.text
  }
  if (Buffer.isBuffer(res.body)) {
    return res.body.toString('utf8')
  }
  if (typeof res.body === 'string') {
    return res.body
  }
  return ''
}

async function accessLogContaining (marker: string) {
  const deadline = Date.now() + 3000
  let text = ''
  while (Date.now() < deadline) {
    text = fs.existsSync(accessLogPath()) ? fs.readFileSync(accessLogPath(), 'utf8') : ''
    if (text.includes(marker)) {
      return text
    }
    await delay(20)
  }
  return text
}

function adminAuthorization () {
  return 'Bearer ' + security.authorize({ data: { role: security.roles.admin } })
}

async function registerAndLogin (email: string, password: string) {
  const registered = await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({ email, password })
  assert.equal(registered.status, 201)
  return await login(app, { email, password })
}

void describe('change-password secrets in access logs', () => {
  void it('does not leave the form passwords in an anonymously downloadable access log', async () => {
    const email = 'placeholder-log-form@example.test'
    const marker = 'change-password-log-marker-form'
    const { token } = await registerAndLogin(email, currentSecret)

    const change = await request(app)
      .get('/rest/user/change-password?current=' + currentSecret + '&new=' + updatedSecret + '&repeat=' + updatedSecret)
      .set({ Authorization: 'Bearer ' + token, 'User-Agent': marker })

    assert.equal(change.status, 200)
    const again = await login(app, { email, password: updatedSecret })
    assert.ok(again.token)

    const disk = await accessLogContaining(marker)
    assert.equal(disk.includes(marker), true)

    const logFile = 'access.log.' + utils.toISO8601(new Date())
    const anonymous = await request(app).get('/support/logs/' + logFile)
    assert.equal(
      responseText(anonymous).includes(updatedSecret),
      false,
      'anonymous download contained the new password'
    )
    assert.equal(
      responseText(anonymous).includes(currentSecret),
      false,
      'anonymous download contained the current password'
    )
    assert.ok(anonymous.status === 401 || anonymous.status === 403)

    const customer = await request(app)
      .get('/support/logs/' + logFile)
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(responseText(customer).includes(updatedSecret), false)
    assert.ok(customer.status === 401 || customer.status === 403)

    const listing = await request(app).get('/support/logs').redirects(2)
    assert.ok(listing.status === 401 || listing.status === 403)
    const slashedListing = await request(app).get('/support/logs/').redirects(2)
    assert.ok(slashedListing.status === 401 || slashedListing.status === 403)

    assert.equal(disk.includes(updatedSecret), false, 'new password was written to the access log')
    assert.equal(disk.includes(currentSecret), false, 'current password was written to the access log')

    const admin = await request(app)
      .get('/support/logs/' + logFile)
      .set({ Authorization: adminAuthorization() })
    assert.equal(admin.status, 200)
    assert.equal(responseText(admin).includes(updatedSecret), false, 'admin download contained the new password')
    assert.equal(responseText(admin).includes(currentSecret), false, 'admin download contained the current password')
  })

  void it('does not write a new password to the access log when the current password is omitted', async () => {
    const email = 'placeholder-log-omit@example.test'
    const marker = 'change-password-log-marker-omit'
    const { token } = await registerAndLogin(email, currentSecret)

    const change = await request(app)
      .get('/rest/user/change-password?new=' + omittedUpdatedSecret + '&repeat=' + omittedUpdatedSecret)
      .set({ Authorization: 'Bearer ' + token, 'User-Agent': marker })

    assert.equal(change.status, 200)
    const again = await login(app, { email, password: omittedUpdatedSecret })
    assert.ok(again.token)

    const disk = await accessLogContaining(marker)
    assert.equal(disk.includes(marker), true)
    assert.equal(disk.includes(omittedUpdatedSecret), false, 'omitted-current password change was written to the access log')

    const anonymous = await request(app).get('/support/logs/access.log.' + utils.toISO8601(new Date()))
    assert.equal(responseText(anonymous).includes(omittedUpdatedSecret), false)
    assert.ok(anonymous.status === 401 || anonymous.status === 403)
  })

  void it('does not write the new password to the access log when the change is refused', async () => {
    const marker = 'change-password-log-marker-refused'
    const change = await request(app)
      .get('/rest/user/change-password?current=' + refusedCurrentSecret + '&new=' + refusedSecret + '&repeat=' + refusedSecret)
      .set({ 'User-Agent': marker })

    assert.notEqual(change.status, 200)

    const disk = await accessLogContaining(marker)
    assert.equal(disk.includes(marker), true)
    assert.equal(disk.includes(refusedSecret), false, 'refused password change was written to the access log')
    assert.equal(disk.includes(refusedCurrentSecret), false, 'refused password change wrote the current password to the access log')
  })

  void it('does not write a change-password URL carried in Referer to the access log', async () => {
    const marker = 'change-password-log-marker-referer'
    const referer = 'http://localhost/rest/user/change-password?current=' + refererCurrentSecret + '&new=' + refererSecret + '&repeat=' + refererSecret
    const followed = await request(app)
      .get('/api/Products')
      .set({ Referer: referer, 'User-Agent': marker })

    assert.equal(followed.status, 200)
    const disk = await accessLogContaining(marker)
    assert.equal(disk.includes(marker), true)
    assert.equal(disk.includes(refererSecret), false, 'Referer change-password URL was written to the access log')
    assert.equal(disk.includes(refererCurrentSecret), false, 'Referer change-password URL wrote the current password to the access log')
  })

  void it('changes the password from a POST body without putting it in the access log', async () => {
    const email = 'placeholder-log-post@example.test'
    const marker = 'change-password-log-marker-post'
    const { token } = await registerAndLogin(email, postedCurrentSecret)

    const changeCall = request(app)
      .post('/rest/user/change-password')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json',
        'User-Agent': marker
      })
      .send({
        current: postedCurrentSecret,
        new: postedUpdatedSecret,
        repeat: postedUpdatedSecret
      })
    const change = await changeCall

    assert.equal(change.status, 200)
    assert.equal(changeCall.url.includes(postedUpdatedSecret), false)
    assert.equal(changeCall.url.includes(postedCurrentSecret), false)

    const again = await login(app, { email, password: postedUpdatedSecret })
    assert.ok(again.token)

    const disk = await accessLogContaining(marker)
    assert.equal(disk.includes(marker), true)
    assert.equal(disk.includes(postedUpdatedSecret), false, 'POST password change wrote the new password to the access log')
    assert.equal(disk.includes(postedCurrentSecret), false, 'POST password change wrote the current password to the access log')
  })
})
