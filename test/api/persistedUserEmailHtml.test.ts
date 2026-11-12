/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import { UserModel } from '../../models/user'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

const registrationMarkup = '</span><img id="pxss" src="x" onerror="window.pxss=1">'
const directPostMarkup = '</span><img id="pxss-direct" src="x" onerror="window.pxss=1">'
const updateMarkup = '</span><img id="pxss-update" src="x" onerror="window.pxss=1">'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function assertEmailIsNotMarkup (email: string) {
  assert.equal(email.includes('<img'), false)
  assert.equal(email.includes('onerror'), false)
  assert.equal(email.includes('</span>'), false)
}

async function emailServedToAdministration (id: number) {
  const listed = await request(app)
    .get('/rest/user/authentication-details')
    .set(authHeader)
  assert.equal(listed.status, 200)
  const stored = listed.body.data.find((user: { id: number }) => user.id === id)
  assert.ok(stored)
  return stored.email as string
}

void describe('persisted user email HTML', () => {
  void it('registration with a repeated password does not store email markup for the administration list', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.persistedXssUserChallenge), true)

    const created = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: registrationMarkup,
        password: 'placeholder-password',
        passwordRepeat: 'placeholder-password'
      })
    assert.equal(created.status, 201)

    assertEmailIsNotMarkup(created.body.data.email)
    assertEmailIsNotMarkup(await emailServedToAdministration(created.body.data.id))
  })

  void it('registration without a repeated password does not store email markup for the administration list', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.persistedXssUserChallenge), true)

    const created = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: directPostMarkup,
        password: 'placeholder-password'
      })
    assert.equal(created.status, 201)

    assertEmailIsNotMarkup(created.body.data.email)
    assertEmailIsNotMarkup(await emailServedToAdministration(created.body.data.id))
  })

  void it('saving an existing user does not store email markup for the administration list', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.persistedXssUserChallenge), true)

    const created = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'plain-user@example.test',
        password: 'placeholder-password'
      })
    assert.equal(created.status, 201)

    const user = await UserModel.findByPk(created.body.data.id)
    assert.ok(user)
    await user.update({ email: updateMarkup })

    assertEmailIsNotMarkup(await emailServedToAdministration(created.body.data.id))
  })
})
