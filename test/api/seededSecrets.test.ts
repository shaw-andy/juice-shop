/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { readFile } from 'node:fs/promises'
import { QueryTypes, type Sequelize } from 'sequelize'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { generateSync } from 'otplib'
import { createTestApp } from './helpers/setup'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

const jsonHeader = { 'content-type': 'application/json' }
const replacementPassword = 'placeholder-new-password'
const resetPassword = 'placeholder-reset-password'

let app: Express
let sequelize: Sequelize
let seededUsers: StaticUser[]

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
  seededUsers = await loadStaticUserData()
}, { timeout: 60000 })

function emailFor (user: StaticUser): string {
  return user.customDomain === true ? user.email : `${user.email}@${config.get<string>('application.domain')}`
}

function sessionRole (body: { user?: { role?: string } } | undefined): string {
  const role = body?.user?.role
  return typeof role === 'string' && role.length > 0 ? role : 'session'
}

async function plantSession (email: string): Promise<{ token: string, passwordHash: string, totpSecret: string }> {
  const row = await UserModel.findOne({ where: { email }, paranoid: false })
  assert.ok(row, 'seeded user row missing')
  const plain = row.get({ plain: true })
  const token = security.authorize({ data: plain })
  security.authenticatedUsers.put(token, { data: plain, bid: 0 })
  return {
    token,
    passwordHash: String(plain.password),
    totpSecret: String(plain.totpSecret ?? '')
  }
}

void describe('seeded account secrets', { concurrency: false }, () => {
  void it('does not let seeded passwords, security answers, or card numbers authenticate or stay stored', async () => {
    const admin = seededUsers.find(user => user.key === 'admin')
    const accountant = seededUsers.find(user => user.key === 'accountant')
    assert.equal(admin?.role, 'admin')
    assert.equal(accountant?.role, 'accounting')

    const acceptedLogins: string[] = []
    for (const user of seededUsers) {
      const email = emailFor(user)
      const loginRes = await request(app)
        .post('/rest/user/login')
        .set(jsonHeader)
        .send({ email, password: user.password })

      const token = loginRes.body?.authentication?.token
      if (typeof token === 'string') {
        const who = await request(app)
          .get('/rest/user/whoami')
          .query({ fields: 'role' })
          .set('Cookie', `token=${token}`)
        acceptedLogins.push(`${user.key}:${sessionRole(who.body)}`)
        continue
      }

      if (loginRes.body?.status === 'totp_token_required') {
        let outcome = 'second-factor'
        if (typeof user.totpSecret === 'string' && user.totpSecret.length > 0 && typeof loginRes.body?.data?.tmpToken === 'string') {
          const totpRes = await request(app)
            .post('/rest/2fa/verify')
            .set(jsonHeader)
            .send({
              tmpToken: loginRes.body.data.tmpToken,
              totpToken: generateSync({ secret: user.totpSecret })
            })
          const totpSession = totpRes.body?.authentication?.token
          if (typeof totpSession === 'string') {
            const who = await request(app)
              .get('/rest/user/whoami')
              .query({ fields: 'role' })
              .set('Cookie', `token=${totpSession}`)
            outcome = sessionRole(who.body)
          }
        }
        acceptedLogins.push(`${user.key}:${outcome}`)
      } else if (loginRes.status !== 401) {
        acceptedLogins.push(`${user.key}:status-${loginRes.status}`)
      }
    }

    const secondFactorOutcomes: string[] = []
    for (const user of seededUsers) {
      // Soft-deleted users make setup and disable return the same status when the
      // password matches and when the row can no longer be loaded.
      if (user.deletedFlag === true) continue
      const email = emailFor(user)
      const planted = await plantSession(email)
      const auth = { Authorization: `Bearer ${planted.token}`, ...jsonHeader }
      if (planted.totpSecret === '') {
        const statusRes = await request(app).get('/rest/2fa/status').set(auth)
        if (statusRes.status !== 200 || typeof statusRes.body?.secret !== 'string' || typeof statusRes.body?.setupToken !== 'string') {
          secondFactorOutcomes.push(`${user.key}:status-endpoint-${statusRes.status}`)
          continue
        }
        const setupRes = await request(app)
          .post('/rest/2fa/setup')
          .set(auth)
          .send({
            password: user.password,
            setupToken: statusRes.body.setupToken,
            initialToken: generateSync({ secret: statusRes.body.secret })
          })
        const after = await UserModel.findOne({ where: { email }, paranoid: false })
        const unchanged = String(after?.get('totpSecret') ?? '') === ''
        if (setupRes.status !== 401 || !unchanged) {
          secondFactorOutcomes.push(`${user.key}:setup-${setupRes.status}:unchanged-${unchanged}`)
        }
      } else {
        const disableRes = await request(app)
          .post('/rest/2fa/disable')
          .set(auth)
          .send({ password: user.password })
        const after = await UserModel.findOne({ where: { email }, paranoid: false })
        const unchanged = String(after?.get('totpSecret') ?? '') === planted.totpSecret
        if (disableRes.status !== 401 || !unchanged) {
          secondFactorOutcomes.push(`${user.key}:disable-${disableRes.status}:unchanged-${unchanged}`)
        }
      }
    }

    const changeOutcomes: string[] = []
    for (const user of seededUsers) {
      const email = emailFor(user)
      const planted = await plantSession(email)
      const params = new URLSearchParams({
        current: user.password,
        new: replacementPassword,
        repeat: replacementPassword
      })
      const changeRes = await request(app)
        .get(`/rest/user/change-password?${params.toString()}`)
        .set({ Authorization: `Bearer ${planted.token}` })
      const after = await UserModel.findOne({ where: { email }, paranoid: false })
      const unchanged = String(after?.get('password')) === planted.passwordHash
      if (changeRes.status !== 401 || !unchanged) {
        changeOutcomes.push(`${user.key}:status-${changeRes.status}:unchanged-${unchanged}`)
      }
    }

    const resetOutcomes: string[] = []
    for (const user of seededUsers) {
      if (user.securityQuestion == null) continue
      const email = emailFor(user)
      const before = await UserModel.findOne({ where: { email }, paranoid: false })
      assert.ok(before, 'seeded user row missing')
      const hashBefore = String(before.get('password'))
      const resetRes = await request(app)
        .post('/rest/user/reset-password')
        .set(jsonHeader)
        .send({
          email,
          answer: user.securityQuestion.answer,
          new: resetPassword,
          repeat: resetPassword
        })
      const after = await UserModel.findOne({ where: { email }, paranoid: false })
      const unchanged = String(after?.get('password')) === hashBefore
      if (resetRes.status !== 401 || !unchanged) {
        resetOutcomes.push(`${user.key}:status-${resetRes.status}:unchanged-${unchanged}`)
      }
    }

    const usersYml = await readFile(path.resolve('data/static/users.yml'), 'utf8')
    const fileCardNumbers = [...usersYml.matchAll(/^\s*cardNum:\s*(\d+)\s*$/gm)].map(match => match[1])
    assert.ok(fileCardNumbers.length > 0)
    const storedCards = await sequelize.query<{ UserId: number, cardNum: number | string }>(
      'SELECT UserId, cardNum FROM Cards',
      { type: QueryTypes.SELECT }
    )
    const storedNumbers = new Set(storedCards.map(card => String(card.cardNum)))
    const leakedCardCount = fileCardNumbers.filter(cardNumber => storedNumbers.has(cardNumber)).length

    const adminEmail = emailFor(admin)
    const adminRow = await UserModel.findOne({ where: { email: adminEmail } })
    assert.ok(adminRow, 'admin row missing')
    const adminSeedNumbers = new Set((admin.card ?? []).map(card => String(card.cardNum)))
    assert.ok(adminSeedNumbers.size > 0)
    const adminLeaked = storedCards.filter(card => card.UserId === adminRow.id && adminSeedNumbers.has(String(card.cardNum))).length

    assert.deepEqual({
      acceptedLogins,
      resetOutcomes,
      changeOutcomes,
      secondFactorOutcomes,
      leakedCardCount,
      adminLeaked
    }, {
      acceptedLogins: [],
      resetOutcomes: [],
      changeOutcomes: [],
      secondFactorOutcomes: [],
      leakedCardCount: 0,
      adminLeaked: 0
    })
  }, { timeout: 180000 })
})
