/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

let app: Express
let sequelize: Sequelize

const sessionMarker = 'planted-session-marker'
const customerPassword = 'placeholder-customer-password'
const replacementPassword = 'placeholder-replacement-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

after(() => {
  delete (Object.prototype as Record<string, unknown>)[sessionMarker]
})

function escapePayload (userId: number) {
  return 'Object.defineProperty(({ }).constructor.prototype, ' +
    JSON.stringify(sessionMarker) +
    ', { value: ({ data: ({ id: ' + String(userId) +
    ' }) }), enumerable: false, configurable: true, writable: true })'
}

async function administrator () {
  const admin = await UserModel.findOne({ where: { role: 'admin' } })
  assert.ok(admin)
  return admin
}

async function restorePasswordHash (id: number, passwordHash: string) {
  await sequelize.query('UPDATE Users SET password = :passwordHash WHERE id = :id', {
    replacements: { passwordHash, id }
  })
}

void describe('b2b order sandbox escape', { concurrency: false }, () => {
  void it('customer orderLinesData does not plant a session or change the administrator password', async () => {
    const admin = await administrator()
    const passwordHashBefore = admin.password
    const email = 'sandbox-customer-' + Date.now() + '@example.test'
    delete (Object.prototype as Record<string, unknown>)[sessionMarker]

    try {
      await register(app, { email, password: customerPassword })
      const { token } = await login(app, { email, password: customerPassword })

      const orderRes = await request(app)
        .post('/b2b/v2/orders')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
        .send({ orderLinesData: escapePayload(admin.id) })

      const polluted = Object.hasOwn(Object.prototype, sessionMarker)
      const plantedSession = security.authenticatedUsers.get(sessionMarker)
      const changeRes = await request(app)
        .get('/rest/user/change-password')
        .query({ new: replacementPassword, repeat: replacementPassword })
        .set({ Authorization: 'Bearer ' + sessionMarker })

      await admin.reload()
      const passwordChanged = admin.password !== passwordHashBefore
      const loginRes = await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({ email: admin.email, password: replacementPassword })

      const failures: string[] = []
      if (polluted) failures.push('order status ' + String(orderRes.status) + ' and orderLinesData added a property to Object.prototype')
      if (plantedSession !== undefined) failures.push('a prototype property was accepted as a session for administrator id ' + String(admin.id))
      if (changeRes.status === 200) failures.push('change-password accepted the planted session')
      if (passwordChanged) failures.push('administrator id ' + String(admin.id) + ' password hash changed')
      if (loginRes.status === 200) failures.push('administrator login succeeded with the replacement password')
      assert.deepEqual(failures, [])
    } finally {
      delete (Object.prototype as Record<string, unknown>)[sessionMarker]
      const current = await UserModel.findByPk(admin.id)
      if (current != null && current.password !== passwordHashBefore) {
        await restorePasswordHash(admin.id, passwordHashBefore)
      }
    }
  })

  void it('a property inherited from Object.prototype is not a session', async () => {
    const admin = await administrator()
    const passwordHashBefore = admin.password
    const inherited = { data: { id: admin.id } }
    // eslint-disable-next-line no-extend-native
    Object.defineProperty(Object.prototype, sessionMarker, {
      value: inherited,
      enumerable: false,
      configurable: true,
      writable: true
    })

    try {
      const inheritedSession = security.authenticatedUsers.get(sessionMarker) !== undefined
      const inheritedFrom = security.authenticatedUsers.from({ headers: { authorization: 'Bearer ' + sessionMarker } } as never) !== undefined

      const idKey = 'prototype-only-user-id'
      // eslint-disable-next-line no-extend-native
      Object.defineProperty(Object.prototype, idKey, {
        value: 'placeholder-token',
        enumerable: false,
        configurable: true,
        writable: true
      })
      let inheritedToken = false
      try {
        inheritedToken = security.authenticatedUsers.tokenOf({ id: idKey } as unknown as UserModel) !== undefined
      } finally {
        delete (Object.prototype as Record<string, unknown>)[idKey]
      }

      let nextCalled = false
      const req = { headers: { authorization: 'Bearer ' + sessionMarker }, body: {} as { UserId?: number } }
      const res = {
        status () { return this },
        json () { return this }
      }
      security.appendUserId()(req as never, res as never, () => { nextCalled = true })

      const changeRes = await request(app)
        .get('/rest/user/change-password')
        .query({ new: replacementPassword, repeat: replacementPassword })
        .set({ Authorization: 'Bearer ' + sessionMarker })
      await admin.reload()

      const failures: string[] = []
      if (inheritedSession) failures.push('get() accepted an inherited session for administrator id ' + String(admin.id))
      if (inheritedFrom) failures.push('from() accepted an inherited session')
      if (inheritedToken) failures.push('tokenOf() accepted an inherited token')
      if (nextCalled || req.body.UserId !== undefined) failures.push('appendUserId accepted an inherited session')
      if (changeRes.status === 200) failures.push('change-password accepted an inherited session')
      if (admin.password !== passwordHashBefore) failures.push('administrator password hash changed through an inherited session')
      assert.deepEqual(failures, [])
    } finally {
      delete (Object.prototype as Record<string, unknown>)[sessionMarker]
      const current = await UserModel.findByPk(admin.id)
      if (current != null && current.password !== passwordHashBefore) {
        await restorePasswordHash(admin.id, passwordHashBefore)
      }
    }
  })
})
