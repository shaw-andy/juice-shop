/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'
import { CardModel } from '../../models/card'
import { AddressModel } from '../../models/address'

const jsonHeader = { 'content-type': 'application/json' }
const placeholderPassword = 'placeholder-not-a-secret'

function accountEmail (user: StaticUser): string {
  const domain = config.get<string>('application.domain')
  return user.customDomain === true ? user.email : `${user.email}@${domain}`
}

function bodyContainsValue (body: unknown, value: string | number | undefined): boolean {
  if (value === undefined || value === null || value === '') return false
  return JSON.stringify(body).includes(String(value))
}

describe('seeded account exposure', () => {
  let app: Express

  before(async () => {
    const result = await createTestApp()
    app = result.app
  }, { timeout: 60000 })

  void it('does not accept seed passwords for login or administrator access', async () => {
    const users = await loadStaticUserData()
    let seedPasswordAccepted = false
    let adminListReached = false
    let fullCardNumberReturned = false
    let seedAddressReturned = false
    let seedPasswordChanged = false

    for (const user of users) {
      if (!user.password) continue
      const email = accountEmail(user)
      const loginRes = await request(app)
        .post('/rest/user/login')
        .set(jsonHeader)
        .send({ email, password: user.password })

      const token = loginRes.body?.authentication?.token
      const passwordAccepted = loginRes.status === 200 || loginRes.body?.status === 'totp_token_required'
      if (passwordAccepted) seedPasswordAccepted = true
      if (typeof token !== 'string') continue

      const auth = { Authorization: 'Bearer ' + token, ...jsonHeader }
      const adminRes = await request(app)
        .get('/rest/user/authentication-details')
        .set(auth)
      if (adminRes.status === 200) adminListReached = true

      const cardsRes = await request(app)
        .get('/api/Cards')
        .set(auth)
      const cards = Array.isArray(cardsRes.body?.data) ? cardsRes.body.data : []
      if (user.card?.some((card) => bodyContainsValue(cardsRes.body, card.cardNum))) {
        fullCardNumberReturned = true
      }
      for (const card of cards) {
        const oneRes = await request(app)
          .get('/api/Cards/' + card.id)
          .set(auth)
        if (user.card?.some((seedCard) => bodyContainsValue(oneRes.body, seedCard.cardNum))) {
          fullCardNumberReturned = true
        }
      }

      const addressRes = await request(app)
        .get('/api/Addresss')
        .set(auth)
      if (user.address?.some((address) => bodyContainsValue(addressRes.body, address.streetAddress))) {
        seedAddressReturned = true
      }

      const changeRes = await request(app)
        .get('/rest/user/change-password')
        .query({
          current: user.password,
          new: placeholderPassword,
          repeat: placeholderPassword
        })
        .set(auth)
      if (changeRes.status === 200) seedPasswordChanged = true
    }

    assert.deepEqual({
      seedPasswordAccepted,
      adminListReached,
      fullCardNumberReturned,
      seedAddressReturned,
      seedPasswordChanged
    }, {
      seedPasswordAccepted: false,
      adminListReached: false,
      fullCardNumberReturned: false,
      seedAddressReturned: false,
      seedPasswordChanged: false
    })
  })

  void it('does not accept seed security answers for password reset', async () => {
    const users = await loadStaticUserData()
    let seedAnswerAccepted = false

    for (const user of users) {
      if (!user.securityQuestion?.answer) continue
      const email = accountEmail(user)
      const resetRes = await request(app)
        .post('/rest/user/reset-password')
        .set(jsonHeader)
        .send({
          email,
          answer: user.securityQuestion.answer,
          new: placeholderPassword,
          repeat: placeholderPassword
        })
      if (resetRes.status === 200) seedAnswerAccepted = true
    }

    assert.equal(seedAnswerAccepted, false)
  })

  void it('does not keep full seed card numbers or seed addresses in the database', async () => {
    const users = await loadStaticUserData()
    const storedCards = await CardModel.findAll()
    const storedAddresses = await AddressModel.findAll()
    let fullCardNumberStored = false
    let seedAddressStored = false

    for (const user of users) {
      for (const card of user.card ?? []) {
        if (storedCards.some((stored) => String(stored.cardNum) === String(card.cardNum))) {
          fullCardNumberStored = true
        }
      }
      for (const address of user.address ?? []) {
        if (storedAddresses.some((stored) => stored.streetAddress === address.streetAddress)) {
          seedAddressStored = true
        }
      }
    }

    assert.deepEqual({
      fullCardNumberStored,
      seedAddressStored
    }, {
      fullCardNumberStored: false,
      seedAddressStored: false
    })
  })
})
