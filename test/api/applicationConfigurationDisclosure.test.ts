/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const placeholderNewPassword = 'placeholder-new-password'
const placeholderCustomerEmail = 'config-disclosure-customer@example.com'
const placeholderCustomerPassword = 'placeholder-password'

const answerFieldAccounts = {
  geoStalkingMetaSecurityAnswer: 'john',
  geoStalkingVisualSecurityAnswer: 'emma'
} as const

type SeededAccount = typeof answerFieldAccounts[keyof typeof answerFieldAccounts]

interface LeakedAnswer {
  account: SeededAccount
  answer: string
}

interface AttackReport {
  account: SeededAccount
  resetAccepted: boolean
  signedInAsTarget: boolean
  profileMatches: boolean
  paymentMethodsAccepted: boolean
  orderHistoryAccepted: boolean
}

function collectPasswordResetAnswers (value: unknown, found: LeakedAnswer[] = []): LeakedAnswer[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectPasswordResetAnswers(item, found)
    }
    return found
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const account = answerFieldAccounts[key as keyof typeof answerFieldAccounts]
      if (account !== undefined && typeof child === 'string' && child.length > 0) {
        found.push({ account, answer: child })
      }
      collectPasswordResetAnswers(child, found)
    }
  }
  return found
}

function dedupeByAccount (leaks: LeakedAnswer[]): LeakedAnswer[] {
  const seen = new Set<SeededAccount>()
  const unique: LeakedAnswer[] = []
  for (const leak of leaks) {
    if (seen.has(leak.account)) continue
    seen.add(leak.account)
    unique.push(leak)
  }
  return unique
}

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 120000 })

void describe('password-reset answers in application configuration', () => {
  void it('finds nested password-reset answer fields', () => {
    const sample = {
      config: {
        memories: [
          { geoStalkingMetaSecurityAnswer: 'placeholder-answer' },
          { nested: { geoStalkingVisualSecurityAnswer: 'placeholder-answer-2' } }
        ]
      }
    }

    const found = collectPasswordResetAnswers(sample)

    assert.deepEqual(found.map((entry) => entry.account), ['john', 'emma'])
  })

  void it('does not let anonymous or non-admin clients reset seeded accounts from application-configuration', async () => {
    await register(app, {
      email: placeholderCustomerEmail,
      password: placeholderCustomerPassword
    })
    const customer = await login(app, {
      email: placeholderCustomerEmail,
      password: placeholderCustomerPassword
    })
    const adminAuthorization = 'Bearer ' + security.authorize({
      data: { id: 0, email: 'placeholder-admin@example.com', role: 'admin' }
    })

    const anonymous = await request(app).get('/rest/admin/application-configuration')
    const customerResponse = await request(app)
      .get('/rest/admin/application-configuration')
      .set('Authorization', 'Bearer ' + customer.token)
    const adminResponse = await request(app)
      .get('/rest/admin/application-configuration')
      .set('Authorization', adminAuthorization)

    const domain = config.get<string>('application.domain')
    const accounts: SeededAccount[] = ['john', 'emma']
    const accountReports = []
    for (const account of accounts) {
      const email = `${account}@${domain}`
      const questionRes = await request(app)
        .get('/rest/user/security-question')
        .query({ email })
      const question = questionRes.body?.question?.question
      accountReports.push({
        account,
        questionPresent: questionRes.status === 200 && typeof question === 'string' && question.length > 0
      })
    }

    const leaks = dedupeByAccount([
      ...collectPasswordResetAnswers(anonymous.body),
      ...collectPasswordResetAnswers(customerResponse.body),
      ...collectPasswordResetAnswers(adminResponse.body)
    ])
    const attackReports: AttackReport[] = []
    for (const leak of leaks) {
      const email = `${leak.account}@${domain}`
      const resetRes = await request(app)
        .post('/rest/user/reset-password')
        .set('content-type', 'application/json')
        .send({
          email,
          answer: leak.answer,
          new: placeholderNewPassword,
          repeat: placeholderNewPassword
        })
      const loginRes = await request(app)
        .post('/rest/user/login')
        .set('content-type', 'application/json')
        .send({ email, password: placeholderNewPassword })
      const token = loginRes.body?.authentication?.token
      const umail = loginRes.body?.authentication?.umail
      let profileMatches = false
      let paymentStatus = 0
      let orderStatus = 0
      if (typeof token === 'string' && token.length > 0) {
        const profile = await request(app)
          .get('/rest/user/whoami')
          .set('Cookie', `token=${token}`)
        profileMatches = profile.body?.user?.email === email
        const cards = await request(app)
          .get('/api/Cards')
          .set('Authorization', `Bearer ${token}`)
        paymentStatus = cards.status
        const orders = await request(app)
          .get('/rest/order-history')
          .set('Authorization', `Bearer ${token}`)
        orderStatus = orders.status
      }
      attackReports.push({
        account: leak.account,
        resetAccepted: resetRes.status === 200,
        signedInAsTarget: loginRes.status === 200 && umail === email,
        profileMatches,
        paymentMethodsAccepted: paymentStatus === 200,
        orderHistoryAccepted: orderStatus === 200
      })
    }

    assert.deepEqual({
      anonymousAnswerFields: collectPasswordResetAnswers(anonymous.body).length,
      customerAnswerFields: collectPasswordResetAnswers(customerResponse.body).length,
      adminAnswerFields: collectPasswordResetAnswers(adminResponse.body).length,
      accounts: accountReports,
      attacks: attackReports
    }, {
      anonymousAnswerFields: 0,
      customerAnswerFields: 0,
      adminAnswerFields: 0,
      accounts: [
        { account: 'john', questionPresent: true },
        { account: 'emma', questionPresent: true }
      ],
      attacks: attackReports.map((report) => ({
        account: report.account,
        resetAccepted: false,
        signedInAsTarget: false,
        profileMatches: false,
        paymentMethodsAccepted: false,
        orderHistoryAccepted: false
      }))
    })
  })
})
