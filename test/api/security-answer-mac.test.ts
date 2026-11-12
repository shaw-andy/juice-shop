/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'
import type { Memory as MemoryConfig } from '../../lib/config.schema'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const placeholderEmail = 'placeholder-reset@example.test'
const placeholderPassword = 'placeholder-original'
const placeholderAnswer = 'placeholder-answer'
const placeholderResetPassword = 'placeholder-reset'
const decoyAnswers = ['placeholder-decoy-one', 'placeholder-decoy-two']

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('security answer MAC key', { concurrency: 1 }, () => {
  void it('does not let a product-search reader reset a registered user by recomputing the HMAC', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: placeholderEmail,
        password: placeholderPassword
      })
    assert.equal(userRes.status, 201)
    assert.equal(typeof userRes.body.data.id, 'number')

    const answerRes = await request(app)
      .post('/api/SecurityAnswers')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + security.authorize() })
      .send({
        UserId: userRes.body.data.id,
        SecurityQuestionId: 1,
        answer: placeholderAnswer
      })
    assert.equal(answerRes.status, 201)

    await assertRecoveredAnswerDoesNotResetPassword({
      email: placeholderEmail,
      originalPassword: placeholderPassword,
      candidates: [placeholderAnswer, ...decoyAnswers]
    })
  })

  void it('does not let a product-search reader reset a startup-seeded user by recomputing the HMAC', async () => {
    const seeded = (await loadStaticUserData()).find((user) =>
      user.securityQuestion != null &&
      user.password != null &&
      user.deletedFlag !== true &&
      (user.totpSecret == null || user.totpSecret === '')
    )
    assert.ok(seeded, 'expected a seeded user with a security answer')

    await assertRecoveredAnswerDoesNotResetPassword({
      email: accountEmail(seeded),
      originalPassword: seeded.password,
      candidates: candidateAnswers(await loadStaticUserData())
    })
  })

  void it('does not let a product-search reader reset a memory-seeded user by recomputing the HMAC', async () => {
    const john = (await loadStaticUserData()).find((user) => user.key === 'john')
    assert.ok(john, 'expected the john seed user')
    const candidates = [
      ...candidateAnswers(await loadStaticUserData()),
      ...memoryAnswers()
    ]

    await assertRecoveredAnswerDoesNotResetPassword({
      email: accountEmail(john),
      originalPassword: john.password,
      candidates
    })
  })
})

async function assertRecoveredAnswerDoesNotResetPassword (options: {
  email: string
  originalPassword: string
  candidates: string[]
}) {
  const before = await loginStatus(options.email, options.originalPassword)
  assert.equal(before, 200)
  const unrelatedBefore = await loginStatus(options.email, placeholderResetPassword)
  assert.notEqual(unrelatedBefore, 200)

  const extracted = (await extractSecurityAnswers()).find((row) => row.email === options.email)
  assert.ok(extracted, 'product search did not return the stored security answer')

  const key = hmacKeyLiteralFromSource()
  const recovered = key == null
    ? undefined
    : recoverAnswer(key, extracted.mac, options.candidates)

  if (recovered != null) {
    await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: options.email,
        answer: recovered,
        new: placeholderResetPassword,
        repeat: placeholderResetPassword
      })
  }

  const takenOver = await loginStatus(options.email, placeholderResetPassword)
  assert.notEqual(takenOver, 200, 'password reset accepted an answer recovered by HMAC-SHA256 with the key literal from the hmac helper')

  const after = await loginStatus(options.email, options.originalPassword)
  assert.equal(after, 200, 'password reset replaced the previous password')
}

async function loginStatus (email: string, password: string): Promise<number> {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  return res.status
}

interface ExtractedAnswer {
  userId: string
  mac: string
  email: string
}

async function extractSecurityAnswers (): Promise<ExtractedAnswer[]> {
  const criteria = "')) union select SecurityAnswers.UserId, SecurityAnswers.answer, Users.email, '4','5','6','7','8','9' from SecurityAnswers inner join Users on Users.id = SecurityAnswers.UserId--"
  assert.ok(criteria.length <= 200)
  const res = await request(app)
    .get('/rest/products/search')
    .query({ q: criteria })
  assert.equal(res.status, 200)
  const rows = Array.isArray(res.body?.data) ? res.body.data : []
  return rows
    .filter((item: { price?: unknown, deluxePrice?: unknown, image?: unknown, name?: unknown, description?: unknown }) =>
      item?.price === '4' && item?.deluxePrice === '5' && item?.image === '6' &&
      typeof item.name === 'string' && typeof item.description === 'string'
    )
    .map((item: { id: unknown, name: string, description: string }) => ({
      userId: String(item.id),
      mac: item.name,
      email: item.description
    }))
}

function recoverAnswer (key: string, mac: string, candidates: string[]): string | undefined {
  for (const candidate of candidates) {
    const digest = crypto.createHmac('sha256', key).update(candidate).digest('hex')
    if (digest === mac) return candidate
  }
  return undefined
}

function hmacKeyLiteralFromSource (): string | undefined {
  const source = fs.readFileSync(path.resolve('lib/insecurity.ts'), 'utf8')
  const start = source.indexOf('export const hmac')
  if (start < 0) return undefined
  const nextExport = source.indexOf('\nexport ', start + 1)
  const fn = source.slice(start, nextExport === -1 ? source.length : nextExport)
  const literal = hmacKeyStringLiteral(fn)
  if (literal != null) return literal
  const identCall = fn.match(/createHmac\(\s*'sha256'\s*,\s*([A-Za-z_$][\w$]*)\s*\)/)
  if (identCall == null) return undefined
  return stringAssignedTo(source, identCall[1])
}

function hmacKeyStringLiteral (fn: string): string | undefined {
  const at = fn.indexOf('createHmac(')
  if (at < 0) return undefined
  const sha = fn.indexOf("'sha256'", at)
  if (sha < 0) return undefined
  const comma = fn.indexOf(',', sha)
  if (comma < 0) return undefined
  return readJsStringLiteral(fn.slice(comma + 1).trimStart())
}

function stringAssignedTo (source: string, name: string): string | undefined {
  const decl = new RegExp('(?:const|let|var)\\s+' + name + '\\s*=\\s*([\'"])')
  const match = decl.exec(source)
  if (match == null) return undefined
  return readJsStringLiteral(source.slice(match.index + match[0].length - 1))
}

function readJsStringLiteral (text: string): string | undefined {
  const quote = text[0]
  if (quote !== '\'' && quote !== '"') return undefined
  let value = ''
  for (let i = 1; i < text.length; i++) {
    const ch = text[i]
    if (ch === '\\') {
      const escaped = text[i + 1]
      if (escaped == null) return undefined
      if (escaped === 'n') value += '\n'
      else if (escaped === 'r') value += '\r'
      else if (escaped === 't') value += '\t'
      else value += escaped
      i++
      continue
    }
    if (ch === quote) return value
    value += ch
  }
  return undefined
}

function accountEmail (user: StaticUser): string {
  return user.customDomain === true ? user.email : `${user.email}@${config.get<string>('application.domain')}`
}

function candidateAnswers (users: StaticUser[]): string[] {
  return users.flatMap((user) => user.securityQuestion == null ? [] : [user.securityQuestion.answer])
}

function memoryAnswers (): string[] {
  const answers: string[] = []
  for (const memory of config.get<MemoryConfig[]>('memories')) {
    if (memory.geoStalkingMetaSecurityAnswer != null) answers.push(memory.geoStalkingMetaSecurityAnswer)
    if (memory.geoStalkingVisualSecurityAnswer != null) answers.push(memory.geoStalkingVisualSecurityAnswer)
  }
  return answers
}
