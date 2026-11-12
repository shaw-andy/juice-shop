/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('math CAPTCHA answer disclosure', { concurrency: false }, () => {
  void it('GET /rest/captcha does not reveal a solution that POST /api/Feedbacks will accept', async () => {
    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.equal(typeof captchaRes.body.captcha, 'string')

    const solution = solveMathCaptcha(captchaRes.body.captcha)
    const comment = `captcha-leak-${String(captchaRes.body.captchaId)}-${solution}`
    const posted = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment,
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: valueTakenFromCaptchaResponse(captchaRes.body, solution)
      })

    const list = await request(app).get('/api/Feedbacks')
    assert.equal(list.status, 200)

    assert.equal(posted.status, 401)
    assert.equal(feedbackComments(list.body).includes(comment), false)
    assert.equal(disclosedSolutions(captchaRes.body, solution).length, 0)
  })

  void it('a solved math CAPTCHA authorizes one feedback post and then rejects the same answer', async () => {
    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    const solution = solveMathCaptcha(captchaRes.body.captcha)
    const firstComment = `captcha-once-a-${String(captchaRes.body.captchaId)}`
    const secondComment = `captcha-once-b-${String(captchaRes.body.captchaId)}`

    const first = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: firstComment,
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: solution
      })
    const second = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: secondComment,
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: solution
      })

    const list = await request(app).get('/api/Feedbacks')
    const comments = feedbackComments(list.body)

    assert.equal(first.status, 201)
    assert.equal(comments.includes(firstComment), true)
    assert.equal(second.status, 401)
    assert.equal(comments.includes(secondComment), false)
  })

  void it('GET /rest/image-captcha does not reveal an answer that POST /rest/user/data-export will accept', async () => {
    const email = 'captcha-leak-probe@juice-sh.op'
    const password = 'placeholder-password'
    await register(app, { email, password })
    const { token } = await login(app, { email, password })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(authHeader)
    assert.equal(captchaRes.status, 200)

    const rejected = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ answer: 'placeholder-wrong-answer', format: 1 })
    assert.equal(rejected.status, 401)
    assert.equal(rejected.body?.userData, undefined)

    const exported = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({
        answer: valueTakenFromCaptchaResponse(captchaRes.body),
        format: 1
      })

    assert.equal(exported.status, 401)
    assert.equal(exported.body?.userData, undefined)
    assert.equal(disclosedImageCaptchaAnswers(captchaRes.body).length, 0)
  })
})

function solveMathCaptcha (expression: string): string {
  const match = /^(10|[1-9])([*+-])(10|[1-9])([*+-])(10|[1-9])$/.exec(expression)
  assert.ok(match)
  const left = Number(match[1])
  const firstOperator = match[2]
  const middle = Number(match[3])
  const secondOperator = match[4]
  const right = Number(match[5])
  const value = secondOperator === '*' && firstOperator !== '*'
    ? applyOperator(left, firstOperator, applyOperator(middle, secondOperator, right))
    : applyOperator(applyOperator(left, firstOperator, middle), secondOperator, right)
  return String(value)
}

function applyOperator (left: number, operator: string, right: number): number {
  if (operator === '+') return left + right
  if (operator === '-') return left - right
  return left * right
}

interface PrimitiveField {
  path: string
  value: string
  original: unknown
}

function primitiveFields (value: unknown, path = ''): PrimitiveField[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => primitiveFields(item, `${path}[${index}]`))
  }
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, item]) => primitiveFields(item, `${path}.${key}`))
  }
  if (typeof value === 'undefined') return []
  return [{ path, value: String(value), original: value }]
}

function disclosedSolutions (body: unknown, solution: string): PrimitiveField[] {
  return primitiveFields(body).filter((field) => {
    return field.path !== '.captchaId' && field.path !== '.captcha' && field.value === solution
  })
}

function disclosedImageCaptchaAnswers (body: unknown): PrimitiveField[] {
  return primitiveFields(body).filter((field) => field.path !== '.image' && field.path !== '.UserId')
}

function valueTakenFromCaptchaResponse (body: { answer?: unknown }, solution?: string): unknown {
  if (Object.hasOwn(body, 'answer')) return body.answer
  if (solution === undefined) return undefined
  return disclosedSolutions(body, solution)[0]?.original
}

function feedbackComments (body: { data?: Array<{ comment?: string }> }): string[] {
  return (body.data ?? []).map((row) => row.comment ?? '')
}
