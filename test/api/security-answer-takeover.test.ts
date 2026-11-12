/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { users } from '../../data/datacache'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

let app: Express
let questionId: number

const jsonHeader = { 'content-type': 'application/json' }
const chosenAnswer = 'placeholder-security-answer'
const chosenPassword = 'placeholder-new-password'
const registrationPassword = 'placeholder-registration-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
  const questions = await request(app).get('/api/SecurityQuestions')
  assert.equal(questions.status, 200)
  questionId = questions.body.data[0].id
  assert.equal(typeof questionId, 'number')
}, { timeout: 120000 })

void describe('security answer takeover', { concurrency: 1 }, () => {
  void it('rejects an unauthenticated answer and password reset for every privileged account that has no answer', async () => {
    const targets = await unansweredPrivilegedUsers()
    const targetIds = new Set(targets.map((user) => user.id))
    assert.ok(targetIds.has(users.LetUsTest.id))
    assert.ok(targetIds.has(users.bjoernGoogle.id))

    const problems: string[] = []
    for (const [index, user] of targets.entries()) {
      const paths = index % 2 === 0
        ? ['/api/SecurityAnswers/', '/api/SecurityAnswers']
        : ['/api/SecurityAnswers', '/api/SecurityAnswers/']
      problems.push(...await takeover(user.id, user.email, {}, paths))
    }
    assert.equal(problems.length, 0, problems.join('; '))
  })

  void it('rejects a logged-in user setting the security answer of a different account', async () => {
    const caller = await registerUser('takeover-caller')
    const callerLogin = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: caller.email, password: registrationPassword })
    assert.equal(callerLogin.status, 200)
    const callerToken = callerLogin.body.authentication.token
    assert.equal(typeof callerToken, 'string')

    const target = await registerUser('takeover-target')
    const problems = await takeover(target.id, target.email, { Authorization: 'Bearer ' + callerToken })
    const targetStillLogsIn = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: target.email, password: registrationPassword })
    if (targetStillLogsIn.status !== 200) {
      problems.push(`target login with the registration password returned ${targetStillLogsIn.status}`)
    }
    const targetSession = sessionOf(targetStillLogsIn.body?.authentication?.token)
    if (targetStillLogsIn.status === 200 && targetSession.role !== 'customer') {
      problems.push(`target session role ${String(targetSession.role)}`)
    }
    assert.equal(problems.length, 0, problems.join('; '))
  })

  void it('rejects the unauthenticated security-answer call that follows user registration', async () => {
    const target = await registerUser('takeover-race')
    const problems = await takeover(target.id, target.email, {})
    const targetStillLogsIn = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: target.email, password: registrationPassword })
    if (targetStillLogsIn.status !== 200) {
      problems.push(`registered user login returned ${targetStillLogsIn.status}`)
    }
    assert.equal(problems.length, 0, problems.join('; '))
  })
})

async function unansweredPrivilegedUsers () {
  const privileged = await UserModel.findAll({
    where: { role: ['admin', 'accounting', 'deluxe'] }
  })
  const answers = await SecurityAnswerModel.findAll({ attributes: ['UserId'] })
  const answered = new Set(answers.map((answer) => answer.UserId))
  return privileged.filter((user) => !answered.has(user.id))
}

async function registerUser (prefix: string) {
  const email = `${prefix}-${Date.now()}@example.test`
  const res = await request(app)
    .post('/api/Users/')
    .set(jsonHeader)
    .send({
      email,
      password: registrationPassword,
      passwordRepeat: registrationPassword
    })
  assert.equal(res.status, 201)
  assert.equal(typeof res.body.data.id, 'number')
  return { id: res.body.data.id as number, email }
}

async function takeover (userId: number, email: string, authorization: Record<string, string>, paths = ['/api/SecurityAnswers/', '/api/SecurityAnswers']) {
  const problems: string[] = []

  for (const answerPath of paths) {
    const before = await SecurityAnswerModel.count({ where: { UserId: userId } })
    const createRes = await request(app)
      .post(answerPath)
      .set(jsonHeader)
      .set(authorization)
      .send({
        UserId: userId,
        SecurityQuestionId: questionId,
        answer: chosenAnswer
      })
    const after = await SecurityAnswerModel.count({ where: { UserId: userId } })
    if (after !== before) {
      problems.push(`${answerPath} stored a security answer for user ${userId} (status ${createRes.status})`)
    }
    if (createRes.status < 400) {
      problems.push(`${answerPath} create status ${createRes.status}`)
    }
    if (after !== before) break
  }

  for (const method of ['put', 'patch'] as const) {
    const before = await SecurityAnswerModel.count({ where: { UserId: userId } })
    const updateRes = await request(app)[method](`/api/SecurityAnswers/${userId}`)
      .set(jsonHeader)
      .set(authorization)
      .send({
        UserId: userId,
        SecurityQuestionId: questionId,
        answer: chosenAnswer
      })
    const after = await SecurityAnswerModel.count({ where: { UserId: userId } })
    if (after !== before || updateRes.status < 400) {
      problems.push(`${method.toUpperCase()} /api/SecurityAnswers/${userId} status ${updateRes.status} changed the answer count from ${before} to ${after}`)
    }
  }

  const resetRes = await request(app)
    .post('/rest/user/reset-password')
    .set(jsonHeader)
    .send({
      email,
      answer: chosenAnswer,
      new: chosenPassword,
      repeat: chosenPassword
    })
  if (resetRes.status < 400) problems.push(`reset status ${resetRes.status} for ${email}`)

  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password: chosenPassword })
  const token = loginRes.body?.authentication?.token
  const session = sessionOf(token)
  if (loginRes.status !== 401 || typeof token === 'string') {
    problems.push(`login status ${loginRes.status} role=${session.role ?? ''} email=${session.email ?? ''}`)
  }

  if (loginRes.status === 200 && typeof token === 'string') {
    const usersRes = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: 'Bearer ' + token })
    const listed = Array.isArray(usersRes.body?.data) && usersRes.body.data.some((row: { email?: string }) => row.email === email)
    if (usersRes.status < 400 && listed) {
      problems.push(`authentication-details status ${usersRes.status} listed ${email}`)
    }
    const feedbackRes = await request(app)
      .get('/api/Feedbacks/')
      .set({ Authorization: 'Bearer ' + token })
    const feedbackCount = Array.isArray(feedbackRes.body?.data) ? feedbackRes.body.data.length : 0
    if (feedbackRes.status < 400 && feedbackCount > 0 && session.role === 'admin') {
      problems.push(`feedback list status ${feedbackRes.status} rows ${feedbackCount}`)
    }
  }

  return problems
}

function sessionOf (token: unknown) {
  if (typeof token !== 'string') return {}
  const decoded = security.decode(token)
  const payload = typeof decoded === 'string' ? JSON.parse(decoded) : decoded
  return {
    role: payload?.data?.role as string | undefined,
    email: payload?.data?.email as string | undefined
  }
}
