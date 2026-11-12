/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * Spec for the coding-challenge snippet and verdict routes.
 * These tests fail while those routes accept anonymous callers, echo the stored
 * vulnerable line numbers, or record a solve for every user of the process.
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import * as http from 'http'
import request from 'supertest'
import type { Express } from 'express'
import yaml from 'js-yaml'
import { io as ioClient } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { getCodeChallenges } from '../../lib/codingChallenges'
import { readFixes } from '../../routes/vulnCodeFixes'

const PLACEHOLDER_PASSWORD = 'placeholder-password'
const USER_A_EMAIL = 'coding-challenge-a@example.test'
const USER_B_EMAIL = 'coding-challenge-b@example.test'
const SINGLE_LINE_KEY = 'loginAdminChallenge'
const MULTI_LINE_KEY = 'directoryListingChallenge'
const FIND_IT_OWNER_KEY = 'accessLogDisclosureChallenge'
const FIX_IT_OWNER_KEY = 'resetPasswordBenderChallenge'

interface ScoreboardRow {
  id: number
  key: string
  codingChallengeStatus: number
}

interface CodeChallengeEvent {
  key: string
  codingChallengeStatus: number
}

let app: Express
let server: http.Server
let serverPort: number
let tokenA: string
let tokenB: string
let userBId: number
let bystander: ReturnType<typeof ioClient>
const codeChallengeEvents: CodeChallengeEvent[] = []

before(async () => {
  const result = await createTestApp()
  app = result.app
  await new Promise<void>((resolve) => {
    server = http.createServer(app)
    registerWebsocketEvents(server)
    server.listen(0, () => {
      const addr = server.address()
      if (addr !== null && typeof addr === 'object') {
        serverPort = addr.port
      }
      resolve()
    })
  })
  bystander = ioClient(`http://127.0.0.1:${serverPort}`, {
    reconnectionDelay: 0,
    forceNew: true
  })
  bystander.on('code challenge solved', (data: CodeChallengeEvent) => {
    codeChallengeEvents.push(data)
  })
  await new Promise<void>((resolve) => {
    bystander.on('connect', () => { resolve() })
  })
  const registeredB = await register(app, { email: USER_B_EMAIL, password: PLACEHOLDER_PASSWORD })
  userBId = registeredB.body.data.id
  await register(app, { email: USER_A_EMAIL, password: PLACEHOLDER_PASSWORD })
  tokenA = (await login(app, { email: USER_A_EMAIL, password: PLACEHOLDER_PASSWORD })).token
  tokenB = (await login(app, { email: USER_B_EMAIL, password: PLACEHOLDER_PASSWORD })).token
}, { timeout: 60000 })

after(() => {
  if (bystander !== undefined) {
    bystander.disconnect()
  }
  if (server !== undefined) {
    server.close()
  }
})

async function challengeKeys (): Promise<string[]> {
  const codeChallenges = await getCodeChallenges()
  return [...codeChallenges.keys()]
}

async function storedLines (key: string): Promise<number[]> {
  const codeChallenges = await getCodeChallenges()
  const challenge = codeChallenges.get(key)
  assert.ok(challenge, key)
  return challenge.vulnLines
}

async function hintCount (key: string): Promise<number> {
  const raw = await fs.readFile(`./data/static/codefixes/${key}.info.yml`, 'utf8')
  const info = yaml.load(raw) as { hints?: string[] }
  return info.hints?.length ?? 0
}

async function scoreboard (token?: string): Promise<ScoreboardRow[]> {
  const req = request(app).get('/api/Challenges/')
  if (token !== undefined) {
    req.set('Authorization', 'Bearer ' + token)
  }
  const res = await req
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

async function statusFor (key: string, token?: string): Promise<number> {
  const rows = await scoreboard(token)
  const row = rows.find((challenge) => challenge.key === key)
  assert.ok(row, key)
  return row.codingChallengeStatus
}

async function findItContinueCode (token?: string): Promise<string | undefined> {
  const req = request(app).get('/rest/continue-code-findIt')
  if (token !== undefined) {
    req.set('Authorization', 'Bearer ' + token)
  }
  const res = await req
  assert.equal(res.status, 200)
  return res.body.continueCode
}

function bodyRevealsLines (body: unknown, lines: number[]): boolean {
  const text = JSON.stringify(body)
  if (!/responsible for this vulnerability/.test(text)) {
    return false
  }
  return lines.every((line) => new RegExp(`(?<!\\d)${line}(?!\\d)`).test(text))
}

async function settleBroadcast (): Promise<void> {
  await new Promise((resolve) => { setTimeout(resolve, 400) })
}

void describe('coding challenge snippet authorization', { concurrency: 1 }, () => {
  void it('does not serve any challenge snippet without a logged-in session', async () => {
    for (const key of await challengeKeys()) {
      const res = await request(app).get('/snippets/' + key)
      assert.equal(res.status, 401)
      assert.equal(res.body.snippet, undefined)
    }
  })

  void it('does not serve fix options without a logged-in session', async () => {
    for (const key of await challengeKeys()) {
      const fixes = readFixes(key)
      if (fixes.fixes.length === 0) {
        continue
      }
      const res = await request(app).get('/snippets/fixes/' + key)
      assert.equal(res.status, 401)
      assert.equal(res.body.fixes, undefined)
    }
  })

  void it('logged-in callers can still load a snippet and its fix options', async () => {
    const snippet = await request(app)
      .get('/snippets/' + SINGLE_LINE_KEY)
      .set('Authorization', 'Bearer ' + tokenA)
    assert.equal(snippet.status, 200)
    assert.equal(typeof snippet.body.snippet, 'string')

    const fixes = await request(app)
      .get('/snippets/fixes/' + FIX_IT_OWNER_KEY)
      .set('Authorization', 'Bearer ' + tokenA)
    assert.equal(fixes.status, 200)
    assert.ok(Array.isArray(fixes.body.fixes))
    assert.ok(fixes.body.fixes.length > 0)
    assert.equal(fixes.body.correct, undefined)
  })
})

void describe('coding challenge verdict authorization', { concurrency: 1 }, () => {
  void it('does not echo stored vulnerable lines to an anonymous caller', async () => {
    for (const key of [MULTI_LINE_KEY, SINGLE_LINE_KEY]) {
      const lines = await storedLines(key)
      assert.ok(lines.length > 0)
      if (key === MULTI_LINE_KEY) {
        assert.ok(lines.length > 1)
      }
      const before = await statusFor(key)
      const attempts = (await hintCount(key)) + 2
      const responses = []
      for (let i = 0; i < attempts; i++) {
        responses.push(await request(app)
          .post('/snippets/verdict')
          .send({ key, selectedLines: i % 2 === 0 ? [] : [99999] }))
      }
      for (const res of responses) {
        assert.equal(bodyRevealsLines(res.body, lines), false, JSON.stringify(res.body))
        assert.notEqual(res.body.verdict, true)
      }
      assert.equal(await statusFor(key), before)
      for (const res of responses) {
        assert.equal(res.status, 401)
      }
    }
  })

  void it('does not echo stored vulnerable lines to a logged-in caller', async () => {
    for (const key of [MULTI_LINE_KEY, SINGLE_LINE_KEY]) {
      const lines = await storedLines(key)
      const before = await statusFor(key, tokenA)
      const attempts = (await hintCount(key)) + 2
      for (let i = 0; i < attempts; i++) {
        const res = await request(app)
          .post('/snippets/verdict')
          .set('Authorization', 'Bearer ' + tokenA)
          .send({ key, selectedLines: [99999] })
        assert.equal(res.status, 200)
        assert.equal(res.body.verdict, false)
        assert.equal(bodyRevealsLines(res.body, lines), false, JSON.stringify(res.body))
      }
      assert.equal(await statusFor(key, tokenA), before)
      assert.equal(await statusFor(key, tokenB), before)
    }
  })

  void it('does not record an anonymous find-it solve on the shared scoreboard', async () => {
    const seenAtStart = codeChallengeEvents.length
    for (const key of await challengeKeys()) {
      const lines = await storedLines(key)
      const before = await statusFor(key)
      const otherBefore = await findItContinueCode(tokenB)
      const res = await request(app)
        .post('/snippets/verdict')
        .send({ key, selectedLines: lines, UserId: userBId })
      await settleBroadcast()
      const broadcast = codeChallengeEvents.slice(seenAtStart)
      assert.equal(await statusFor(key), before, JSON.stringify({ body: res.body, broadcast }))
      assert.equal(await statusFor(key, tokenB), before)
      assert.equal(await findItContinueCode(tokenB), otherBefore)
      assert.deepEqual(broadcast, [])
      assert.notEqual(res.body.verdict, true)
      assert.equal(res.status, 401)
    }
  })

  void it('records a find-it solve only for the logged-in caller', async () => {
    const lines = await storedLines(FIND_IT_OWNER_KEY)
    const callerBefore = await statusFor(FIND_IT_OWNER_KEY, tokenA)
    const otherBefore = await statusFor(FIND_IT_OWNER_KEY, tokenB)
    const anonymousBefore = await statusFor(FIND_IT_OWNER_KEY)
    const otherContinueBefore = await findItContinueCode(tokenB)
    const seenAtStart = codeChallengeEvents.length
    assert.equal(callerBefore, 0)
    assert.equal(otherBefore, 0)

    const res = await request(app)
      .post('/snippets/verdict')
      .set('Authorization', 'Bearer ' + tokenA)
      .send({ key: FIND_IT_OWNER_KEY, selectedLines: lines, UserId: userBId })

    assert.equal(res.status, 200)
    assert.equal(res.body.verdict, true)
    await settleBroadcast()
    const broadcast = codeChallengeEvents.slice(seenAtStart)
    assert.deepEqual(broadcast.filter((event) => event.key === FIND_IT_OWNER_KEY), [], JSON.stringify(broadcast))
    assert.equal(await statusFor(FIND_IT_OWNER_KEY, tokenA), 1)
    assert.equal(await statusFor(FIND_IT_OWNER_KEY, tokenB), otherBefore)
    assert.equal(await statusFor(FIND_IT_OWNER_KEY), anonymousBefore)
    assert.equal(await findItContinueCode(tokenB), otherContinueBefore)
    const callerContinue = await findItContinueCode(tokenA)
    assert.notEqual(callerContinue, otherContinueBefore)
  })

  void it('does not record an anonymous fix-it solve', async () => {
    const correct = readFixes(FIX_IT_OWNER_KEY).correct
    assert.ok(correct >= 0)
    const before = await statusFor(FIX_IT_OWNER_KEY)
    const seenAtStart = codeChallengeEvents.length
    const res = await request(app)
      .post('/snippets/fixes')
      .send({ key: FIX_IT_OWNER_KEY, selectedFix: correct, UserId: userBId })
    await settleBroadcast()
    const broadcast = codeChallengeEvents.slice(seenAtStart)
    assert.equal(await statusFor(FIX_IT_OWNER_KEY), before, JSON.stringify({ body: res.body, broadcast }))
    assert.equal(await statusFor(FIX_IT_OWNER_KEY, tokenB), before)
    assert.deepEqual(broadcast, [])
    assert.notEqual(res.body.verdict, true)
    assert.equal(res.status, 401)
  })

  void it('records a fix-it solve only for the logged-in caller', async () => {
    const correct = readFixes(SINGLE_LINE_KEY).correct
    assert.ok(correct >= 0)
    const otherBefore = await statusFor(SINGLE_LINE_KEY, tokenB)
    const seenAtStart = codeChallengeEvents.length
    const res = await request(app)
      .post('/snippets/fixes')
      .set('Authorization', 'Bearer ' + tokenA)
      .send({ key: SINGLE_LINE_KEY, selectedFix: correct, UserId: userBId })
    assert.equal(res.status, 200)
    assert.equal(res.body.verdict, true)
    await settleBroadcast()
    const broadcast = codeChallengeEvents.slice(seenAtStart)
    assert.deepEqual(broadcast.filter((event) => event.key === SINGLE_LINE_KEY), [], JSON.stringify(broadcast))
    assert.equal(await statusFor(SINGLE_LINE_KEY, tokenA), 2)
    assert.equal(await statusFor(SINGLE_LINE_KEY, tokenB), otherBefore)
    assert.notEqual(await statusFor(SINGLE_LINE_KEY), 2)
  })
})
