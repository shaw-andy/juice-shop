/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as http from 'http'
import { Op } from 'sequelize'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import * as security from '../../lib/insecurity'
import { BasketModel } from '../../models/basket'
import { ChallengeModel } from '../../models/challenge'
import { UserModel } from '../../models/user'
import { retrieveCodeSnippet } from '../../routes/vulnCodeSnippet'

let app: Express
let server: http.Server
let serverPort: number

interface ScoreboardChallenge {
  id: number
  key: string
  solved: boolean
  hasCodingChallenge: boolean
  codingChallengeStatus: number
}

interface Session {
  id: number
  token: string
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  await new Promise<void>((resolve) => {
    server = http.createServer(app)
    registerWebsocketEvents(server)
    server.listen(0, () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') {
        serverPort = addr.port
      }
      resolve()
    })
  })
}, { timeout: 60000 })

after(() => {
  if (server) {
    server.close()
  }
})

async function openBystander (): Promise<{ socket: Socket, events: Array<{ key: string, codingChallengeStatus: number }> }> {
  const events: Array<{ key: string, codingChallengeStatus: number }> = []
  const socket = await new Promise<Socket>((resolve) => {
    const client = ioClient(`http://localhost:${serverPort}`, {
      reconnectionDelay: 0,
      forceNew: true
    })
    client.on('code challenge solved', (data: { key: string, codingChallengeStatus: number }) => {
      events.push(data)
    })
    client.on('connect', () => {
      resolve(client)
    })
  })
  return { socket, events }
}

async function scoreboard (token?: string): Promise<ScoreboardChallenge[]> {
  const req = request(app).get('/api/Challenges')
  if (token !== undefined) {
    req.set('Authorization', 'Bearer ' + token)
  }
  const res = await req
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data.map((row: ScoreboardChallenge) => ({
    id: row.id,
    key: row.key,
    solved: row.solved,
    hasCodingChallenge: row.hasCodingChallenge,
    codingChallengeStatus: Number(row.codingChallengeStatus)
  }))
}

function codingChallenges (rows: ScoreboardChallenge[]): ScoreboardChallenge[] {
  return rows.filter((row) => row.hasCodingChallenge)
}

async function sessions (): Promise<[Session, Session]> {
  const users = await UserModel.findAll({
    attributes: ['id', 'email', 'role'],
    order: [['id', 'ASC']],
    limit: 2
  })
  assert.equal(users.length, 2)
  const opened: Session[] = []
  for (const user of users) {
    const basket = await BasketModel.findOne({ where: { UserId: user.id } })
    assert.ok(basket)
    const authenticatedUser = {
      data: { id: user.id, email: user.email, role: user.role },
      bid: basket.id
    }
    const token = security.authorize(authenticatedUser)
    security.authenticatedUsers.put(token, authenticatedUser as never)
    opened.push({ id: user.id, token })
  }
  return opened as [Session, Session]
}

async function resetCodingStatus (): Promise<void> {
  await ChallengeModel.update(
    { codingChallengeStatus: 0 },
    { where: { id: { [Op.gte]: 1 } } }
  )
}

void describe('shared coding-challenge solve state', () => {
  let bystander: Awaited<ReturnType<typeof openBystander>>

  beforeEach(async () => {
    await resetCodingStatus()
    bystander = await openBystander()
  })

  afterEach(() => {
    if (bystander?.socket.connected) {
      bystander.socket.disconnect()
    }
  })

  void it('anonymous fix-index guesses do not solve a coding challenge for the instance', async () => {
    const before = await scoreboard()
    const targets = codingChallenges(before)
    assert.ok(targets.length > 0)

    let guesses = 0
    for (const challenge of targets) {
      const listed = await request(app).get('/snippets/fixes/' + challenge.key)
      const optionCount = Array.isArray(listed.body?.fixes) ? listed.body.fixes.length : 0
      const attempts = Math.max(optionCount, 8)
      for (let selectedFix = 0; selectedFix < attempts; selectedFix++) {
        guesses++
        const res = await request(app)
          .post('/snippets/fixes')
          .send({ key: challenge.key, selectedFix })
        const seenByOthers = (await scoreboard()).find((row) => row.key === challenge.key)
        const fixedIt = (await request(app).get('/rest/continue-code-fixIt')).body.continueCode
        assert.ok(
          (res.status === 401 || res.status === 403) &&
            res.body?.verdict !== true &&
            seenByOthers?.codingChallengeStatus === 0 &&
            fixedIt === undefined &&
            bystander.events.length === 0,
          `anonymous POST /snippets/fixes key=${challenge.key} selectedFix=${selectedFix} status=${res.status} verdict=${String(res.body?.verdict)} codingChallengeStatus=${String(seenByOthers?.codingChallengeStatus)} continueCode=${String(fixedIt)} notifications=${bystander.events.length}`
        )
      }
    }
    assert.ok(guesses > 0)
  }, { timeout: 180000 })

  void it('an authenticated fix submission does not solve that challenge on anyone else\'s scoreboard', async () => {
    const [actor, other] = await sessions()
    const before = await scoreboard(other.token)
    const targets = codingChallenges(before)
    assert.ok(targets.length > 0)

    for (const challenge of targets) {
      const listed = await request(app)
        .get('/snippets/fixes/' + challenge.key)
        .set('Authorization', 'Bearer ' + actor.token)
      const optionCount = Array.isArray(listed.body?.fixes) ? listed.body.fixes.length : 0
      const attempts = Math.max(optionCount, 8)
      for (let selectedFix = 0; selectedFix < attempts; selectedFix++) {
        await request(app)
          .post('/snippets/fixes')
          .set('Authorization', 'Bearer ' + actor.token)
          .send({ key: challenge.key, selectedFix })
        const seenByOther = (await scoreboard(other.token)).find((row) => row.id === challenge.id)
        const seenAnonymously = (await scoreboard()).find((row) => row.id === challenge.id)
        const fixedIt = (await request(app).get('/rest/continue-code-fixIt')).body.continueCode
        assert.equal(seenByOther?.codingChallengeStatus, 0, `user ${other.id} scoreboard changed for ${challenge.key} after user ${actor.id} submitted selectedFix ${selectedFix}`)
        assert.equal(seenAnonymously?.codingChallengeStatus, 0, `anonymous scoreboard changed for ${challenge.key} after user ${actor.id} submitted selectedFix ${selectedFix}`)
        assert.equal(seenByOther?.key, challenge.key)
        assert.equal(fixedIt, undefined)
        assert.equal(bystander.events.length, 0)
      }
    }
  }, { timeout: 180000 })

  void it('find-it verdicts do not solve a coding challenge on the shared scoreboard', async () => {
    const [actor, other] = await sessions()
    const targets = codingChallenges(await scoreboard())
    let submitted = 0
    for (const challenge of targets) {
      const snippet = await retrieveCodeSnippet(challenge.key)
      if (snippet == null) {
        continue
      }
      submitted++
      const anonymous = await request(app)
        .post('/snippets/verdict')
        .send({ key: challenge.key, selectedLines: snippet.vulnLines })
      const afterAnonymous = (await scoreboard(other.token)).find((row) => row.id === challenge.id)
      const foundIt = (await request(app).get('/rest/continue-code-findIt')).body.continueCode
      assert.ok(
        (anonymous.status === 401 || anonymous.status === 403) &&
          anonymous.body?.verdict !== true &&
          afterAnonymous?.codingChallengeStatus === 0 &&
          foundIt === undefined &&
          bystander.events.length === 0,
        `anonymous POST /snippets/verdict key=${challenge.key} status=${anonymous.status} verdict=${String(anonymous.body?.verdict)} codingChallengeStatus=${String(afterAnonymous?.codingChallengeStatus)}`
      )

      await request(app)
        .post('/snippets/verdict')
        .set('Authorization', 'Bearer ' + actor.token)
        .send({ key: challenge.key, selectedLines: snippet.vulnLines })
      const seenByOther = (await scoreboard(other.token)).find((row) => row.id === challenge.id)
      assert.equal(seenByOther?.codingChallengeStatus, 0, `user ${other.id} scoreboard changed for ${challenge.key} after user ${actor.id} submitted find-it lines`)
      assert.equal(seenByOther?.key, challenge.key)
      assert.equal(bystander.events.length, 0)
    }
    assert.ok(submitted > 0)
  }, { timeout: 180000 })
})
