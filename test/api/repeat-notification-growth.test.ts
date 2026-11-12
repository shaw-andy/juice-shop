/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import request from 'supertest'
import type { Express } from 'express'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { notifications, challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'

const repeatTimes = 20

let app: Express
let server: http.Server
let serverPort: number

interface ListedChallenge {
  key: string
  name: string
  solved: boolean
}

function noticesFor (key: string) {
  return notifications.filter(notification => notification.key === key)
}

async function waitUntil (predicate: () => boolean, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() > deadline) return false
    await new Promise(resolve => { setTimeout(resolve, 20) })
  }
  return true
}

async function listedChallenges () {
  const res = await request(app).get('/api/Challenges')
  assert.equal(res.status, 200)
  const data: unknown = res.body.data
  assert.ok(Array.isArray(data))
  return data as ListedChallenge[]
}

async function repeatByName (name: string, times: number, authorization?: string) {
  await Promise.all(Array.from({ length: times }, async () => {
    let pending = request(app).get('/rest/repeat-notification').query({ challenge: name })
    if (authorization !== undefined) {
      pending = pending.set('Authorization', authorization)
    }
    const res = await pending
    assert.ok(res.status < 500)
  }))
}

async function solvePublicChallenge (url: string, key: 'scoreBoardChallenge' | 'securityPolicyChallenge') {
  const challenge = challenges[key]
  challenge.solved = false
  await challenge.save()
  for (let i = notifications.length - 1; i >= 0; i--) {
    if (notifications[i].key === key) notifications.splice(i, 1)
  }
  await request(app).get(url)
  const stored = await waitUntil(() => {
    return challenge.solved === true && noticesFor(key).length >= 1
  }, 5000)
  assert.equal(stored, true)
}

void describe('repeat-notification notice retention', () => {
  before(async () => {
    const result = await createTestApp()
    app = result.app
    await new Promise<void>((resolve) => {
      server = http.createServer(app)
      registerWebsocketEvents(server)
      server.listen(0, '127.0.0.1', () => {
        const address = server.address()
        if (address !== null && typeof address === 'object') {
          serverPort = address.port
        }
        resolve()
      })
    })
  }, { timeout: 60000 })

  beforeEach(() => {
    notifications.splice(0, notifications.length)
  })

  after(() => {
    server?.close()
  })

  void it('does not keep another notice for every anonymous repeat of a publicly listed solved challenge', async () => {
    await solvePublicChallenge('/assets/public/images/padding/1px.png', 'scoreBoardChallenge')
    await solvePublicChallenge('/security.txt', 'securityPolicyChallenge')

    const listed = await listedChallenges()
    const scoreBoard = listed.find(challenge => challenge.key === 'scoreBoardChallenge')
    const securityPolicy = listed.find(challenge => challenge.key === 'securityPolicyChallenge')
    if (scoreBoard === undefined || securityPolicy === undefined) {
      assert.fail('solved challenges were not listed')
    }
    assert.equal(scoreBoard.solved, true)
    assert.equal(securityPolicy.solved, true)

    await repeatByName(scoreBoard.name, repeatTimes)
    await repeatByName(securityPolicy.name, repeatTimes)

    assert.equal(noticesFor(scoreBoard.key).length, 1)
    assert.equal(noticesFor(securityPolicy.key).length, 1)
  })

  void it('does not keep another notice for every repeat sent with an Authorization header', async () => {
    await solvePublicChallenge('/assets/public/images/padding/1px.png', 'scoreBoardChallenge')

    const listed = await listedChallenges()
    const scoreBoard = listed.find(challenge => challenge.key === 'scoreBoardChallenge')
    if (scoreBoard === undefined) {
      assert.fail('solved challenge was not listed')
    }
    assert.equal(scoreBoard.solved, true)

    const authorization = security.authorize()
    await repeatByName(scoreBoard.name, repeatTimes, authorization)

    assert.equal(noticesFor(scoreBoard.key).length, 1)
  })

  void it('does not keep another notice for every restore of the same continue code', async () => {
    await solvePublicChallenge('/assets/public/images/padding/1px.png', 'scoreBoardChallenge')
    const before = noticesFor('scoreBoardChallenge').length
    assert.equal(before, 1)

    const codeResponse = await request(app).get('/rest/continue-code')
    assert.equal(codeResponse.status, 200)
    const continueCode: unknown = codeResponse.body.continueCode
    assert.equal(typeof continueCode, 'string')

    let retainedAnother = false
    for (let i = 0; i < repeatTimes; i++) {
      const res = await request(app).put('/rest/continue-code/apply/' + continueCode)
      assert.equal(res.status, 200)
      if (noticesFor('scoreBoardChallenge').length > 1) {
        retainedAnother = true
        break
      }
    }
    if (!retainedAnother) {
      retainedAnother = await waitUntil(() => noticesFor('scoreBoardChallenge').length > 1, 3000)
    }
    assert.equal(retainedAnother, false)
    assert.equal(noticesFor('scoreBoardChallenge').length, before)
  })

  void it('drops the stored notice with one acknowledgement after repeats', async () => {
    await solvePublicChallenge('/assets/public/images/padding/1px.png', 'scoreBoardChallenge')

    const listed = await listedChallenges()
    const scoreBoard = listed.find(challenge => challenge.key === 'scoreBoardChallenge')
    if (scoreBoard === undefined) {
      assert.fail('solved challenge was not listed')
    }

    await repeatByName(scoreBoard.name, repeatTimes)
    assert.equal(noticesFor(scoreBoard.key).length, 1)

    const flag = noticesFor(scoreBoard.key)[0].flag
    const socket: Socket = ioClient(`http://127.0.0.1:${serverPort}`, {
      reconnection: false,
      forceNew: true,
      transports: ['websocket']
    })
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', () => { resolve() })
        socket.once('connect_error', reject)
      })
      socket.emit('notification received', flag)
      const cleared = await waitUntil(() => noticesFor(scoreBoard.key).length === 0, 2000)
      assert.equal(cleared, true)
    } finally {
      socket.disconnect()
    }
  })
})
