/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import config from 'config'
import type { Express } from 'express'
import * as http from 'http'
import { io as ioClient } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { challenges, notifications } from '../../data/datacache'
import { ChallengeModel, type ChallengeKey } from '../../models/challenge'
import * as security from '../../lib/insecurity'

let app: Express
let server: http.Server
let serverPort: number

const sockets: Array<ReturnType<typeof ioClient>> = []

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
  for (const socket of sockets) {
    socket.close()
  }
  if (server) {
    server.close()
  }
})

void describe('unauthenticated socket events must not mark challenges solved', () => {
  void it('verifyLocalXssChallenge does not solve the DOM XSS challenge', async () => {
    const payload = '<iframe src="javascript:alert(`xss`)">'
    await expectUnauthenticatedEmitDoesNotSolve('localXssChallenge', 'verifyLocalXssChallenge', payload)
  }, { timeout: 20000 })

  void it('verifyLocalXssChallenge does not solve the bonus payload challenge', async () => {
    const payload = config.get<string>('challenges.xssBonusPayload')
    assert.equal(payload.includes('<iframe'), true)
    await expectUnauthenticatedEmitDoesNotSolve('xssBonusChallenge', 'verifyLocalXssChallenge', payload)
  }, { timeout: 20000 })

  void it('verifySvgInjectionChallenge does not solve the cross-site imaging challenge', async () => {
    const payload = '../../../redirect?to=https://cataas.com/cat/https://github.com/juice-shop/juice-shop'
    assert.match(payload, /.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/cataas.com\/cat.*/)
    assert.equal(security.isRedirectAllowed(payload), true)
    await expectUnauthenticatedEmitDoesNotSolve('svgInjectionChallenge', 'verifySvgInjectionChallenge', payload)
  }, { timeout: 20000 })

  void it('verifyCloseNotificationsChallenge does not solve the mass dispel challenge', async () => {
    const payload = [{ closed: true }, { closed: true }]
    assert.equal(Array.isArray(payload) && payload.length > 1, true)
    await expectUnauthenticatedEmitDoesNotSolve('closeNotificationsChallenge', 'verifyCloseNotificationsChallenge', payload)
  }, { timeout: 20000 })
})

async function expectUnauthenticatedEmitDoesNotSolve (key: ChallengeKey, event: string, payload: unknown) {
  await resetChallenge(key)
  const attacker = openSocket()
  let emitted = false
  attacker.on('challenge solved', (data: { key?: string }) => {
    if (data?.key === key) emitted = true
  })
  const connected = await waitForConnect(attacker)
  let replayed = false
  if (connected) {
    attacker.emit(event, payload)
    const deadline = Date.now() + 2000
    while (Date.now() < deadline) {
      if (challenges[key].solved === true && await persistedSolved(key) && notifications.some((notification) => notification.key === key) && emitted) {
        break
      }
      await delay(25)
    }
    replayed = await laterClientReceives(key)
  }
  const memory = challenges[key].solved === true
  const database = await persistedSolved(key)
  const listed = notifications.some((notification) => notification.key === key)
  const scoreboard = await scoreboardSolved(key)
  assert.equal(
    memory || database || listed || emitted || replayed || scoreboard,
    false,
    `unauthenticated ${event} (connected=${connected}) marked ${key} solved: memory=${memory} database=${database} listed=${listed} emitted=${emitted} replayed=${replayed} scoreboard=${scoreboard}`
  )
}

function openSocket () {
  const socket = ioClient(`http://127.0.0.1:${serverPort}`, {
    reconnection: false,
    forceNew: true,
    timeout: 5000,
    transports: ['websocket']
  })
  sockets.push(socket)
  return socket
}

async function waitForConnect (socket: ReturnType<typeof ioClient>) {
  if (socket.connected) return true
  return await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => { resolve(false) }, 5000)
    socket.on('connect', () => {
      clearTimeout(timer)
      resolve(true)
    })
    socket.on('connect_error', () => {
      clearTimeout(timer)
      resolve(false)
    })
  })
}

async function laterClientReceives (key: string) {
  const socket = openSocket()
  let saw = false
  socket.on('challenge solved', (data: { key?: string }) => {
    if (data?.key === key) saw = true
  })
  if (await waitForConnect(socket)) {
    await delay(300)
  }
  socket.close()
  return saw
}

async function resetChallenge (key: ChallengeKey) {
  const challenge = challenges[key]
  assert.ok(challenge)
  challenge.solved = false
  await challenge.save()
  for (let i = notifications.length - 1; i >= 0; i--) {
    if (notifications[i].key === key) {
      notifications.splice(i, 1)
    }
  }
  assert.equal(challenge.solved, false)
  assert.equal(await persistedSolved(key), false)
}

async function persistedSolved (key: ChallengeKey) {
  const row = await ChallengeModel.findOne({
    attributes: ['solved'],
    where: { key },
    raw: true
  }) as { solved: boolean | number } | null
  return row?.solved === true || row?.solved === 1
}

async function scoreboardSolved (key: ChallengeKey) {
  const response = await fetch(`http://127.0.0.1:${serverPort}/api/Challenges`)
  assert.equal(response.status, 200)
  const body = await response.json() as { data: Array<{ key: string, solved: boolean | number }> }
  const row = body.data.find((item) => item.key === key)
  assert.ok(row)
  return row.solved === true || row.solved === 1
}

function delay (ms: number) {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}
