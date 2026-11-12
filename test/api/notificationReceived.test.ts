/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import type { Express } from 'express'
import * as http from 'http'
import { io as ioClient, type Socket } from 'socket.io-client'
import { type Server } from 'socket.io'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { notifications, type Notification } from '../../data/datacache'
import * as utils from '../../lib/utils'

const globalWithSocketIO = global as typeof globalThis & { io: Server }

const SCORE_BOARD_KEY = 'scoreBoardChallenge'
const SCORE_BOARD_NAME = 'Score Board'
const ADMIN_SECTION_KEY = 'adminSectionChallenge'
const ADMIN_SECTION_NAME = 'Admin Section'

let app: Express
let server: http.Server
let serverPort: number
let baseline: Notification[]
const openSockets: Socket[] = []

const buildNotice = (key: string, name: string): Notification => {
  return {
    key,
    name,
    challenge: name,
    flag: utils.ctfFlag(name),
    hidden: false,
    isRestore: false
  }
}

const connectClient = async () => {
  const solved: Array<{ key?: string, flag?: string }> = []
  const socket = ioClient(`http://127.0.0.1:${serverPort}`, {
    reconnectionDelay: 0,
    forceNew: true,
    transports: ['websocket']
  })
  openSockets.push(socket)
  socket.on('challenge solved', (data: { key?: string, flag?: string }) => {
    solved.push(data)
  })
  await new Promise<void>((resolve, reject) => {
    socket.on('connect', () => { resolve() })
    socket.on('connect_error', (error) => { reject(error) })
  })
  return { socket, solved }
}

const waitForKeys = async (solved: Array<{ key?: string }>, keys: string[]) => {
  const deadline = Date.now() + 2000
  while (Date.now() < deadline) {
    if (keys.every((key) => solved.some((entry) => entry.key === key))) {
      return
    }
    await new Promise((resolve) => { setTimeout(resolve, 10) })
  }
  const present = solved.map((entry) => entry.key).join(',')
  assert.fail(`timed out waiting for ${keys.join(',')} ; saw ${present}`)
}

const serverSocketFor = (socket: Socket) => {
  const serverSocket = globalWithSocketIO.io.sockets.sockets.get(socket.id)
  assert.ok(serverSocket)
  return serverSocket
}

const assertAnonymous = (socket: Socket) => {
  const handshake = serverSocketFor(socket).handshake
  assert.equal(handshake.headers.authorization, undefined)
  assert.deepEqual(handshake.auth, {})
  assert.equal(handshake.query.token, undefined)
  assert.equal(handshake.query.authorization, undefined)
}

const emitNotificationReceived = async (socket: Socket, flag: string) => {
  const serverSocket = serverSocketFor(socket)
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('server did not observe notification received'))
    }, 2000)
    serverSocket.on('notification received', () => {
      clearTimeout(timer)
      setTimeout(resolve, 0)
    })
    socket.emit('notification received', flag)
  })
}

const assertNoticesRemain = (keys: string[]) => {
  for (const key of keys) {
    assert.ok(notifications.some((notice) => notice.key === key), `shared notice list lost ${key}`)
  }
}

const seedNotices = () => {
  const scoreBoard = buildNotice(SCORE_BOARD_KEY, SCORE_BOARD_NAME)
  const adminSection = buildNotice(ADMIN_SECTION_KEY, ADMIN_SECTION_NAME)
  notifications.push(scoreBoard, adminSection)
  return { scoreBoard, adminSection }
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
  baseline = notifications.slice()
}, { timeout: 60000 })

after(() => {
  if (server) {
    server.close()
  }
})

void describe('shared solved-challenge notices', () => {
  beforeEach(() => {
    notifications.splice(0, notifications.length, ...baseline)
  })

  afterEach(() => {
    for (const socket of openSockets) {
      if (socket.connected) {
        socket.disconnect()
      }
    }
    openSockets.length = 0
    notifications.splice(0, notifications.length, ...baseline)
  })

  void it('keeps a replayed notice after an anonymous client echoes the flag it was sent', async () => {
    const keys = [SCORE_BOARD_KEY, ADMIN_SECTION_KEY]
    seedNotices()
    const attacker = await connectClient()
    assertAnonymous(attacker.socket)
    await waitForKeys(attacker.solved, keys)
    const replayed = attacker.solved.find((entry) => entry.key === SCORE_BOARD_KEY)
    assert.equal(typeof replayed?.flag, 'string')
    assert.ok(replayed?.flag)

    await emitNotificationReceived(attacker.socket, replayed.flag)

    assertNoticesRemain(keys)
    const latecomer = await connectClient()
    assertAnonymous(latecomer.socket)
    await waitForKeys(latecomer.solved, keys)
  })

  void it('keeps a notice after an anonymous client sends a flag computed from the challenge name', async () => {
    const keys = [SCORE_BOARD_KEY, ADMIN_SECTION_KEY]
    seedNotices()
    const attacker = await connectClient()
    assertAnonymous(attacker.socket)

    await emitNotificationReceived(attacker.socket, utils.ctfFlag(ADMIN_SECTION_NAME))

    assertNoticesRemain(keys)
    const latecomer = await connectClient()
    await waitForKeys(latecomer.solved, keys)
  })

  void it('keeps a notice that was broadcast to an anonymous client while it was connected', async () => {
    const keys = [SCORE_BOARD_KEY, ADMIN_SECTION_KEY]
    const attacker = await connectClient()
    assertAnonymous(attacker.socket)
    const { scoreBoard } = seedNotices()
    globalWithSocketIO.io.emit('challenge solved', scoreBoard)
    globalWithSocketIO.io.emit('challenge solved', buildNotice(ADMIN_SECTION_KEY, ADMIN_SECTION_NAME))
    await waitForKeys(attacker.solved, keys)
    const broadcast = attacker.solved.find((entry) => entry.key === SCORE_BOARD_KEY)
    assert.equal(typeof broadcast?.flag, 'string')
    assert.ok(broadcast?.flag)

    await emitNotificationReceived(attacker.socket, broadcast.flag)

    assertNoticesRemain(keys)
    const latecomer = await connectClient()
    await waitForKeys(latecomer.solved, keys)
  })
})
