/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { Express } from 'express'
import * as http from 'http'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import * as antiCheat from '../../lib/antiCheat'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges } from '../../data/datacache'
import logger from '../../lib/logger'
import { ctfFlag } from '../../lib/utils'

const TEN_YEARS_MS = 10 * 365 * 24 * 60 * 60 * 1000
const VICTIM_ID = 'victim-1'

let app: Express
let server: http.Server
let serverPort: number

function installClock () {
  const RealDate = Date
  let current = RealDate.now()
  function FakeDate (this: unknown, ...args: unknown[]) {
    if (!new.target) {
      return RealDate()
    }
    if (args.length === 0) {
      return new RealDate(current)
    }
    return new RealDate(...args as [string])
  }
  FakeDate.now = () => current
  FakeDate.parse = RealDate.parse
  FakeDate.UTC = RealDate.UTC
  FakeDate.prototype = RealDate.prototype
  Object.setPrototypeOf(FakeDate, RealDate)
  global.Date = FakeDate as DateConstructor
  return {
    advance (ms: number) {
      current += ms
    },
    restore () {
      global.Date = RealDate
    }
  }
}

function waitForCheatScoreLog (key: string) {
  return new Promise<void>((resolve, reject) => {
    const original = logger.info.bind(logger)
    const timer = setTimeout(() => {
      logger.info = original
      reject(new Error(`timed out waiting for cheat score log of ${key}`))
    }, 3000)
    logger.info = ((...args: unknown[]) => {
      const line = args.map(String).join(' ')
      const result = original(...args)
      if (line.includes('Cheat score') && line.includes(key)) {
        clearTimeout(timer)
        logger.info = original
        resolve()
      }
      return result
    }) as typeof logger.info
  })
}

async function connectWithoutSession () {
  const socket = ioClient(`http://127.0.0.1:${serverPort}`, {
    reconnection: false,
    forceNew: true,
    transports: ['websocket'],
    auth: {}
  })
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => { resolve() })
    socket.once('connect_error', (error: Error) => { reject(error) })
  })
  const namespace = (global as any).io.sockets
  const serverSocket = namespace.sockets.get(socket.id)
  assert.ok(serverSocket, 'server accepted the socket')
  assert.equal(serverSocket.handshake.headers.authorization, undefined)
  assert.equal(serverSocket.handshake.headers.cookie, undefined)
  const auth = serverSocket.handshake.auth
  assert.ok(auth == null || Object.keys(auth).length === 0)
  return socket
}

async function markUnsolved (key: string) {
  const challenge = challenges[key as keyof typeof challenges]
  assert.ok(challenge, `missing challenge ${key}`)
  if (challenge.solved) {
    challenge.solved = false
    await challenge.save()
  }
}

function flagsMatch (actual: string, challengeName: string) {
  assert.equal(actual === ctfFlag(challengeName), true, 'webhook ctfFlag does not match the solved challenge')
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  await new Promise<void>((resolve) => {
    server = http.createServer(app)
    registerWebsocketEvents(server)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') {
        serverPort = addr.port
      }
      resolve()
    })
  })
}, { timeout: 120000 })

after(() => {
  const io = (global as any).io
  if (io) {
    io.close()
  }
  if (server) {
    server.close()
  }
  antiCheat.reset()
})

void describe('unauthenticated solve clock', { concurrency: 1 }, () => {
  void it('does not let an anonymous notification close make the next participant look instant', async () => {
    const clock = installClock()
    const previousWebhook = process.env.SOLUTIONS_WEBHOOK
    const winstonInfo = logger.info
    let webhook: http.Server | undefined
    let socket: Socket | undefined
    const posts: any[] = []
    const lines: string[] = []
    try {
      await markUnsolved('closeNotificationsChallenge')
      await markUnsolved('securityPolicyChallenge')
      socket = await connectWithoutSession()
      antiCheat.reset()
      clock.advance(TEN_YEARS_MS)
      const logged = waitForCheatScoreLog('closeNotificationsChallenge')
      socket.emit('verifyCloseNotificationsChallenge', [{ id: 'one' }, { id: 'two' }])
      await logged
      await new Promise(resolve => setTimeout(resolve, 100))
      assert.equal(challenges.closeNotificationsChallenge.solved, true)

      webhook = http.createServer((req, res) => {
        const chunks: Buffer[] = []
        req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
        req.on('end', () => {
          posts.push(JSON.parse(Buffer.concat(chunks).toString('utf8')))
          res.writeHead(204)
          res.end()
        })
      })
      const webhookPort = await new Promise<number>((resolve) => {
        webhook!.listen(0, '127.0.0.1', () => {
          const addr = webhook!.address()
          resolve(typeof addr === 'object' && addr ? addr.port : 0)
        })
      })
      process.env.SOLUTIONS_WEBHOOK = `http://127.0.0.1:${webhookPort}/solutions`
      const originalInfo = logger.info.bind(logger)
      logger.info = ((...args: unknown[]) => {
        lines.push(args.map(String).join(' '))
        return originalInfo(...args)
      }) as typeof logger.info

      await challengeUtils.solve(challenges.securityPolicyChallenge, false, false, VICTIM_ID)
      for (let i = 0; i < 150 && posts.length === 0; i++) {
        await new Promise(resolve => setTimeout(resolve, 20))
      }
      const body = posts.find(post => post?.solution?.challenge === 'securityPolicyChallenge')
      assert.ok(body, 'solutions webhook received the victim solve')
      flagsMatch(body.ctfFlag, challenges.securityPolicyChallenge.name)
      const line = lines.find(entry => entry.includes('Cheat score') && entry.includes('securityPolicyChallenge'))
      assert.ok(line, 'server log records the victim cheat score')
      assert.ok(line.includes(String(body.solution.cheatScore)))
      assert.ok(body.solution.cheatScore < 0.33, `victim cheat score was ${body.solution.cheatScore}`)
      assert.equal(body.solution.participantId, VICTIM_ID)
    } finally {
      logger.info = winstonInfo
      if (previousWebhook === undefined) {
        delete process.env.SOLUTIONS_WEBHOOK
      } else {
        process.env.SOLUTIONS_WEBHOOK = previousWebhook
      }
      socket?.disconnect()
      if (webhook) {
        await new Promise<void>((resolve) => { webhook!.close(() => { resolve() }) })
      }
      clock.restore()
      antiCheat.reset()
    }
  })

  void it('does not let an anonymous local XSS verification move another participant\'s clock', async () => {
    const clock = installClock()
    let socket: Socket | undefined
    try {
      await markUnsolved('localXssChallenge')
      socket = await connectWithoutSession()
      antiCheat.reset()
      clock.advance(TEN_YEARS_MS)
      const logged = waitForCheatScoreLog('localXssChallenge')
      socket.emit('verifyLocalXssChallenge', '<iframe src="javascript:alert(`xss`)">')
      await logged
      assert.equal(challenges.localXssChallenge.solved, true)
      const score = antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2, tutorialOrder: null } as any, false, VICTIM_ID)
      assert.ok(score < 0.33, `victim score was ${score}`)
    } finally {
      socket?.disconnect()
      clock.restore()
      antiCheat.reset()
    }
  })

  void it('does not let an anonymous SVG verification move another participant\'s clock', async () => {
    const clock = installClock()
    let socket: Socket | undefined
    try {
      await markUnsolved('svgInjectionChallenge')
      socket = await connectWithoutSession()
      antiCheat.reset()
      clock.advance(TEN_YEARS_MS)
      const logged = waitForCheatScoreLog('svgInjectionChallenge')
      socket.emit('verifySvgInjectionChallenge', '../../../redirect?to=https://cataas.com/cat?next=https://github.com/juice-shop/juice-shop')
      await logged
      assert.equal(challenges.svgInjectionChallenge.solved, true)
      const score = antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2, tutorialOrder: null } as any, false, VICTIM_ID)
      assert.ok(score < 0.33, `victim score was ${score}`)
    } finally {
      socket?.disconnect()
      clock.restore()
      antiCheat.reset()
    }
  })
})
