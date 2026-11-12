/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import * as http from 'node:http'
import './helpers/placeholder-ctf-key'
import request from 'supertest'
import { io as ioClient, type Socket } from 'socket.io-client'
import config from 'config'
import type { Express } from 'express'
import type { Server as IoServer } from 'socket.io'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import * as challengeUtils from '../../lib/challengeUtils'
import * as utils from '../../lib/utils'

const PLACEHOLDER_CTF_KEY = 'placeholder-ctf-key'
const UNTRUSTED_ORIGIN = 'http://untrusted.example'

let app: Express
let server: http.Server
let serverPort: number
const clients: Socket[] = []

const globalWithSocketIO = global as typeof globalThis & { io?: IoServer }

function scoringFlag (challengeName: string): string {
  return crypto.createHmac('sha1', PLACEHOLDER_CTF_KEY).update(challengeName).digest('hex')
}

function leakedChallengeNames (payloads: unknown[], names: string[]): string[] {
  const leaked = new Set<string>()
  for (const payload of payloads) {
    const serialized = JSON.stringify(payload)
    if (serialized == null) {
      continue
    }
    for (const name of names) {
      if (serialized.includes(scoringFlag(name))) {
        leaked.add(name)
      }
    }
  }
  return [...leaked]
}

async function waitUntilQuiet (events: unknown[], quietMs = 400, maxMs = 2000): Promise<void> {
  const start = Date.now()
  let lastCount = events.length
  let lastChange = Date.now()
  while (Date.now() - start < maxMs) {
    await new Promise(resolve => { setTimeout(resolve, 25) })
    if (events.length !== lastCount) {
      lastCount = events.length
      lastChange = Date.now()
    } else if (Date.now() - lastChange >= quietMs) {
      return
    }
  }
}

interface AnonymousClient {
  socket: Socket
  events: unknown[]
}

function connectAnonymous (options: { transports?: string[], origin?: string, cookie?: string } = {}): Promise<AnonymousClient> {
  const events: unknown[] = []
  const extraHeaders: Record<string, string> = {}
  if (options.cookie !== undefined) {
    extraHeaders.Cookie = options.cookie
  }
  const socket = ioClient(`http://127.0.0.1:${serverPort}`, {
    reconnection: false,
    forceNew: true,
    timeout: 5000,
    transports: options.transports,
    extraHeaders,
    origin: options.origin
  })
  clients.push(socket)
  socket.onAny((...args: unknown[]) => {
    events.push(args)
  })
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('anonymous socket connection timed out'))
    }, 5000)
    socket.on('connect', () => {
      clearTimeout(timer)
      resolve({ socket, events })
    })
    socket.on('connect_error', (err: Error) => {
      clearTimeout(timer)
      reject(err)
    })
  })
}

interface ChallengeRow {
  name: string
  solved: boolean
}

async function listChallenges (): Promise<ChallengeRow[]> {
  const res = await request(app).get('/api/Challenges')
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

async function solveFromPublicList (): Promise<string> {
  const rows = await listChallenges()
  const row = rows.find(candidate => candidate.solved === false)
  assert.ok(row, 'expected an unsolved challenge on the public list')
  const challenge = challengeUtils.findChallengeByName(row.name)
  assert.ok(challenge, 'public challenge name was not found on the server')
  await challengeUtils.solve(challenge)
  return row.name
}

before(async () => {
  assert.ok(
    utils.ctfFlag('Score Board') === scoringFlag('Score Board'),
    'CTF_KEY was not used to compute scoring flags'
  )
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
  for (const client of clients) {
    if (client.connected) {
      client.disconnect()
    }
  }
  globalWithSocketIO.io?.close()
  if (server) {
    server.close()
  }
})

void describe('solved challenge scoring flags on sockets', () => {
  void it('does not give an anonymous client the flag when someone else solves a challenge', async () => {
    const websocket = await connectAnonymous({ transports: ['websocket'], origin: UNTRUSTED_ORIGIN })
    const polling = await connectAnonymous({ transports: ['polling'] })
    const withCookie = await connectAnonymous({
      transports: ['websocket'],
      origin: UNTRUSTED_ORIGIN,
      cookie: 'token=placeholder-session'
    })
    assert.equal(websocket.socket.connected, true)
    assert.equal(polling.socket.connected, true)
    assert.equal(withCookie.socket.connected, true)
    await waitUntilQuiet(websocket.events)
    await waitUntilQuiet(polling.events)
    await waitUntilQuiet(withCookie.events)
    const markers = {
      websocket: websocket.events.length,
      polling: polling.events.length,
      withCookie: withCookie.events.length
    }

    const name = await solveFromPublicList()
    const listed = (await listChallenges()).find(row => row.name === name)
    assert.equal(listed?.solved, true)
    await waitUntilQuiet(websocket.events)
    await waitUntilQuiet(polling.events)
    await waitUntilQuiet(withCookie.events)

    const names = (await listChallenges()).map(row => row.name)
    assert.deepEqual({
      websocket: leakedChallengeNames(websocket.events.slice(markers.websocket), names),
      polling: leakedChallengeNames(polling.events.slice(markers.polling), names),
      withCookie: leakedChallengeNames(withCookie.events.slice(markers.withCookie), names)
    }, {
      websocket: [],
      polling: [],
      withCookie: []
    })
  })

  void it('does not replay stored scoring flags to a socket that connects later', async () => {
    const name = await solveFromPublicList()
    const late = await connectAnonymous({ transports: ['websocket'], origin: UNTRUSTED_ORIGIN })
    assert.equal(late.socket.connected, true)
    await waitUntilQuiet(late.events)
    const names = (await listChallenges()).map(row => row.name)
    assert.ok(names.includes(name))
    assert.deepEqual(leakedChallengeNames(late.events, names), [])
  })

  void it('does not emit a scoring flag when an anonymous client repeats a solved challenge notice', async () => {
    const name = await solveFromPublicList()
    const solvedName = (await listChallenges()).find(row => row.name === name && row.solved)
    assert.ok(solvedName)

    const client = await connectAnonymous({ transports: ['websocket'], origin: UNTRUSTED_ORIGIN })
    assert.equal(client.socket.connected, true)
    await waitUntilQuiet(client.events)
    const marker = client.events.length

    await request(app)
      .get('/rest/repeat-notification')
      .query({ challenge: solvedName.name })
    await waitUntilQuiet(client.events)

    const names = (await listChallenges()).map(row => row.name)
    assert.deepEqual(leakedChallengeNames(client.events.slice(marker), names), [])
  })

  void it('does not emit a scoring flag when an anonymous client restores solved challenges', async () => {
    const name = await solveFromPublicList()
    const codeRes = await request(app).get('/rest/continue-code')
    assert.equal(codeRes.status, 200)
    assert.equal(typeof codeRes.body.continueCode, 'string')

    const client = await connectAnonymous({ transports: ['polling'] })
    assert.equal(client.socket.connected, true)
    await waitUntilQuiet(client.events)
    const marker = client.events.length

    await request(app).put('/rest/continue-code/apply/' + codeRes.body.continueCode)
    await waitUntilQuiet(client.events)

    const names = (await listChallenges()).map(row => row.name)
    assert.ok(names.includes(name))
    assert.deepEqual(leakedChallengeNames(client.events.slice(marker), names), [])
  })

  void it('does not emit a scoring flag when solved notices are configured to show flags', async () => {
    const ctf = config.get('ctf') as { showFlagsInNotifications: boolean }
    const previous = ctf.showFlagsInNotifications
    ctf.showFlagsInNotifications = true
    try {
      assert.equal(config.get('ctf.showFlagsInNotifications'), true)
      const client = await connectAnonymous({ transports: ['websocket'], origin: UNTRUSTED_ORIGIN })
      assert.equal(client.socket.connected, true)
      await waitUntilQuiet(client.events)
      const marker = client.events.length
      await solveFromPublicList()
      await waitUntilQuiet(client.events)
      const names = (await listChallenges()).map(row => row.name)
      assert.deepEqual(leakedChallengeNames(client.events.slice(marker), names), [])
    } finally {
      ctf.showFlagsInNotifications = previous
    }
  })

  void it('does not emit a scoring flag when repeat-notification is asked for an unsolved challenge', async () => {
    const unsolved = (await listChallenges()).find(row => row.solved === false)
    assert.ok(unsolved)
    const client = await connectAnonymous({ transports: ['websocket'], origin: UNTRUSTED_ORIGIN })
    assert.equal(client.socket.connected, true)
    await waitUntilQuiet(client.events)
    const marker = client.events.length

    await request(app)
      .get('/rest/repeat-notification')
      .query({ challenge: unsolved.name })
    await waitUntilQuiet(client.events)

    assert.deepEqual(leakedChallengeNames(client.events.slice(marker), [unsolved.name]), [])
  })
})
