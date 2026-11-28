/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { type AddressInfo } from 'node:net'
import request from 'supertest'
import type { Express } from 'express'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import { challenges, notifications } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'

const SOLVE_PATH = '/solve/challenges/server-side'
const FORGED_IMAGE_URL = 'http://x/solve/challenges/server-side'
const LOOPBACK_FORWARDED_FOR = '127.0.0.1'
const SESSION_TOKEN = 'placeholder-session'

let app: Express
let server: http.Server
let serverPort: number
let serverHost: string
let webhookServer: http.Server
let webhookChallenges: string[]
let socket: Socket
let socketSolves: string[]
let remoteAddresses: string[]
let previousWebhook: string | undefined

function externalIPv4 (): string {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address
    }
  }
  throw new Error('no non-loopback IPv4 address available for the attacker client')
}

function isLoopbackAddress (address: string): boolean {
  const normalized = address.startsWith('::ffff:') ? address.slice('::ffff:'.length) : address
  return normalized === '::1' || normalized.startsWith('127.')
}

function serverSideVerificationKey (): string {
  const source = fs.readFileSync(path.resolve(__dirname, '../../routes/verify.ts'), 'utf8')
  const match = /req\.query\.key === (['"])(.*?)\1/.exec(source)
  if (match?.[2] == null || match[2].length === 0) return 'placeholder-key'
  return match[2]
}

function delay (ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}

async function resetSsrfState (): Promise<void> {
  app.locals.abused_ssrf_bug = false
  const challenge = challenges.ssrfChallenge
  if (challenge.solved) {
    challenge.solved = false
    await challenge.save()
  }
  for (let i = notifications.length - 1; i >= 0; i--) {
    if (notifications[i].key === 'ssrfChallenge') notifications.splice(i, 1)
  }
  webhookChallenges = []
  socketSolves = []
  remoteAddresses = []
}

async function waitForEffects (): Promise<void> {
  const deadline = Date.now() + 2000
  while (Date.now() < deadline) {
    const flagged = app.locals.abused_ssrf_bug === true
    const solved = challenges.ssrfChallenge.solved === true
    const hooked = webhookChallenges.includes('ssrfChallenge')
    const broadcast = socketSolves.includes('ssrfChallenge')
    if (flagged && solved && hooked && broadcast) return
    if (!flagged && !solved && !hooked && !broadcast) {
      await delay(100)
      if (app.locals.abused_ssrf_bug !== true && challenges.ssrfChallenge.solved !== true && !webhookChallenges.includes('ssrfChallenge') && !socketSolves.includes('ssrfChallenge')) return
    }
    await delay(50)
  }
}

function attacker (method: 'get' | 'post', url: string) {
  return request(server)[method](url).set('X-Forwarded-For', LOOPBACK_FORWARDED_FOR)
}

async function followUpSolve (): Promise<number> {
  const res = await attacker('get', SOLVE_PATH)
    .query({ key: serverSideVerificationKey() })
  await waitForEffects()
  return res.status
}

async function assertNotForged (solveStatus: number): Promise<void> {
  const solvedBeforeReload = challenges.ssrfChallenge.solved === true
  await challenges.ssrfChallenge.reload()
  assert.deepEqual({
    ssrfFlag: app.locals.abused_ssrf_bug === true,
    solvedBeforeReload,
    solvedInDatabase: challenges.ssrfChallenge.solved === true,
    webhookNotified: webhookChallenges.includes('ssrfChallenge'),
    socketBroadcast: socketSolves.includes('ssrfChallenge'),
    attackerWasLoopback: remoteAddresses.length === 0 || remoteAddresses.some((address) => isLoopbackAddress(address))
  }, {
    ssrfFlag: false,
    solvedBeforeReload: false,
    solvedInDatabase: false,
    webhookNotified: false,
    socketBroadcast: false,
    attackerWasLoopback: false
  }, `solve response status was ${solveStatus}`)
}

before(async () => {
  serverHost = externalIPv4()
  const result = await createTestApp()
  app = result.app
  previousWebhook = process.env.SOLUTIONS_WEBHOOK
  webhookChallenges = []
  webhookServer = http.createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { solution?: { challenge?: unknown } }
        if (typeof body.solution?.challenge === 'string') webhookChallenges.push(body.solution.challenge)
      } catch {
        webhookChallenges.push('unparsed')
      }
      res.statusCode = 204
      res.end()
    })
  })
  await new Promise<void>((resolve) => { webhookServer.listen(0, '127.0.0.1', resolve) })
  const webhookPort = (webhookServer.address() as AddressInfo).port
  process.env.SOLUTIONS_WEBHOOK = `http://127.0.0.1:${webhookPort}/hook`

  remoteAddresses = []
  server = http.createServer(app)
  server.on('connection', (socket) => {
    if (socket.remoteAddress != null) remoteAddresses.push(socket.remoteAddress)
  })
  registerWebsocketEvents(server)
  await new Promise<void>((resolve) => {
    server.listen(0, serverHost, () => {
      serverPort = (server.address() as AddressInfo).port
      resolve()
    })
  })

  socketSolves = []
  socket = ioClient(`http://${serverHost}:${serverPort}`, { reconnection: false, forceNew: true })
  socket.on('challenge solved', (notification: { key?: string }) => {
    if (notification?.key === 'ssrfChallenge') socketSolves.push(notification.key)
  })
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => { resolve() })
    socket.once('connect_error', reject)
  })
}, { timeout: 60000 })

after(async () => {
  socket.disconnect()
  if (previousWebhook === undefined) delete process.env.SOLUTIONS_WEBHOOK
  else process.env.SOLUTIONS_WEBHOOK = previousWebhook
  await new Promise<void>((resolve, reject) => { server.close((err) => { err != null ? reject(err) : resolve() }) })
  await new Promise<void>((resolve, reject) => { webhookServer.close((err) => { err != null ? reject(err) : resolve() }) })
})

beforeEach(async () => {
  await resetSsrfState()
})

void describe('SSRF challenge forgery', () => {
  void it('refuses an anonymous urlencoded profile image URL that names the server-side solve path without solving the challenge', async () => {
    assert.equal(challenges.ssrfChallenge.difficulty, 6)
    assert.equal(challenges.ssrfChallenge.disabledEnv, null)
    assert.equal(challenges.ssrfChallenge.solved, false)

    const posted = await attacker('post', '/profile/image/url')
      .type('form')
      .send({ imageUrl: FORGED_IMAGE_URL })

    assert.equal(posted.status, 500)
    assert.match(posted.text, /Blocked illegal activity/)

    const solveStatus = await followUpSolve()
    await assertNotForged(solveStatus)
  })

  void it('refuses an anonymous multipart profile image URL that names the server-side solve path without solving the challenge', async () => {
    const posted = await attacker('post', '/profile/image/url')
      .field('imageUrl', FORGED_IMAGE_URL)

    assert.equal(posted.status, 500)
    assert.match(posted.text, /Blocked illegal activity/)

    const solveStatus = await followUpSolve()
    await assertNotForged(solveStatus)
  })

  void it('does not solve the challenge when a signed-in profile image URL matches the solve path but the shop never requests its own solve route', async () => {
    const fetchedPaths: string[] = []
    const decoy = http.createServer((req, res) => {
      fetchedPaths.push(req.url ?? '')
      res.statusCode = 404
      res.end('missing')
    })
    await new Promise<void>((resolve) => { decoy.listen(0, '127.0.0.1', resolve) })
    const decoyPort = (decoy.address() as AddressInfo).port
    const user = await UserModel.findOne()
    assert.ok(user)
    security.authenticatedUsers.put(SESSION_TOKEN, { data: user })

    try {
      const posted = await attacker('post', '/profile/image/url')
        .set('Cookie', `token=${SESSION_TOKEN}`)
        .type('form')
        .redirects(0)
        .send({ imageUrl: `http://127.0.0.1:${decoyPort}${SOLVE_PATH}` })

      assert.equal(posted.status, 302)
      assert.ok(fetchedPaths.some((fetched) => fetched.includes(SOLVE_PATH)))

      const solveStatus = await followUpSolve()
      await assertNotForged(solveStatus)
    } finally {
      delete security.authenticatedUsers.tokenMap[SESSION_TOKEN]
      delete security.authenticatedUsers.idMap[String(user.id)]
      await new Promise<void>((resolve, reject) => { decoy.close((err) => { err != null ? reject(err) : resolve() }) })
    }
  })
})
