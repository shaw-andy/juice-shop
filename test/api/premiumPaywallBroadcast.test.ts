/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import * as http from 'http'
import request from 'supertest'
import type { Express } from 'express'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import { notifications } from '../../data/datacache'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'

const PAYWALL_PATH = '/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us'
const PLACEHOLDER_PASSWORD = 'placeholder-password'
const WALLPAPER = path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg')
const WALLPAPER_SOURCE = path.resolve('frontend/src/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg')

let app: Express
let server: http.Server
let serverPort: number
let wallpaperCreated = false

before(async () => {
  if (!fs.existsSync(WALLPAPER) && fs.existsSync(WALLPAPER_SOURCE)) {
    fs.mkdirSync(path.dirname(WALLPAPER), { recursive: true })
    fs.copyFileSync(WALLPAPER_SOURCE, WALLPAPER)
    wallpaperCreated = true
  }
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
  if (wallpaperCreated) {
    fs.rmSync(WALLPAPER, { force: true })
  }
})

function connectBystander (): Promise<{ socket: Socket, sawPremiumFlag: () => boolean }> {
  const socket = ioClient(`http://127.0.0.1:${serverPort}`, {
    reconnection: false,
    forceNew: true
  })
  let sawPremiumFlag = false
  socket.on('challenge solved', (data: { key?: string, flag?: unknown }) => {
    if (data?.key === 'premiumPaywallChallenge' && typeof data.flag === 'string' && data.flag.length > 0) {
      sawPremiumFlag = true
    }
  })
  return new Promise((resolve, reject) => {
    socket.once('connect', () => {
      resolve({ socket, sawPremiumFlag: () => sawPremiumFlag })
    })
    socket.once('connect_error', reject)
  })
}

async function premiumSolved (): Promise<boolean> {
  const res = await request(server).get('/api/Challenges')
  assert.equal(res.status, 200)
  const row = res.body.data.find((challenge: { key: string }) => challenge.key === 'premiumPaywallChallenge')
  assert.ok(row)
  return row.solved === true
}

async function waitForPremiumLeak (readers: Array<() => boolean>): Promise<boolean> {
  const deadline = Date.now() + 2000
  while (Date.now() < deadline) {
    if (readers.some((read) => read())) return true
    if (await premiumSolved()) return true
    if (notifications.some((notice) => notice.key === 'premiumPaywallChallenge' && typeof notice.flag === 'string' && notice.flag.length > 0)) {
      return true
    }
    await new Promise((resolve) => { setTimeout(resolve, 50) })
  }
  return readers.some((read) => read()) ||
    await premiumSolved() ||
    notifications.some((notice) => notice.key === 'premiumPaywallChallenge' && typeof notice.flag === 'string' && notice.flag.length > 0)
}

void describe('premium paywall', () => {
  void it('does not solve the shared challenge or broadcast its flag when no payment was collected', async () => {
    assert.equal(await premiumSolved(), false)

    const bystander = await connectBystander()
    const lateJoined = { current: null as null | { socket: Socket, sawPremiumFlag: () => boolean } }

    const anonymous = await request(server).get(PAYWALL_PATH)
    const forgedQuery = await request(server).get(PAYWALL_PATH + '?paid=1&amount=1btc&tx=placeholder')
    const forgedHeader = await request(server)
      .get(PAYWALL_PATH)
      .set('X-Payment', '1btc')
      .set('Cookie', 'token=placeholder')

    const email = 'paywall-unpaid@juice-sh.op'
    const registered = await request(server)
      .post('/api/Users')
      .set('content-type', 'application/json')
      .send({
        email,
        password: PLACEHOLDER_PASSWORD,
        passwordRepeat: PLACEHOLDER_PASSWORD,
        securityQuestion: { id: 1 },
        securityAnswer: 'placeholder-answer'
      })
    assert.equal(registered.status, 201)
    const loggedIn = await request(server)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email, password: PLACEHOLDER_PASSWORD })
    assert.equal(loggedIn.status, 200)
    const authenticated = await request(server)
      .get(PAYWALL_PATH)
      .set('Authorization', 'Bearer ' + loggedIn.body.authentication.token)

    for (const res of [anonymous, forgedQuery, forgedHeader, authenticated]) {
      const type = String(res.headers['content-type'] ?? '')
      const servedWallpaper = res.status === 200 && type.includes('image/jpeg')
      const refused = res.status >= 400 && res.status < 500
      assert.ok(servedWallpaper || refused)
    }

    const leaked = await waitForPremiumLeak([bystander.sawPremiumFlag])
    lateJoined.current = await connectBystander()
    await new Promise((resolve) => { setTimeout(resolve, 300) })

    assert.equal(leaked, false)
    assert.equal(await premiumSolved(), false)
    assert.equal(bystander.sawPremiumFlag(), false)
    assert.equal(lateJoined.current.sawPremiumFlag(), false)
    assert.equal(notifications.some((notice) => notice.key === 'premiumPaywallChallenge'), false)

    bystander.socket.disconnect()
    lateJoined.current.socket.disconnect()
  })
})
