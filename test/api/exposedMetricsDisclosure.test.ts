/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import fs from 'node:fs'
import path from 'node:path'
import type { Express } from 'express'
import type { AddressInfo } from 'node:net'

// Load the server with a non-test NODE_ENV so configureApp registers the
// second /metrics route on the listening app, the same way production does.
process.env.NODE_ENV = 'development'

const SHOP_GAUGE_SUFFIXES = [
  'users_registered_total',
  'users_registered',
  'orders_placed_total',
  'wallet_balance_total',
  'challenges_solved',
  'challenges_total',
  'coding_challenges_progress'
]

interface HttpResult {
  status: number
  body: string
}

const FRONTEND_STUBS = [
  'build/server.js',
  'frontend/dist/frontend/index.html',
  'frontend/dist/frontend/styles.css',
  'frontend/dist/frontend/main.js',
  'frontend/dist/frontend/polyfills.js',
  'frontend/dist/frontend/hacking-instructor-stub.js',
  'frontend/dist/frontend/assets/private/threejs-demo.html'
]

const FRONTEND_COPIES: Array<[string, string]> = [
  ['frontend/src/assets/public/images/JuicyChatBot.png', 'frontend/dist/frontend/assets/public/images/JuicyChatBot.png'],
  ['frontend/src/assets/public/images/JuicyBot.png', 'frontend/dist/frontend/assets/public/images/JuicyBot.png']
]

function ensureFrontendStubs (): string[] {
  const created: string[] = []
  for (const relativePath of FRONTEND_STUBS) {
    if (fs.existsSync(relativePath)) continue
    fs.mkdirSync(path.dirname(relativePath), { recursive: true })
    const contents = relativePath.endsWith('.html')
      ? '<html><head><title>stub</title></head><body class="bluegrey-lightgreen-theme"></body></html>'
      : ''
    fs.writeFileSync(relativePath, contents)
    created.push(relativePath)
  }
  for (const [from, to] of FRONTEND_COPIES) {
    if (fs.existsSync(to) || !fs.existsSync(from)) continue
    fs.mkdirSync(path.dirname(to), { recursive: true })
    fs.copyFileSync(from, to)
    created.push(to)
  }
  return created
}

function removeCreated (created: string[]) {
  for (const relativePath of created) {
    fs.rmSync(relativePath, { force: true })
  }
}

function freePort (): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer()
    probe.once('error', reject)
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address()
      if (address == null || typeof address === 'string') {
        probe.close()
        reject(new Error('Could not reserve a local port'))
        return
      }
      const chosen = address.port
      probe.close(() => resolve(chosen))
    })
  })
}

function rawRequest (port: number, method: string, requestPath: string, headers: Record<string, string> = {}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path: requestPath,
      headers
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      res.on('end', () => {
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8')
        })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

function rawGet (port: number, requestPath: string, headers: Record<string, string> = {}): Promise<HttpResult> {
  return rawRequest(port, 'GET', requestPath, headers)
}

function leakedGauges (body: string, prefix: string): string[] {
  const hits: string[] = []
  for (const suffix of SHOP_GAUGE_SUFFIXES) {
    const name = `${prefix}_${suffix}`
    const valueLine = new RegExp(`^${name}(?:\\{[^\\n]*\\})? [0-9]`, 'm')
    if (valueLine.test(body)) hits.push(name)
  }
  if (/^process_resident_memory_bytes(?:\{[^\n]*\})? [0-9]/m.test(body)) {
    hits.push('process_resident_memory_bytes')
  }
  return hits
}

function assertPublicResponseHidesMetrics (result: HttpResult, prefix: string, what: string) {
  const hits = leakedGauges(result.body, prefix)
  assert.deepEqual(hits, [], `${what} disclosed ${hits.join(', ')} (status ${result.status})`)
}

async function listen (app: Express): Promise<{ port: number, close: () => Promise<void> }> {
  const server = http.createServer(app)
  await new Promise<void>((resolve) => { server.listen(0, '127.0.0.1', () => resolve()) })
  const address = server.address() as AddressInfo
  return {
    port: address.port,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => err ? reject(err) : resolve())
      })
    }
  }
}

void describe('Prometheus metrics disclosure', { concurrency: 1 }, () => {
  void describe('listening server', () => {
    let port = 0
    let prefix = ''
    let closeServer: (exitCode?: number) => void = () => {}
    let customerAuthorization = ''
    let customerCookie = ''
    let createdStubs: string[] = []
    const originalExit = process.exit

    before(async () => {
      createdStubs = ensureFrontendStubs()
      port = await freePort()
      process.env.PORT = String(port)
      process.exit = ((code?: number) => {
      // Preconditions call process.exit when the frontend bundle is absent.
      // The metrics listener does not need that bundle; keep going.
        console.error(`ignored process.exit(${code ?? 0}) during metrics disclosure setup`)
        return undefined as never
      }) as typeof process.exit

      try {
        const serverMod = await import('../../server')
        const config = (await import('config')).default
        const { UserModel } = await import('../../models/user')
        const security = await import('../../lib/insecurity')
        prefix = config.get<string>('application.customMetricsPrefix')
        closeServer = serverMod.close

        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('server start timed out')), 90000)
          void serverMod.start(() => {
            clearTimeout(timer)
            resolve()
          })
        })

        const configured = Date.now() + 20000
        while (Date.now() < configured) {
          const probe = await rawGet(port, '/security.txt')
          if (probe.status !== 404) break
          await new Promise<void>((resolve) => setTimeout(resolve, 50))
        }

        const customer = await UserModel.findOne({ where: { role: security.roles.customer } })
        assert.ok(customer, 'expected a customer row from the data creator')
        const token = security.authorize({
          data: {
            id: customer.id,
            email: customer.email,
            role: customer.role
          }
        })
        security.authenticatedUsers.put(token, { status: 'success', data: customer })
        customerAuthorization = `Bearer ${token}`
        customerCookie = `token=${token}`

        const { ordersCollection } = await import('../../data/mongodb')
        const { WalletModel } = await import('../../models/wallet')
        const userCount = await UserModel.count()
        const orderCount = await ordersCollection.count({})
        const walletSum = Number(await WalletModel.sum('balance'))
        assert.ok(userCount > 0)
        assert.ok(orderCount > 0)
        assert.ok(walletSum > 0)

        const Prometheus = await import('prom-client')
        const deadline = Date.now() + 12000
        const userLine = new RegExp(`^${prefix}_users_registered_total\\{[^\\n]*\\} ${userCount}$`, 'm')
        const orderLine = new RegExp(`^${prefix}_orders_placed_total\\{[^\\n]*\\} ${orderCount}$`, 'm')
        while (Date.now() < deadline) {
          const text = await Prometheus.register.metrics()
          if (userLine.test(text) && orderLine.test(text)) break
          await new Promise<void>((resolve) => setTimeout(resolve, 100))
        }
        const populated = await Prometheus.register.metrics()
        assert.match(populated, userLine, 'user gauge was not filled from the database')
        assert.match(populated, orderLine, 'order gauge was not filled from the database')
        assert.match(populated, new RegExp(`^${prefix}_wallet_balance_total\\{[^\\n]*\\} ${walletSum}$`, 'm'), 'wallet gauge was not filled from the database')
      } finally {
        process.exit = originalExit
      }
    }, { timeout: 180000 })

    after(() => {
      process.exit = originalExit
      closeServer()
      removeCreated(createdStubs)
    })

    void it('anonymous GET /metrics does not return shop or process gauges', async () => {
      const result = await rawGet(port, '/metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })
      assertPublicResponseHidesMetrics(result, prefix, 'anonymous GET /metrics')
    })

    void it('anonymous HEAD /metrics does not return shop gauges or solve exposedMetricsChallenge', async () => {
      const { challenges } = await import('../../data/datacache')
      assert.ok(challenges.exposedMetricsChallenge)
      challenges.exposedMetricsChallenge.solved = false

      const result = await rawRequest(port, 'HEAD', '/metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })
      assertPublicResponseHidesMetrics(result, prefix, 'anonymous HEAD /metrics')
      assert.equal(challenges.exposedMetricsChallenge.solved, false)
    })

    void it('anonymous GET /metrics does not solve exposedMetricsChallenge', async () => {
      const { challenges } = await import('../../data/datacache')
      assert.ok(challenges.exposedMetricsChallenge)
      challenges.exposedMetricsChallenge.solved = false

      await rawGet(port, '/metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })

      assert.equal(challenges.exposedMetricsChallenge.solved, false)
    })

    void it('customer bearer token does not authorize aggregate shop gauges on GET /metrics', async () => {
      const result = await rawGet(port, '/metrics', {
        Authorization: customerAuthorization,
        'User-Agent': 'JuiceShopMetricsDisclosureTest'
      })
      assertPublicResponseHidesMetrics(result, prefix, 'customer bearer GET /metrics')
    })

    void it('customer cookie does not authorize aggregate shop gauges on GET /metrics', async () => {
      const result = await rawGet(port, '/metrics', {
        Cookie: customerCookie,
        'User-Agent': 'JuiceShopMetricsDisclosureTest'
      })
      assertPublicResponseHidesMetrics(result, prefix, 'customer cookie GET /metrics')
    })

    void it('anonymous GET //metrics does not return shop or process gauges', async () => {
      const result = await rawGet(port, '//metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })
      assertPublicResponseHidesMetrics(result, prefix, 'anonymous GET //metrics')
    })

    void it('anonymous GET //metrics does not solve exposedMetricsChallenge', async () => {
      const { challenges } = await import('../../data/datacache')
      assert.ok(challenges.exposedMetricsChallenge)
      challenges.exposedMetricsChallenge.solved = false

      await rawGet(port, '//metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })

      assert.equal(challenges.exposedMetricsChallenge.solved, false)
    })

    void it('customer bearer token does not authorize aggregate shop gauges on GET //metrics', async () => {
      const result = await rawGet(port, '//metrics', {
        Authorization: customerAuthorization,
        'User-Agent': 'JuiceShopMetricsDisclosureTest'
      })
      assertPublicResponseHidesMetrics(result, prefix, 'customer bearer GET //metrics')
    })

    void it('ignored scraper user agent still must not receive shop gauges', async () => {
      const config = (await import('config')).default
      const ignored = config.get<string[]>('challenges.metricsIgnoredUserAgents')
      const result = await rawGet(port, '/metrics', { 'User-Agent': `${ignored[0]}/2.45.0` })
      assertPublicResponseHidesMetrics(result, prefix, 'scraper GET /metrics')
      const second = await rawGet(port, '//metrics', { 'User-Agent': `${ignored[0]}/2.45.0` })
      assertPublicResponseHidesMetrics(second, prefix, 'scraper GET //metrics')
    })
  })

  void describe('configureApp /metrics route', () => {
    let app: Express
    let prefix = ''
    let customerAuthorization = ''
    let closeApp: () => Promise<void> = async () => {}
    let appPort = 0

    before(async () => {
      const { createTestApp } = await import('./helpers/setup')
      const metricsRoute = await import('../../routes/metrics')
      const config = (await import('config')).default
      const { UserModel } = await import('../../models/user')
      const { WalletModel } = await import('../../models/wallet')
      const { ordersCollection } = await import('../../data/mongodb')
      const security = await import('../../lib/insecurity')
      const Prometheus = await import('prom-client')
      const { mock } = await import('node:test')

      const created = await createTestApp()
      app = created.app
      prefix = config.get<string>('application.customMetricsPrefix')

      const Metrics = metricsRoute.observeMetrics()
      metricsRoute.reRegisterMetrics()
      mock.timers.enable({ apis: ['setInterval'] })
      const loop = Metrics.updateLoop()
      mock.timers.tick(5000)
      clearInterval(loop)
      mock.timers.reset()

      const userCount = await UserModel.count()
      const orderCount = await ordersCollection.count({})
      const walletSum = Number(await WalletModel.sum('balance'))
      assert.ok(userCount > 0)
      assert.ok(orderCount > 0)
      assert.ok(walletSum > 0)

      const userLine = new RegExp(`^${prefix}_users_registered_total\\{[^\\n]*\\} ${userCount}$`, 'm')
      const orderLine = new RegExp(`^${prefix}_orders_placed_total\\{[^\\n]*\\} ${orderCount}$`, 'm')
      const walletLine = new RegExp(`^${prefix}_wallet_balance_total\\{[^\\n]*\\} ${walletSum}$`, 'm')
      const deadline = Date.now() + 12000
      while (Date.now() < deadline) {
        const text = await Prometheus.register.metrics()
        if (userLine.test(text) && orderLine.test(text) && walletLine.test(text)) break
        await new Promise<void>((resolve) => setTimeout(resolve, 50))
      }
      const populated = await Prometheus.register.metrics()
      assert.match(populated, userLine)
      assert.match(populated, orderLine)
      assert.match(populated, walletLine)

      const customer = await UserModel.findOne({ where: { role: security.roles.customer } })
      assert.ok(customer)
      const token = security.authorize({
        data: {
          id: customer.id,
          email: customer.email,
          role: customer.role
        }
      })
      security.authenticatedUsers.put(token, { status: 'success', data: customer })
      customerAuthorization = `Bearer ${token}`

      const listener = await listen(app)
      appPort = listener.port
      closeApp = listener.close
    }, { timeout: 180000 })

    after(async () => {
      await closeApp()
    })

    void it('anonymous GET /metrics on the configureApp router does not return shop or process gauges', async () => {
      const result = await rawGet(appPort, '/metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })
      assertPublicResponseHidesMetrics(result, prefix, 'configureApp anonymous GET /metrics')
    })

    void it('anonymous HEAD /metrics on the configureApp router does not return shop gauges or solve exposedMetricsChallenge', async () => {
      const { challenges } = await import('../../data/datacache')
      assert.ok(challenges.exposedMetricsChallenge)
      challenges.exposedMetricsChallenge.solved = false

      const result = await rawRequest(appPort, 'HEAD', '/metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })
      assertPublicResponseHidesMetrics(result, prefix, 'configureApp anonymous HEAD /metrics')
      assert.equal(challenges.exposedMetricsChallenge.solved, false)
    })

    void it('anonymous GET /metrics on the configureApp router does not solve exposedMetricsChallenge', async () => {
      const { challenges } = await import('../../data/datacache')
      assert.ok(challenges.exposedMetricsChallenge)
      challenges.exposedMetricsChallenge.solved = false

      await rawGet(appPort, '/metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })

      assert.equal(challenges.exposedMetricsChallenge.solved, false)
    })

    void it('customer bearer token does not authorize aggregate shop gauges on the configureApp router', async () => {
      const result = await rawGet(appPort, '/metrics', {
        Authorization: customerAuthorization,
        'User-Agent': 'JuiceShopMetricsDisclosureTest'
      })
      assertPublicResponseHidesMetrics(result, prefix, 'configureApp customer GET /metrics')
    })

    void it('slash-collapsed GET //metrics on the configureApp router does not return shop gauges', async () => {
      const result = await rawGet(appPort, '//metrics', { 'User-Agent': 'JuiceShopMetricsDisclosureTest' })
      assertPublicResponseHidesMetrics(result, prefix, 'configureApp anonymous GET //metrics')
    })
  })
})
