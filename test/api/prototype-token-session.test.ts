/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'

const root = process.cwd()
const nodeRequire = createRequire(path.join(root, 'package.json'))
const tsxLoader = nodeRequire.resolve('tsx')

const inheritedTokens = ['__proto__', 'constructor', 'toString']

interface RunningServer {
  child: ChildProcessWithoutNullStreams
  port: number
  stderr: string
  stdout: string
  exited: { code: number | null, signal: NodeJS.Signals | null } | null
}

interface HttpResult {
  status: number
  body: string
}

function delay (ms: number) {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}

async function startServer (): Promise<RunningServer> {
  const portFile = path.join(os.tmpdir(), `juice-proto-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`)
  const child = spawn(process.execPath, [
    '--import', path.join(root, 'test/api/helpers/test-env.mjs'),
    '--import', tsxLoader,
    path.join(root, 'test/api/helpers/prototype-token-harness.ts'),
    portFile
  ], {
    cwd: root,
    env: { ...process.env, NODE_ENV: 'test' },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const running: RunningServer = { child, port: 0, stderr: '', stdout: '', exited: null }
  child.stderr.setEncoding('utf8')
  child.stdout.setEncoding('utf8')
  child.stderr.on('data', (chunk: string) => { running.stderr += chunk })
  child.stdout.on('data', (chunk: string) => { running.stdout += chunk })
  child.on('exit', (code, signal) => { running.exited = { code, signal } })

  const deadline = Date.now() + 90000
  while (Date.now() < deadline) {
    if (running.exited) {
      throw new Error(`server exited during startup code=${running.exited.code} signal=${running.exited.signal}\n${running.stderr}\n${running.stdout}`)
    }
    if (fs.existsSync(portFile)) {
      const text = fs.readFileSync(portFile, 'utf8').trim()
      if (text) {
        running.port = Number(text)
        fs.rmSync(portFile, { force: true })
        break
      }
    }
    await delay(50)
  }
  if (!running.port) {
    child.kill('SIGKILL')
    throw new Error(`server did not listen\n${running.stderr}\n${running.stdout}`)
  }
  return running
}

function stopServer (running: RunningServer) {
  if (running.exited === null) {
    running.child.kill('SIGKILL')
  }
}

function request (port: number, method: string, requestPath: string, headers: Record<string, string>, body?: string): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: requestPath,
      method,
      headers: body === undefined ? headers : { ...headers, 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') })
      })
    })
    req.setTimeout(10000, () => { req.destroy(new Error('timeout')) })
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

async function waitForExit (running: RunningServer, ms: number) {
  if (running.exited) return
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms)
    running.child.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

async function sameResponseAsAnonymous (running: RunningServer, anonymous: HttpResult, attack: Promise<HttpResult>, label: string) {
  let attackResult: HttpResult
  try {
    attackResult = await attack
  } catch (error) {
    await waitForExit(running, 1000)
    assert.fail(`${label} failed (${error instanceof Error ? error.message : String(error)}); process ${JSON.stringify(running.exited)}\n${running.stderr}`)
  }
  await waitForExit(running, 400)
  assert.equal(running.exited, null, `${label} terminated the server\n${running.stderr}`)
  assert.equal(attackResult.status, anonymous.status, label)
  assert.equal(attackResult.body, anonymous.body, label)
}

async function withServer (fn: (running: RunningServer) => Promise<void>) {
  const running = await startServer()
  try {
    await fn(running)
  } finally {
    stopServer(running)
  }
}

void describe('inherited session tokens', { concurrency: 1 }, () => {
  void it('GET /dataerasure does not authenticate an inherited cookie token or terminate the process', { timeout: 180000 }, async () => {
    const cookies = [
      ...inheritedTokens.map((token) => `token=${token}`),
      'token="__proto__"'
    ]
    for (const cookie of cookies) {
      await withServer(async (running) => {
        const anonymous = await request(running.port, 'GET', '/dataerasure', {})
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'GET', '/dataerasure', { Cookie: cookie }),
          `GET /dataerasure Cookie: ${cookie}`
        )
      })
    }
  })

  void it('POST /dataerasure does not authenticate an inherited cookie token or terminate the process', { timeout: 180000 }, async () => {
    for (const token of inheritedTokens) {
      await withServer(async (running) => {
        const anonymous = await request(running.port, 'POST', '/dataerasure', { 'Content-Type': 'application/x-www-form-urlencoded' }, 'layout=')
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'POST', '/dataerasure', { Cookie: `token=${token}`, 'Content-Type': 'application/x-www-form-urlencoded' }, 'layout='),
          `POST /dataerasure token=${token}`
        )
      })
    }
  })

  void it('GET /rest/products/:id/reviews does not authenticate an inherited bearer token or terminate the process', { timeout: 180000 }, async () => {
    for (const token of inheritedTokens) {
      await withServer(async (running) => {
        let reviewedPath = ''
        let anonymous: HttpResult | undefined
        for (let id = 1; id <= 40; id++) {
          const candidate = await request(running.port, 'GET', `/rest/products/${id}/reviews`, {})
          const parsed: { data?: unknown } = JSON.parse(candidate.body)
          if (candidate.status === 200 && Array.isArray(parsed.data) && parsed.data.length > 0) {
            reviewedPath = `/rest/products/${id}/reviews`
            anonymous = candidate
            break
          }
        }
        assert.ok(anonymous, 'seeded product reviews were not found')
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'GET', reviewedPath, { Authorization: `Bearer ${token}` }),
          `GET ${reviewedPath} Authorization Bearer ${token}`
        )
      })
    }
  })

  void it('GET /profile does not authenticate an inherited cookie token', { timeout: 120000 }, async () => {
    await withServer(async (running) => {
      const anonymous = await request(running.port, 'GET', '/profile', {})
      for (const token of inheritedTokens) {
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'GET', '/profile', { Cookie: `token=${token}` }),
          `GET /profile token=${token}`
        )
      }
    })
  })

  void it('POST /profile does not authenticate an inherited cookie token', { timeout: 120000 }, async () => {
    const body = 'username=anonymous'
    await withServer(async (running) => {
      const anonymous = await request(running.port, 'POST', '/profile', { 'Content-Type': 'application/x-www-form-urlencoded' }, body)
      for (const token of inheritedTokens) {
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'POST', '/profile', { Cookie: `token=${token}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body),
          `POST /profile token=${token}`
        )
      }
    })
  })

  void it('POST /profile/image/url does not authenticate an inherited cookie token', { timeout: 120000 }, async () => {
    const body = 'imageUrl=http%3A%2F%2F127.0.0.1%3A1%2Fnot-a-server'
    await withServer(async (running) => {
      const anonymous = await request(running.port, 'POST', '/profile/image/url', { 'Content-Type': 'application/x-www-form-urlencoded' }, body)
      for (const token of inheritedTokens) {
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'POST', '/profile/image/url', { Cookie: `token=${token}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body),
          `POST /profile/image/url token=${token}`
        )
      }
    })
  })

  void it('GET /rest/saveLoginIp does not authenticate an inherited bearer token', { timeout: 120000 }, async () => {
    await withServer(async (running) => {
      const anonymous = await request(running.port, 'GET', '/rest/saveLoginIp', {})
      for (const token of inheritedTokens) {
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'GET', '/rest/saveLoginIp', { Authorization: `Bearer ${token}` }),
          `GET /rest/saveLoginIp Bearer ${token}`
        )
      }
    })
  })

  void it('GET /rest/image-captcha does not authenticate an inherited bearer token', { timeout: 120000 }, async () => {
    await withServer(async (running) => {
      const anonymous = await request(running.port, 'GET', '/rest/image-captcha', {})
      for (const token of inheritedTokens) {
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'GET', '/rest/image-captcha', { Authorization: `Bearer ${token}` }),
          `GET /rest/image-captcha Bearer ${token}`
        )
      }
    })
  })

  void it('GET /rest/user/change-password does not authenticate an inherited token', { timeout: 120000 }, async () => {
    const requestPath = '/rest/user/change-password?new=replacement-value&repeat=replacement-value&current=current-value'
    await withServer(async (running) => {
      const anonymous = await request(running.port, 'GET', requestPath, {})
      for (const token of inheritedTokens) {
        await sameResponseAsAnonymous(
          running,
          anonymous,
          request(running.port, 'GET', requestPath, { Authorization: `Bearer=${token}` }),
          `GET /rest/user/change-password Bearer=${token}`
        )
      }
    })
  })
})
