/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { type AddressInfo } from 'node:net'

const placeholderPassword = 'placeholder-password'

// server.ts refuses to stay up until these built files exist. The upload
// handler does not read them; empty stand-ins let the real server module boot.
const shopBuildPlaceholders = [
  'build/server.js',
  'frontend/dist/frontend/index.html',
  'frontend/dist/frontend/styles.css',
  'frontend/dist/frontend/main.js',
  'frontend/dist/frontend/polyfills.js',
  'frontend/dist/frontend/hacking-instructor-test.js'
]

function ensureShopBuildPlaceholders (): string[] {
  const created: string[] = []
  for (const relativePath of shopBuildPlaceholders) {
    const absolutePath = path.resolve(relativePath)
    if (!fs.existsSync(absolutePath)) {
      fs.mkdirSync(path.dirname(absolutePath), { recursive: true })
      fs.writeFileSync(absolutePath, '')
      created.push(absolutePath)
    }
  }
  return created
}

function startTruncatedImageServer (): Promise<{ server: http.Server, port: number }> {
  const server = http.createServer((req, res) => {
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': '1000000',
      Connection: 'keep-alive'
    })
    res.write(Buffer.from('not-a-complete-image'), () => {
      setTimeout(() => {
        res.socket?.destroy()
      }, 300)
    })
  })
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo | null
      if (address == null) {
        reject(new Error('truncated image server failed to bind'))
        return
      }
      resolve({ server, port: address.port })
    })
    server.once('error', reject)
  })
}

function startShop (): { child: ChildProcess, ready: Promise<number>, output: () => string } {
  let output = ''
  const child = spawn(process.execPath, [
    '--import', './test/api/helpers/test-env.mjs',
    '--import', 'tsx',
    './test/api/helpers/profileImageUrlUploadServer.ts'
  ], {
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: { ...process.env, NODE_ENV: 'test' }
  })
  child.stdout?.on('data', (chunk: Buffer) => {
    output += chunk.toString()
  })
  child.stderr?.on('data', (chunk: Buffer) => {
    output += chunk.toString()
  })
  const ready = new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`shop process did not listen\n${output}`))
    }, 60000)
    child.once('message', (message: { port?: number }) => {
      clearTimeout(timer)
      if (typeof message?.port !== 'number') {
        reject(new Error(`shop process sent no port\n${output}`))
        return
      }
      resolve(message.port)
    })
    child.once('exit', (code, signal) => {
      clearTimeout(timer)
      reject(new Error(`shop process exited before listening code=${code} signal=${signal}\n${output}`))
    })
  })
  return { child, ready, output: () => output }
}

void describe('POST /profile/image/url truncated response body', () => {
  let imageServer: http.Server | undefined
  let shop: ChildProcess | undefined
  let createdPlaceholders: string[] = []

  after(() => {
    imageServer?.close()
    if (shop != null && shop.exitCode == null && !shop.killed) {
      shop.kill('SIGTERM')
    }
    for (const created of createdPlaceholders) {
      fs.rmSync(created, { force: true })
    }
  })

  void it('keeps the process alive and answers the request when the image host closes early', async () => {
    createdPlaceholders = ensureShopBuildPlaceholders()
    const truncated = await startTruncatedImageServer()
    imageServer = truncated.server
    const started = startShop()
    shop = started.child
    const shopPort = await started.ready

    const email = `stream-error-${Date.now()}@juice-sh.op`
    const registerRes = await fetch(`http://127.0.0.1:${shopPort}/api/Users/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email,
        password: placeholderPassword,
        passwordRepeat: placeholderPassword
      })
    })
    const registerBody = await registerRes.text()
    assert.equal(registerRes.status, 201, `registration failed: ${registerRes.status} ${registerBody}`)

    const loginRes = await fetch(`http://127.0.0.1:${shopPort}/rest/user/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: placeholderPassword })
    })
    const loginText = await loginRes.text()
    assert.equal(loginRes.status, 200, `login failed: ${loginRes.status} ${loginText}`)
    const loginBody = JSON.parse(loginText) as { authentication?: { token?: string } }
    const token = loginBody.authentication?.token
    assert.equal(typeof token, 'string')

    const form = new FormData()
    form.set('imageUrl', `http://127.0.0.1:${truncated.port}/photo.jpg`)
    let uploadRes: Response
    try {
      uploadRes = await fetch(`http://127.0.0.1:${shopPort}/profile/image/url`, {
        method: 'POST',
        headers: { cookie: `token=${token}` },
        body: form,
        redirect: 'manual'
      })
    } catch (error) {
      await new Promise((resolve) => setTimeout(resolve, 200))
      assert.fail(`upload request failed and the shop process is no longer usable: ${(error as Error).message}\nexit=${started.child.exitCode} signal=${started.child.signalCode}\n${started.output()}`)
    }

    assert.equal(uploadRes.status, 302, `upload was not handled\nexit=${started.child.exitCode}\n${started.output()}`)
    assert.ok(uploadRes.headers.get('location')?.endsWith('/profile'), uploadRes.headers.get('location') ?? '')

    await new Promise((resolve) => setTimeout(resolve, 200))
    assert.equal(started.child.exitCode, null, `shop process exited\n${started.output()}`)

    const followUp = await fetch(`http://127.0.0.1:${shopPort}/rest/user/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: placeholderPassword })
    })
    assert.equal(followUp.status, 200)
    assert.equal(started.child.exitCode, null)
  })
})
