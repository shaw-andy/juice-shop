/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import config from 'config'

const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
const placeholderPassword = 'placeholder-password'

interface RunningServer {
  child: ChildProcessWithoutNullStreams
  port: number
  output: () => string
  stop: () => void
}

function craftedAsfBuffer (length: number): Buffer {
  const payload = Buffer.alloc(length)
  Buffer.from([0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9]).copy(payload, 0)
  return payload
}

function uploadListing (): string[] {
  if (!existsSync(uploadDir)) {
    return []
  }
  return readdirSync(uploadDir).sort()
}

function delay (ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

function startServer (): Promise<RunningServer> {
  const child = spawn(process.execPath, [
    '--import', './test/api/helpers/test-env.mjs',
    '--import', 'tsx',
    path.resolve('test/api/helpers/profileImageDosServer.ts')
  ], {
    cwd: path.resolve('.'),
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NODE_ENV: 'test' }
  })

  let output = ''
  child.stdout.on('data', (chunk: Buffer) => {
    output += chunk.toString()
  })
  child.stderr.on('data', (chunk: Buffer) => {
    output += chunk.toString()
  })

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      reject(new Error('profile image server did not become ready\n' + output.slice(-4000)))
    }, 60000)

    child.on('exit', (code, signal) => {
      if (!output.includes('ready ')) {
        clearTimeout(timer)
        reject(new Error(`profile image server exited (${String(code)}/${String(signal)})\n` + output.slice(-4000)))
      }
    })

    const poll = setInterval(() => {
      const match = output.match(/ready (\d+)/)
      if (match == null) {
        return
      }
      clearInterval(poll)
      clearTimeout(timer)
      const port = Number(match[1])
      resolve({
        child,
        port,
        output: () => output,
        stop: () => {
          if (child.exitCode == null && child.signalCode == null) {
            child.kill('SIGKILL')
          }
        }
      })
    }, 50)
  })
}

function tickCount (output: string): number {
  return output.split('tick').length - 1
}

function probe (port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.get({
      hostname: '127.0.0.1',
      port,
      path: '/robots.txt',
      timeout: 2000
    }, (res) => {
      res.resume()
      res.on('end', () => {
        resolve(res.statusCode ?? 0)
      })
    })
    req.on('timeout', () => {
      req.destroy()
      reject(new Error('probe timed out'))
    })
    req.on('error', reject)
  })
}

async function postFile (port: number, payload: Buffer, cookie?: string): Promise<number> {
  const form = new FormData()
  form.append('file', new Blob([new Uint8Array(payload)]), 'sample.bin')
  const headers = new Headers()
  if (cookie != null) {
    headers.set('cookie', cookie)
  }
  const response = await fetch(`http://127.0.0.1:${port}/profile/image/file`, {
    method: 'POST',
    body: form,
    headers,
    redirect: 'manual',
    signal: AbortSignal.timeout(3000)
  })
  await response.arrayBuffer()
  return response.status
}

async function postJson (port: number, urlPath: string, body: unknown): Promise<{ status: number, body: unknown }> {
  const response = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000)
  })
  const text = await response.text()
  try {
    return { status: response.status, body: JSON.parse(text) as unknown }
  } catch {
    return { status: response.status, body: text }
  }
}

function tokenFrom (body: unknown): string {
  if (body == null || typeof body !== 'object' || !('authentication' in body)) {
    return ''
  }
  const authentication = body.authentication
  if (authentication == null || typeof authentication !== 'object' || !('token' in authentication)) {
    return ''
  }
  return typeof authentication.token === 'string' ? authentication.token : ''
}

async function assertUploadDoesNotStall (server: RunningServer, payload: Buffer, cookie?: string): Promise<number> {
  const before = uploadListing()
  const ticksBefore = tickCount(server.output())
  const uploadPromise = postFile(server.port, payload, cookie)
  await delay(500)
  const ticksWhileRunning = tickCount(server.output())
  let probeStatus = 0
  let probeError: unknown
  try {
    probeStatus = await probe(server.port)
  } catch (error) {
    probeError = error
  }
  let uploadStatus = 0
  let uploadError: unknown
  try {
    uploadStatus = await uploadPromise
  } catch (error) {
    uploadError = error
  }
  assert.deepEqual(uploadListing(), before)
  assert.ok(ticksWhileRunning > ticksBefore, 'event loop stopped while the profile image upload was being detected')
  assert.ifError(probeError)
  assert.equal(probeStatus, 200)
  assert.ifError(uploadError)
  assert.ok(uploadStatus === 415 || uploadStatus === 500, `unexpected status ${uploadStatus}`)
  return uploadStatus
}

void describe('/profile/image/file file-type detection', () => {
  void it('rejects a non-image upload without stalling the server', async () => {
    const server = await startServer()
    try {
      const status = await assertUploadDoesNotStall(server, Buffer.from('not an image, just plain text content'))
      assert.equal(status, 500)
    } finally {
      server.stop()
    }
  }, { timeout: 90000 })

  void it('rejects a short ASF upload without stalling the server', async () => {
    const server = await startServer()
    try {
      const status = await assertUploadDoesNotStall(server, craftedAsfBuffer(54))
      assert.equal(status, 415)
    } finally {
      server.stop()
    }
  }, { timeout: 90000 })

  void it('rejects an unauthenticated crafted ASF upload without stalling the server', async () => {
    const server = await startServer()
    try {
      await assertUploadDoesNotStall(server, craftedAsfBuffer(55))
    } finally {
      server.stop()
    }
  }, { timeout: 90000 })

  void it('rejects an authenticated crafted ASF upload without stalling the server', async () => {
    const server = await startServer()
    try {
      const email = `profile-image-dos@${config.get<string>('application.domain')}`
      const registered = await postJson(server.port, '/api/Users', {
        email,
        password: placeholderPassword,
        passwordRepeat: placeholderPassword
      })
      assert.equal(registered.status, 201)
      const loggedIn = await postJson(server.port, '/rest/user/login', {
        email,
        password: placeholderPassword
      })
      assert.equal(loggedIn.status, 200)
      const token = tokenFrom(loggedIn.body)
      assert.notEqual(token, '')
      await assertUploadDoesNotStall(server, craftedAsfBuffer(55), `token=${token}`)
    } finally {
      server.stop()
    }
  }, { timeout: 90000 })
})
