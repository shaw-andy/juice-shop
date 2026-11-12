/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * Security spec for POST /profile/image/url. These tests fail while the handler
 * fetches a user-supplied URL and publishes the response body. They pass once
 * that request is refused before any outbound fetch or upload is written.
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { type AddressInfo } from 'node:net'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'

const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')

let app: Express

before(async () => {
  await fs.promises.mkdir(uploadDir, { recursive: true })
  const result = await createTestApp()
  app = result.app
}, { timeout: 120000 })

interface InternalEndpoint {
  port: number
  hits: string[]
  close: () => Promise<void>
}

async function listen (host: string, respond: http.RequestListener): Promise<InternalEndpoint> {
  const hits: string[] = []
  const server = http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url ?? ''}`)
    respond(req, res)
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, host, () => { resolve() })
  })
  return {
    port: (server.address() as AddressInfo).port,
    hits,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => { err != null ? reject(err) : resolve() })
      })
    }
  }
}

function marker () {
  return `internal-response-${crypto.randomBytes(8).toString('hex')}`
}

async function signedInUser () {
  const email = `profile-url-${crypto.randomBytes(8).toString('hex')}@${config.get<string>('application.domain')}`
  const password = 'placeholder-password'
  const registered = await register(app, { email, password })
  const userId = registered.body.data.id as number
  const { token } = await login(app, { email, password })
  return { token, userId }
}

async function userUploadNames (userId: number) {
  const names = await fs.promises.readdir(uploadDir)
  return names.filter((name) => name.startsWith(`${userId}.`))
}

async function userFileMtimes (userId: number) {
  const mtimes = new Map<string, number>()
  for (const name of await userUploadNames(userId)) {
    const stat = await fs.promises.stat(path.join(uploadDir, name))
    mtimes.set(name, stat.mtimeMs)
  }
  return mtimes
}

async function filesContaining (needle: string) {
  const names = await fs.promises.readdir(uploadDir)
  const found: string[] = []
  for (const name of names) {
    const full = path.join(uploadDir, name)
    const stat = await fs.promises.stat(full)
    if (!stat.isFile()) continue
    const body = await fs.promises.readFile(full)
    if (body.includes(Buffer.from(needle))) found.push(name)
  }
  return found
}

async function postImageUrl (imageUrl: string, encoding: 'urlencoded' | 'multipart', token?: string) {
  const req = request(app).post('/profile/image/url').redirects(0)
  if (token != null) req.set('Cookie', `token=${token}`)
  if (encoding === 'urlencoded') {
    return await req.type('form').send({ imageUrl })
  }
  return await req.field('imageUrl', imageUrl)
}

async function publicationProblems (userId: number, bodyMarker: string, hits: string[]) {
  const leakedNames = await filesContaining(bodyMarker)
  const written = await userUploadNames(userId)
  const publicPaths = [...new Set([
    ...written.map((name) => `/assets/public/images/uploads/${name}`),
    `/assets/public/images/uploads/${userId}.jpg`
  ])]
  const publicLeaks: string[] = []
  for (const publicPath of publicPaths) {
    const publicRes = await request(app).get(publicPath)
    const raw = Buffer.isBuffer(publicRes.body)
      ? publicRes.body
      : Buffer.from(typeof publicRes.text === 'string' ? publicRes.text : '')
    if (raw.includes(Buffer.from(bodyMarker))) {
      publicLeaks.push(`${publicPath} (${publicRes.status})`)
    }
  }
  const user = await UserModel.findByPk(userId)
  const profileImage = user?.profileImage ?? ''

  const problems: string[] = []
  if (hits.length > 0) problems.push(`internal endpoint was requested (${hits.join(', ')})`)
  if (leakedNames.length > 0) problems.push(`upload file contained the response body (${leakedNames.join(', ')})`)
  if (publicLeaks.length > 0) problems.push(`unauthenticated GET returned the response body (${publicLeaks.join(', ')})`)
  if (profileImage.includes(`/assets/public/images/uploads/${userId}.`)) {
    problems.push(`profileImage was set to the published upload (${profileImage})`)
  }
  return problems
}

async function expectNoPublication (options: {
  imageUrl: string
  bodyMarker: string
  encoding: 'urlencoded' | 'multipart'
  endpoints?: InternalEndpoint[]
  token?: string
  userId?: number
}) {
  const { token, userId } = options.token != null && options.userId != null
    ? { token: options.token, userId: options.userId }
    : await signedInUser()
  const before = await userFileMtimes(userId)
  const touched: string[] = []
  const watcher = fs.watch(uploadDir, (_event, filename) => {
    if (filename != null && String(filename).startsWith(`${userId}.`)) touched.push(String(filename))
  })
  try {
    await postImageUrl(options.imageUrl, options.encoding, token)
    await new Promise((resolve) => setImmediate(resolve))
  } finally {
    watcher.close()
  }
  const hits = (options.endpoints ?? []).flatMap((endpoint) => endpoint.hits)
  const problems = await publicationProblems(userId, options.bodyMarker, hits)
  const after = await userFileMtimes(userId)
  const changed = [...after.entries()]
    .filter(([name, mtime]) => before.get(name) !== mtime)
    .map(([name]) => name)
  for (const name of before.keys()) {
    if (!after.has(name)) changed.push(name)
  }
  if (touched.length > 0 || changed.length > 0) {
    const names = [...new Set([...touched, ...changed])]
    problems.push(`upload file was written during the request (${names.join(', ')})`)
  }
  await Promise.all([...after.keys()].map(async (name) => {
    await fs.promises.unlink(path.join(uploadDir, name)).catch(() => {})
  }))
  assert.deepEqual(problems, [])
}

void describe('POST /profile/image/url must not fetch or publish internal responses', () => {
  void it('urlencoded imageUrl, the profile form encoding, does not fetch loopback or publish the body', async () => {
    const bodyMarker = marker()
    const endpoint = await listen('127.0.0.1', (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(bodyMarker)
    })
    try {
      await expectNoPublication({
        imageUrl: `http://127.0.0.1:${endpoint.port}/internal.jpg`,
        bodyMarker,
        encoding: 'urlencoded',
        endpoints: [endpoint]
      })
    } finally {
      await endpoint.close()
    }
  })

  void it('multipart imageUrl does not fetch loopback or publish the body', async () => {
    const bodyMarker = marker()
    const endpoint = await listen('127.0.0.1', (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(bodyMarker)
    })
    try {
      await expectNoPublication({
        imageUrl: `http://127.0.0.1:${endpoint.port}/internal.jpg`,
        bodyMarker,
        encoding: 'multipart',
        endpoints: [endpoint]
      })
    } finally {
      await endpoint.close()
    }
  })

  const loopbackForms: Array<{ name: string, host: string, urlHost: (port: number) => string }> = [
    { name: 'localhost', host: '127.0.0.1', urlHost: (port) => `localhost:${port}` },
    { name: 'decimal loopback', host: '127.0.0.1', urlHost: (port) => `2130706433:${port}` },
    { name: 'hex loopback', host: '127.0.0.1', urlHost: (port) => `0x7f000001:${port}` },
    { name: 'short loopback', host: '127.0.0.1', urlHost: (port) => `127.1:${port}` },
    { name: 'IPv4-mapped IPv6 loopback', host: '127.0.0.1', urlHost: (port) => `[::ffff:127.0.0.1]:${port}` },
    { name: 'IPv6 loopback', host: '::1', urlHost: (port) => `[::1]:${port}` }
  ]

  for (const form of loopbackForms) {
    void it(`urlencoded imageUrl via ${form.name} does not fetch or publish the body`, async () => {
      const bodyMarker = marker()
      const endpoint = await listen(form.host, (_req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end(bodyMarker)
      })
      try {
        await expectNoPublication({
          imageUrl: `http://${form.urlHost(endpoint.port)}/internal.jpg`,
          bodyMarker,
          encoding: 'urlencoded',
          endpoints: [endpoint]
        })
      } finally {
        await endpoint.close()
      }
    })
  }

  void it('does not follow a redirect from an alternate loopback form to a second internal response', async () => {
    const bodyMarker = marker()
    const secret = await listen('::1', (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(bodyMarker)
    })
    const hop = await listen('127.0.0.1', (_req, res) => {
      res.writeHead(302, { location: `http://[::1]:${secret.port}/secret.jpg` })
      res.end('redirect-page')
    })
    try {
      await expectNoPublication({
        imageUrl: `http://0x7f000001:${hop.port}/hop.jpg`,
        bodyMarker,
        encoding: 'urlencoded',
        endpoints: [hop, secret]
      })
    } finally {
      await hop.close()
      await secret.close()
    }
  })

  void it('does not publish a data-scheme response body', async () => {
    const bodyMarker = marker()
    await expectNoPublication({
      imageUrl: `data:text/plain,${bodyMarker}`,
      bodyMarker,
      encoding: 'urlencoded'
    })
  })

  void it('does not fetch an internal URL for an anonymous request', async () => {
    const bodyMarker = marker()
    const endpoint = await listen('127.0.0.1', (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(bodyMarker)
    })
    try {
      await postImageUrl(`http://127.0.0.1:${endpoint.port}/internal.jpg`, 'urlencoded')
      const leakedNames = await filesContaining(bodyMarker)
      assert.deepEqual(endpoint.hits, [])
      assert.deepEqual(leakedNames, [])
    } finally {
      await endpoint.close()
    }
  })
})
