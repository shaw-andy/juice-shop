/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import config from 'config'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { type AddressInfo } from 'node:net'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'

const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')

const activeExtension = /\.(svg|svgz|html|xhtml|htm|xml|js|mjs|cjs)$/i

const activeContentTypes = [
  'image/svg+xml',
  'text/html',
  'application/xhtml+xml',
  'text/xml',
  'application/xml',
  'application/javascript',
  'text/javascript',
  'application/ecmascript',
  'text/ecmascript'
]

let app: Express
let mockServer: http.Server
let mockOrigin: string

before(async () => {
  fs.mkdirSync(uploadDir, { recursive: true })
  const result = await createTestApp()
  app = result.app

  mockServer = http.createServer((req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname
    const payload = svgDocument(markerFrom(pathname))
    res.statusCode = 200
    res.setHeader('Content-Type', pathname.includes('/plain/') ? 'text/plain' : 'image/svg+xml')
    res.end(payload)
  })
  await new Promise<void>((resolve) => { mockServer.listen(0, '127.0.0.1', resolve) })
  const address = mockServer.address() as AddressInfo
  mockOrigin = `http://127.0.0.1:${address.port}`
}, { timeout: 60000 })

after(async () => {
  await new Promise<void>((resolve, reject) => {
    mockServer.close((err) => { err != null ? reject(err) : resolve() })
  })
})

void describe('profile image URL upload must not publish an executable SVG', () => {
  void it('does not serve a script-bearing SVG fetched from a URL whose suffix is svg', async () => {
    const marker = uniqueMarker()
    const { token, userId } = await signedInCustomer()
    const seen = watchForMarker(marker)

    const posted = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .type('form')
      .send({ imageUrl: `${mockOrigin}/plain/${marker}.svg` })
      .redirects(0)

    seen.stop()
    assert.equal(posted.status, 302)
    await assertMarkerIsNotExecutable(token, userId, marker, seen.captured)
  })

  void it('does not serve a script-bearing SVG when the URL suffix is SVG in another case', async () => {
    const marker = uniqueMarker()
    const { token, userId } = await signedInCustomer()
    const seen = watchForMarker(marker)

    const posted = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .type('form')
      .send({ imageUrl: `${mockOrigin}/typed/${marker}.SVG` })
      .redirects(0)

    seen.stop()
    assert.equal(posted.status, 302)
    await assertMarkerIsNotExecutable(token, userId, marker, seen.captured)
  })

  void it('does not publish an SVG document uploaded as a profile image file', async () => {
    const marker = uniqueMarker()
    const { token, userId } = await signedInCustomer()
    const seen = watchForMarker(marker)

    await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', Buffer.from(svgDocument(marker)), { filename: 'picture.svg', contentType: 'image/svg+xml' })

    seen.stop()
    await assertMarkerIsNotExecutable(token, userId, marker, seen.captured)
  })

  void it('does not publish an SVG document uploaded as a photo-wall memory', async () => {
    const marker = uniqueMarker()
    const { token, userId } = await signedInCustomer()
    const seen = watchForMarker(marker)

    await request(app)
      .post('/rest/memories')
      .set('Authorization', `Bearer ${token}`)
      .set('Cookie', `token=${token}`)
      .attach('image', Buffer.from(svgDocument(marker)), { filename: 'picture.svg', contentType: 'image/svg+xml' })

    seen.stop()
    await assertMarkerIsNotExecutable(token, userId, marker, seen.captured)
  })
})

async function signedInCustomer (): Promise<{ token: string, userId: number }> {
  const email = `svg-probe-${crypto.randomBytes(8).toString('hex')}@${config.get<string>('application.domain')}`
  const password = 'placeholder'
  await register(app, { email, password })
  const { token } = await login(app, { email, password })
  const who = await request(app)
    .get('/rest/user/whoami')
    .set('Cookie', `token=${token}`)
  const userId = who.body?.user?.id
  assert.equal(typeof userId, 'number')
  return { token, userId }
}

async function assertMarkerIsNotExecutable (token: string, userId: number, marker: string, capturedDuringRequest: boolean): Promise<void> {
  const predictable = await request(app).get(`/assets/public/images/uploads/${userId}.svg`)
  assertExecutable(predictable, marker, `/assets/public/images/uploads/${userId}.svg`)
  assert.equal(capturedDuringRequest, false, 'the upload wrote a script-bearing image into the public uploads directory before the request finished')

  const row = await UserModel.findByPk(userId)
  const profileImage = row?.profileImage ?? ''
  if (profileImage.startsWith('/assets/') || profileImage.startsWith('assets/')) {
    const urlPath = profileImage.startsWith('/') ? profileImage : `/${profileImage}`
    const served = await request(app).get(urlPath).set('Cookie', `token=${token}`)
    assertExecutable(served, marker, urlPath)
  }

  for (const name of fs.readdirSync(uploadDir)) {
    const full = path.join(uploadDir, name)
    if (!fs.statSync(full).isFile()) continue
    if (!fs.readFileSync(full).includes(marker)) continue
    const served = await request(app).get(`/assets/public/images/uploads/${name}`)
    assertExecutable(served, marker, name)
    fs.unlinkSync(full)
  }
}

function assertExecutable (res: Response, marker: string, where: string): void {
  assert.equal(
    responseExecutesInlineScript(res, marker),
    false,
    `${where} is served as an executable same-origin document (status ${res.status}, content-type ${String(res.headers['content-type'])}, content-disposition ${String(res.headers['content-disposition'] ?? '')}, content-security-policy ${String(res.headers['content-security-policy'] ?? '')})`
  )
}

function responseExecutesInlineScript (res: Response, marker: string): boolean {
  if (res.status !== 200) return false
  if (!responseBody(res).includes(marker)) return false
  const disposition = String(res.headers['content-disposition'] ?? '')
  if (/attachment/i.test(disposition)) return false
  if (cspBlocksInlineScript(headerValue(res.headers['content-security-policy']))) return false
  const contentType = headerValue(res.headers['content-type'])
  if (contentType === '') return true
  return activeContentTypes.some((type) => contentType.startsWith(type))
}

function responseBody (res: Response): string {
  if (typeof res.text === 'string' && res.text.length > 0) return res.text
  if (Buffer.isBuffer(res.body)) return res.body.toString('utf8')
  if (typeof res.body === 'string') return res.body
  return ''
}

function cspBlocksInlineScript (csp: string): boolean {
  if (csp.trim() === '') return false
  const directives = new Map<string, string>()
  for (const part of csp.split(';')) {
    const trimmed = part.trim()
    if (trimmed === '') continue
    const space = trimmed.indexOf(' ')
    const name = (space === -1 ? trimmed : trimmed.slice(0, space)).toLowerCase()
    const value = space === -1 ? '' : trimmed.slice(space + 1).trim().toLowerCase()
    directives.set(name, value)
  }
  const source = directives.get('script-src') ?? directives.get('default-src')
  if (source == null) return false
  return !source.includes("'unsafe-inline'")
}

function headerValue (value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value.join(',').toLowerCase()
  return (value ?? '').toLowerCase()
}

function watchForMarker (marker: string): { stop: () => void, captured: boolean } {
  const state = { captured: false }
  const watcher = fs.watch(uploadDir, (_event, filename) => {
    if (filename == null) return
    const name = filename.toString()
    if (!activeExtension.test(name)) return
    const full = path.join(uploadDir, name)
    try {
      if (fs.readFileSync(full).includes(marker)) state.captured = true
    } catch {
      // The file can disappear between the event and the read.
    }
  })
  return {
    stop: () => { watcher.close() },
    get captured () { return state.captured }
  }
}

function svgDocument (marker: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" onload="document.documentElement.setAttribute('data-probe','${marker}')"><script>document.documentElement.setAttribute('data-probe','${marker}')</script></svg>`
}

function uniqueMarker (): string {
  return `svgprobe${crypto.randomBytes(8).toString('hex')}`
}

function markerFrom (pathname: string): string {
  const base = pathname.split('/').pop() ?? ''
  return base.replace(/\.[^.]+$/, '')
}
