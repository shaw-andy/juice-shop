/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { createTestApp } from './helpers/setup'

const browserAccept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
const invertedRange = 'bytes=50-1'
const stackFrame = /at .+\(.+:\d+:\d+\)/
const videoFile = path.resolve('frontend/dist/frontend/assets/public/videos/owasp_promo.mp4')

let app: Express

before(async () => {
  fs.mkdirSync(path.dirname(videoFile), { recursive: true })
  if (!fs.existsSync(videoFile)) {
    fs.copyFileSync(path.resolve('frontend/src/assets/public/videos/owasp_promo.mp4'), videoFile)
  }
  assert.ok(fs.statSync(videoFile).size > 50)
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function assertFixedError (res: Response) {
  const body = res.text ?? ''
  assert.equal(res.status, 500, body.slice(0, 500))
  assert.doesNotMatch(body, stackFrame)
  assert.equal(body.includes(process.cwd()), false)
  assert.equal(body.includes('node:internal'), false)
  assert.equal(body.includes('node:fs'), false)
  assert.equal(body.includes('videoHandler.ts'), false)
  assert.equal(body.includes('ERR_OUT_OF_RANGE'), false)
  assert.equal(body.includes('out of range'), false)
  assert.equal(body.includes('SQLITE_ERROR'), false)
  assert.equal(body.includes('SequelizeDatabaseError'), false)
  assert.equal(body.includes('SELECT * FROM Products'), false)
  assert.equal(body.includes('SELECT * FROM Users'), false)
  assert.equal(body.includes('id="stacktrace"'), false)
  assert.equal(body.includes('"stack"'), false)
  assert.equal(body.includes('"sql"'), false)
}

void describe('anonymous error responses', () => {
  void it('GET /video with an inverted Range and a browser Accept hides the exception', async () => {
    const res = await request(app)
      .get('/video')
      .set('Accept', browserAccept)
      .set('Range', invertedRange)
    assertFixedError(res)
  })

  void it('GET /video with an inverted Range and Accept application/json hides the exception', async () => {
    const res = await request(app)
      .get('/video')
      .set('Accept', 'application/json')
      .set('Range', invertedRange)
    assertFixedError(res)
  })

  void it('GET /video with an inverted Range and Accept text/plain hides the exception', async () => {
    const res = await request(app)
      .get('/video')
      .set('Accept', 'text/plain')
      .set('Range', invertedRange)
    assertFixedError(res)
  })

  void it('GET /rest/products/search with a broken query and Accept application/json hides the query', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=';")
      .set('Accept', 'application/json')
    assertFixedError(res)
  })

  void it('GET /rest/products/search with a broken query and a browser Accept hides the database error', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=';")
      .set('Accept', browserAccept)
    assertFixedError(res)
  })

  void it('POST /rest/user/login with a broken email and Accept application/json hides the query', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('Accept', 'application/json')
      .set('content-type', 'application/json')
      .send({ email: "'", password: 'placeholder' })
    assertFixedError(res)
  })
})
