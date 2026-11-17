/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { MemoryModel } from '../../models/memory'

const MEMORY_CAPTION_MAX_LENGTH = 200
const MEMORY_PAGE_MAX = 10
const PARSER_FIELD_MAX = (1 * 1024 * 1024) - 1
const PUBLIC_USER_KEYS = ['id', 'username']

const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
const imageFile = path.resolve(__dirname, '../files/validProfileImage.jpg')

let app: Express
let token: string

before(async () => {
  fs.mkdirSync(uploadDir, { recursive: true })
  const result = await createTestApp()
  app = result.app
  const domain = config.get<string>('application.domain')
  const email = `memory-limit@${domain}`
  const password = 'placeholder-password'
  await register(app, { email, password })
  const authentication = await login(app, { email, password })
  token = authentication.token
}, { timeout: 60000 })

void describe('/rest/memories resource limits', { concurrency: 1 }, () => {
  void it('rejects a caption above 200 characters before insert and before writing an upload', async () => {
    await assertCaptionRejected('A'.repeat(MEMORY_CAPTION_MAX_LENGTH + 1))
  })

  void it('rejects a caption at the multipart parser field ceiling before insert and before writing an upload', async () => {
    await assertCaptionRejected('B'.repeat(PARSER_FIELD_MAX))
  })

  void it('still accepts a caption at the 200 character limit', async () => {
    const caption = `C${'c'.repeat(MEMORY_CAPTION_MAX_LENGTH - 1)}`
    const res = await postMemory(caption)
    assert.equal(res.status, 200, `short caption was refused: ${res.status} ${JSON.stringify(res.body).slice(0, 300)}`)
    assert.equal(res.body.data.caption, caption)
  })

  void it('pages the public list and omits user columns the photo wall does not show', async () => {
    let created = 0
    while (await MemoryModel.count() <= MEMORY_PAGE_MAX && created < MEMORY_PAGE_MAX) {
      const res = await postMemory(`short-${created}`)
      assert.equal(res.status, 200, `short caption was refused: ${res.status} ${JSON.stringify(res.body).slice(0, 300)}`)
      created++
    }
    const count = await MemoryModel.count()
    assert.ok(count > MEMORY_PAGE_MAX, `expected more than ${MEMORY_PAGE_MAX} stored memories, found ${count}`)

    const listed = await request(app).get('/rest/memories')
    assert.equal(listed.status, 200)
    const userKeys = Object.keys(listed.body.data[0]?.User ?? {}).join(',')
    assert.ok(listed.body.data.length <= MEMORY_PAGE_MAX, `public list returned ${listed.body.data.length} rows; user keys: ${userKeys}`)
    assert.equal(listed.body.total, count)

    const first = await request(app).get('/rest/memories').query({ limit: 1, offset: 0 })
    const second = await request(app).get('/rest/memories').query({ limit: 1, offset: 1 })
    assert.equal(first.status, 200)
    assert.equal(second.status, 200)
    assert.equal(first.body.data.length, 1)
    assert.equal(second.body.data.length, 1)
    assert.notEqual(first.body.data[0].id, second.body.data[0].id)
    assert.equal(first.body.total, count)
    assert.equal(second.body.total, count)

    for (const memory of [...listed.body.data, ...first.body.data, ...second.body.data]) {
      assertUserColumns(memory.User)
    }
  })

  void it('does not return an overlong caption from the authenticated data export', async () => {
    const caption = 'D'.repeat(MEMORY_CAPTION_MAX_LENGTH + 1)
    const { created, restore } = trackUploadWrites()
    try {
      const posted = await postMemory(caption)
      const exported = await request(app)
        .post('/rest/user/data-export')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
        .send({ format: '1' })
      const parsed = exported.status === 200 ? JSON.parse(exported.body.userData) : { memories: [] }
      const captions = (parsed.memories ?? []).map((memory: { caption?: string }) => memory.caption ?? '')
      const stored = await MemoryModel.findAll({ where: { caption } })
      assert.equal(
        posted.status >= 400 && posted.status < 500 && created.length === 0 && stored.length === 0 && !captions.includes(caption),
        true,
        `status=${posted.status} uploads=${created.length} stored=${stored.length} exportStatus=${exported.status} exported=${captions.includes(caption)}`
      )
    } finally {
      restore()
      for (const file of created) {
        fs.rmSync(file, { force: true })
      }
    }
  })
})

async function assertCaptionRejected (caption: string) {
  const { created, restore } = trackUploadWrites()
  try {
    const res = await postMemory(caption)
    const stored = await MemoryModel.findAll({ where: { caption } })
    const listed = await request(app).get('/rest/memories')
    const listedText = JSON.stringify(listed.body)
    assert.equal(
      res.status >= 400 && res.status < 500 && created.length === 0 && stored.length === 0 && !listedText.includes(caption),
      true,
      `status=${res.status} uploads=${created.length} stored=${stored.length} listed=${listedText.includes(caption)} body=${JSON.stringify(res.body).slice(0, 300)}`
    )
  } finally {
    restore()
    for (const file of created) {
      fs.rmSync(file, { force: true })
    }
  }
}

function postMemory (caption: string) {
  return request(app)
    .post('/rest/memories')
    .set('Authorization', 'Bearer ' + token)
    .attach('image', imageFile, { filename: 'valid.jpg', contentType: 'image/jpeg' })
    .field('caption', caption)
}

function trackUploadWrites () {
  const created: string[] = []
  const original = fs.createWriteStream
  const patched = function (this: unknown, file: fs.PathLike, options?: BufferEncoding | fs.WriteStreamOptions) {
    const target = String(file)
    if (target.includes(`${path.sep}uploads${path.sep}`)) {
      created.push(target)
    }
    return original.call(fs, file, options as fs.WriteStreamOptions)
  }
  fs.createWriteStream = patched as typeof fs.createWriteStream
  return {
    created,
    restore () {
      fs.createWriteStream = original
    }
  }
}

function assertUserColumns (user: Record<string, unknown> | undefined) {
  assert.ok(user)
  assert.equal(typeof user.username, 'string')
  for (const key of Object.keys(user)) {
    assert.ok(PUBLIC_USER_KEYS.includes(key), `public memory list included User.${key}`)
  }
}
