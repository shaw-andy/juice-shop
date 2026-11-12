/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import v8 from 'node:v8'
import vm from 'node:vm'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

v8.setFlagsFromString('--expose-gc')
const collectGarbage: () => void = vm.runInNewContext('gc')

const keyLength = 512

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 120000 })

function writeUnknownKey (file: string, length: number) {
  const unique = `notachallenge${process.hrtime.bigint().toString(16)}${Math.random().toString(16).slice(2)}`
  assert.ok(unique.length < length)
  fs.writeFileSync(file, unique + 'x'.repeat(length - unique.length))
}

async function postUnknownKey (file: string) {
  const key = fs.readFileSync(file, 'utf8')
  const res = await request(app)
    .post('/snippets/fixes')
    .set('Content-Type', 'application/json')
    .send({ key, selectedFix: 0 })
  assert.equal(res.status, 404)
  assert.equal(res.body.error, 'No fixes found for the snippet!')
}

async function getUnknownKey (file: string) {
  const key = fs.readFileSync(file, 'utf8')
  const res = await request(app)
    .get('/snippets/fixes/' + key)
  assert.equal(res.status, 404)
  assert.equal(res.body.error, 'No fixes found for the snippet!')
}

function heapSnapshot (dir: string) {
  collectGarbage()
  collectGarbage()
  const snapFile = path.join(dir, 'heap.heapsnapshot')
  v8.writeHeapSnapshot(snapFile)
  return fs.readFileSync(snapFile)
}

void describe('anonymous fix-check cache', () => {
  void it('GET /snippets/fixes/:key still returns fixes for a known challenge', async () => {
    const res = await request(app)
      .get('/snippets/fixes/resetPasswordBenderChallenge')
    assert.equal(res.status, 200)
    assert.equal(res.body.fixes.length, 3)
  })

  void it('POST /snippets/fixes does not retain unknown keys', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fixes-cache-'))
    try {
      const files: string[] = []
      for (let i = 0; i < 8; i++) {
        const file = path.join(dir, `post-${i}.txt`)
        writeUnknownKey(file, keyLength)
        files.push(file)
        await postUnknownKey(file)
      }
      await request(app)
        .post('/snippets/fixes')
        .set('Content-Type', 'application/json')
        .send({ key: 'resetPasswordBenderChallenge', selectedFix: 0 })
      const control = path.join(dir, 'control.txt')
      writeUnknownKey(control, keyLength)
      const snap = heapSnapshot(dir)
      assert.equal(snap.includes(fs.readFileSync(control)), false)
      const retained = files.filter((file) => snap.includes(fs.readFileSync(file)))
      assert.equal(retained.length, 0)
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  void it('GET /snippets/fixes/:key does not retain unknown keys', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fixes-cache-'))
    try {
      const files: string[] = []
      for (let i = 0; i < 8; i++) {
        const file = path.join(dir, `get-${i}.txt`)
        writeUnknownKey(file, keyLength)
        files.push(file)
        await getUnknownKey(file)
      }
      await request(app).get('/snippets/fixes/resetPasswordBenderChallenge')
      const control = path.join(dir, 'control.txt')
      writeUnknownKey(control, keyLength)
      const snap = heapSnapshot(dir)
      assert.equal(snap.includes(fs.readFileSync(control)), false)
      const retained = files.filter((file) => snap.includes(fs.readFileSync(file)))
      assert.equal(retained.length, 0)
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })
})
