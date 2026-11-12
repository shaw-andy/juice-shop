/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import express from 'express'
import multer from 'multer'
import request from 'supertest'
import type { Express } from 'express'
import { challenges } from '../../data/datacache'
import * as metrics from '../../routes/metrics'
import {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
} from '../../routes/fileUpload'
import { storedZip } from '../server/helpers/storedZip'

let app: Express
const complaintsDir = path.resolve('uploads/complaints')

before(() => {
  // Same registration as server.ts. Importing server.ts exits when the frontend build is absent.
  challenges.fileWriteChallenge = { solved: false, disabledEnv: null } as typeof challenges.fileWriteChallenge
  const uploadToMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200000 } })
  app = express()
  app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), checkUploadSize, checkFileType, handleZipFileUpload, handleXmlUpload, handleYamlUpload)
})

function upload (entryName: string, content: Buffer | string) {
  const zip = storedZip(entryName, content)
  return request(app)
    .post('/file-upload')
    .attach('file', zip, { filename: 'complaint.zip', contentType: 'application/zip' })
}

async function tracked<T> (dir: string, action: () => Promise<T>) {
  const seen: string[] = []
  const watcher = fs.watch(dir, (_event, filename) => {
    if (filename != null) seen.push(filename)
  })
  try {
    await new Promise((resolve) => setTimeout(resolve, 50))
    const value = await action()
    await new Promise((resolve) => setImmediate(resolve))
    return { value, seen }
  } finally {
    watcher.close()
  }
}

void describe('POST /file-upload zip entries', () => {
  void it('writes an entry whose resolved path stays inside uploads/complaints', async () => {
    const name = `zz-inside-${process.pid}.txt`
    const target = path.join(complaintsDir, name)
    try {
      const res = await upload(name, 'hello')
      assert.equal(res.status, 204)
      assert.equal(fs.existsSync(target), true)
      assert.equal(fs.readFileSync(target, 'utf8'), 'hello')
    } finally {
      fs.rmSync(target, { force: true })
    }
  })

  void it('does not create a file outside uploads/complaints when the entry name climbs into routes', async () => {
    const name = `zz-plant-${process.pid}.ts`
    const target = path.resolve('routes', name)
    const entryName = `../../routes/${name}`
    try {
      const { value: res, seen } = await tracked(path.resolve('routes'), async () => await upload(entryName, 'planted'))
      assert.equal(res.status === 204 || res.status === 400, true)
      assert.equal(fs.existsSync(target), false)
      assert.equal(seen.includes(name), false)
    } finally {
      fs.rmSync(target, { force: true })
    }
  })

  void it('does not follow a symlink under uploads/complaints to a directory outside it', async () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'complaint-escape-'))
    const linkName = `zz-escape-${process.pid}`
    const linkPath = path.join(complaintsDir, linkName)
    const planted = path.join(outside, 'planted.txt')
    fs.symlinkSync(outside, linkPath)
    try {
      const { value: res, seen } = await tracked(outside, async () => await upload(`${linkName}/planted.txt`, 'owned'))
      assert.equal(res.status === 204 || res.status === 400, true)
      assert.equal(fs.existsSync(planted), false)
      assert.equal(seen.includes('planted.txt'), false)
    } finally {
      fs.rmSync(planted, { force: true })
      fs.rmSync(linkPath, { force: true })
      fs.rmSync(outside, { recursive: true, force: true })
    }
  })
})
