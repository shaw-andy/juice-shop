/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { crc32 } from 'node:zlib'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'

const ORIGINAL = 'original-sentinel-bytes\n'
const complaintsDir = path.resolve('uploads/complaints')
const outsideDir = path.join(path.dirname(process.cwd()), path.basename(process.cwd()) + '-zip-slip-outside')

let app: Express

interface Snap {
  existed: boolean
  data: Buffer | null
  ino: bigint | null
  mtimeNs: bigint | null
}

function snap (abs: string): Snap {
  if (!fs.existsSync(abs)) {
    return { existed: false, data: null, ino: null, mtimeNs: null }
  }
  const st = fs.statSync(abs)
  return { existed: true, data: fs.readFileSync(abs), ino: BigInt(st.ino), mtimeNs: st.mtimeNs }
}

function restore (abs: string, before: Snap) {
  if (!before.existed || before.data == null) {
    fs.rmSync(abs, { force: true })
    return
  }
  fs.mkdirSync(path.dirname(abs), { recursive: true })
  fs.writeFileSync(abs, before.data)
  if (before.mtimeNs != null) {
    const ns = before.mtimeNs
    const sec = Number(ns / 1_000_000_000n)
    const nsec = Number(ns % 1_000_000_000n)
    fs.utimesSync(abs, sec + nsec / 1e9, sec + nsec / 1e9)
  }
}

function entryLeavingComplaints (absoluteTarget: string) {
  const rel = path.relative(complaintsDir, absoluteTarget).split(path.sep).join('/')
  assert.ok(rel.startsWith('..'), 'entry does not leave uploads/complaints: ' + rel)
  const resolved = path.resolve('uploads/complaints/' + rel)
  assert.equal(resolved, absoluteTarget)
  assert.ok(resolved.includes(path.resolve('.')))
  return rel
}

function u16 (value: number) {
  const buf = Buffer.alloc(2)
  buf.writeUInt16LE(value)
  return buf
}

function u32 (value: number) {
  const buf = Buffer.alloc(4)
  buf.writeUInt32LE(value >>> 0)
  return buf
}

function storedZip (entries: Array<{ name: string, data: Buffer }>) {
  const locals: Buffer[] = []
  const centrals: Buffer[] = []
  let offset = 0
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8')
    const crc = crc32(entry.data) >>> 0
    const local = Buffer.concat([
      u32(0x04034b50),
      u16(20),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(crc),
      u32(entry.data.length),
      u32(entry.data.length),
      u16(name.length),
      u16(0),
      name,
      entry.data
    ])
    locals.push(local)
    centrals.push(Buffer.concat([
      u32(0x02014b50),
      u16(20),
      u16(20),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(crc),
      u32(entry.data.length),
      u32(entry.data.length),
      u16(name.length),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(0),
      u32(offset),
      name
    ]))
    offset += local.length
  }
  const centralDir = Buffer.concat(centrals)
  const eocd = Buffer.concat([
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(entries.length),
    u16(entries.length),
    u32(centralDir.length),
    u32(offset),
    u16(0)
  ])
  return Buffer.concat([...locals, centralDir, eocd])
}

async function postZip (body: Buffer, filename = 'complaint.zip') {
  return await request(app)
    .post('/file-upload')
    .attach('file', body, filename)
}

function untouchedProblems (abs: string, before: Snap) {
  const after = snap(abs)
  const problems: string[] = []
  if (after.existed !== before.existed) {
    problems.push(abs + ' existed=' + String(after.existed))
  }
  if (after.ino !== before.ino) problems.push(abs + ' inode changed')
  if (after.mtimeNs !== before.mtimeNs) problems.push(abs + ' mtime changed')
  if (before.data == null) {
    if (after.data != null) problems.push(abs + ' was created')
  } else if (after.data == null || !after.data.equals(before.data)) {
    problems.push(abs + ' bytes changed')
  }
  return problems
}

function assertUntouched (abs: string, before: Snap) {
  const problems = untouchedProblems(abs, before)
  assert.deepEqual(problems, [], 'fileWriteChallenge enabled=' + String(utils.isChallengeEnabled(challenges.fileWriteChallenge)))
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 120000 })

after(() => {
  fs.rmSync(outsideDir, { recursive: true, force: true })
})

void describe('POST /file-upload zip extraction', { concurrency: 1 }, () => {
  void it('does not replace ftp/legal.md from a parent-segment entry', async () => {
    const target = path.resolve('ftp/legal.md')
    const source = path.resolve('data/static/legal.md')
    const before = snap(target)
    if (!before.existed) {
      fs.copyFileSync(source, target)
    }
    const placed = snap(target)
    try {
      const zip = fs.readFileSync(path.resolve('test/files/arbitraryFileWrite.zip'))
      await postZip(zip, 'arbitraryFileWrite.zip')
      assertUntouched(target, placed)
      const served = await request(app).get('/ftp/legal.md')
      assert.equal(served.status, 200)
      assert.equal(served.text, placed.data?.toString('utf8'))
    } finally {
      restore(target, before)
    }
  })

  void it('does not replace the promotion subtitles from a parent-segment entry', async () => {
    const target = path.resolve('frontend/dist/frontend/assets/public/videos/owasp_promo.vtt')
    const source = path.resolve('data/static/owasp_promo.vtt')
    const before = snap(target)
    fs.mkdirSync(path.dirname(target), { recursive: true })
    if (!before.existed) fs.copyFileSync(source, target)
    const placed = snap(target)
    try {
      const zip = fs.readFileSync(path.resolve('test/files/videoExploit.zip'))
      await postZip(zip, 'videoExploit.zip')
      assertUntouched(target, placed)
      const page = await request(app).get('/promotion')
      assert.equal(page.status, 200)
      assert.ok(page.text.includes(placed.data?.toString('utf8') ?? 'missing-subtitles'))
    } finally {
      restore(target, before)
    }
  })

  void it('does not replace a file in the sqlite directory, a built frontend file, or a path outside the app that still contains the app directory', async () => {
    const dbFile = path.resolve('data/zip-slip-sentinel.sqlite')
    const scriptFile = path.resolve('frontend/dist/frontend/zip-slip-sentinel.js')
    const outsideFile = path.join(outsideDir, 'sentinel.txt')
    const createdFile = path.resolve('ftp/zip-slip-created.md')
    const payload = Buffer.from('zip-slip-sentinel\n')
    let dbBefore: Snap | undefined
    let scriptBefore: Snap | undefined
    let outsideBefore: Snap | undefined
    let createdBefore: Snap | undefined
    try {
      fs.mkdirSync(outsideDir, { recursive: true })
      fs.writeFileSync(dbFile, ORIGINAL)
      fs.mkdirSync(path.dirname(scriptFile), { recursive: true })
      fs.writeFileSync(scriptFile, ORIGINAL)
      fs.writeFileSync(outsideFile, ORIGINAL)
      dbBefore = snap(dbFile)
      scriptBefore = snap(scriptFile)
      outsideBefore = snap(outsideFile)
      createdBefore = snap(createdFile)
      const zip = storedZip([
        { name: 'kept-inside.txt', data: payload },
        { name: entryLeavingComplaints(dbFile), data: payload },
        { name: entryLeavingComplaints(scriptFile), data: payload },
        { name: entryLeavingComplaints(outsideFile), data: payload },
        { name: entryLeavingComplaints(createdFile), data: payload }
      ])
      await postZip(zip)
      const problems = [
        ...untouchedProblems(dbFile, dbBefore),
        ...untouchedProblems(scriptFile, scriptBefore),
        ...untouchedProblems(outsideFile, outsideBefore),
        ...untouchedProblems(createdFile, createdBefore)
      ]
      assert.deepEqual(problems, [], 'fileWriteChallenge enabled=' + String(utils.isChallengeEnabled(challenges.fileWriteChallenge)))
      const served = await request(app).get('/zip-slip-sentinel.js')
      assert.equal(served.status, 200)
      assert.equal(served.text, ORIGINAL)
      assert.ok(!path.resolve(outsideFile).startsWith(path.resolve('.') + path.sep))
    } finally {
      restore(dbFile, { existed: false, data: null, ino: null, mtimeNs: null })
      restore(scriptFile, { existed: false, data: null, ino: null, mtimeNs: null })
      restore(createdFile, createdBefore ?? { existed: false, data: null, ino: null, mtimeNs: null })
      fs.rmSync(path.resolve('uploads/complaints/kept-inside.txt'), { force: true })
    }
  })

  void it('does not write through a symlink inside the complaints directory', async () => {
    const link = path.resolve('uploads/complaints/zip-slip-link')
    const target = path.resolve('ftp/zip-slip-symlink-target.md')
    fs.mkdirSync(complaintsDir, { recursive: true })
    fs.writeFileSync(target, ORIGINAL)
    fs.rmSync(link, { force: true })
    fs.symlinkSync(path.resolve('ftp'), link)
    const before = snap(target)
    const lexical = path.resolve('uploads/complaints/zip-slip-link/zip-slip-symlink-target.md')
    assert.ok(lexical.startsWith(complaintsDir + path.sep))
    assert.ok(!fs.realpathSync(lexical).startsWith(complaintsDir + path.sep))
    const zip = storedZip([
      { name: 'zip-slip-link/zip-slip-symlink-target.md', data: Buffer.from('zip-slip-sentinel\n') }
    ])
    try {
      await postZip(zip)
      assert.ok(fs.lstatSync(link).isSymbolicLink())
      assertUntouched(target, before)
      const served = await request(app).get('/ftp/zip-slip-symlink-target.md')
      assert.equal(served.status, 200)
      assert.equal(served.text, ORIGINAL)
    } finally {
      fs.rmSync(link, { force: true })
      fs.rmSync(target, { force: true })
    }
  })
})
