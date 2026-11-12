/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'

const scriptBreakout = '</script><script>window.promotionSubtitleBreakout=1</script>'
const mixedCaseBreakout = '</ScRiPt><script>window.promotionSubtitleBreakout=1</script>'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('promotion subtitle insertion', { concurrency: false }, () => {
  void it('does not insert the subtitle file into the promotion HTML as markup', async () => {
    const original = readSubtitle()
    writeSubtitle(vttCue(scriptBreakout))
    try {
      const res = await request(app).get('/promotion')
      assert.equal(res.status, 200)
      assert.equal(String(res.headers['content-type']).includes('text/html'), true)
      assert.equal(res.text.includes(scriptBreakout), false)
    } finally {
      writeSubtitle(original)
    }
  })

  void it('does not insert a mixed-case script end tag from the subtitle file as markup', async () => {
    const original = readSubtitle()
    writeSubtitle(vttCue(mixedCaseBreakout))
    try {
      const res = await request(app).get('/promotion')
      assert.equal(res.status, 200)
      assert.equal(String(res.headers['content-type']).includes('text/html'), true)
      assert.equal(res.text.includes(mixedCaseBreakout), false)
    } finally {
      writeSubtitle(original)
    }
  })

  void it('does not let a zip entry with parent segments overwrite the promotion subtitle', async () => {
    const file = subtitleFile()
    const original = readSubtitle()
    const payload = Buffer.from(vttCue(scriptBreakout), 'utf8')
    const zip = zipStored([{ name: '../../' + file, data: payload }])
    const writes = watch(file)
    try {
      await uploadZip(app, zip)
      await settle()
      assert.equal(writes.sawWrite(), false)
      assert.equal(fs.readFileSync(file).equals(Buffer.from(original)), true)
    } finally {
      writes.close()
      writeSubtitle(original)
    }
  })

  void it('does not let a zip entry with parent segments create a file outside the complaints directory', async () => {
    const sentinel = path.resolve('ftp/promotion-zip-sentinel.txt')
    if (fs.existsSync(sentinel)) fs.unlinkSync(sentinel)
    const writes = watch(sentinel)
    try {
      const zip = zipStored([{
        name: '../../ftp/promotion-zip-sentinel.txt',
        data: Buffer.from('promotion-zip-sentinel', 'utf8')
      }])
      await uploadZip(app, zip)
      await settle()
      assert.equal(fs.existsSync(sentinel), false)
      assert.equal(writes.sawWrite(), false)
    } finally {
      writes.close()
      if (fs.existsSync(sentinel)) fs.unlinkSync(sentinel)
    }
  })

  void it('does not let a zip entry follow a symlink out of the complaints directory', async () => {
    const outsideDir = path.resolve('ftp/promotion-symlink-outside')
    const link = path.resolve('uploads/complaints/promotion-escape')
    const sentinel = path.join(outsideDir, 'sentinel.txt')
    fs.mkdirSync(outsideDir, { recursive: true })
    fs.mkdirSync(path.dirname(link), { recursive: true })
    if (fs.existsSync(link)) fs.unlinkSync(link)
    fs.symlinkSync(outsideDir, link)
    const writes = watch(sentinel)
    try {
      const zip = zipStored([{
        name: 'promotion-escape/sentinel.txt',
        data: Buffer.from('promotion-symlink-sentinel', 'utf8')
      }])
      await uploadZip(app, zip)
      await settle()
      assert.equal(fs.existsSync(sentinel), false)
      assert.equal(writes.sawWrite(), false)
    } finally {
      writes.close()
      if (fs.existsSync(sentinel)) fs.unlinkSync(sentinel)
      if (fs.existsSync(link)) fs.unlinkSync(link)
      fs.rmSync(outsideDir, { recursive: true, force: true })
    }
  })

  void it('does not serve a script planted in the promotion subtitle by an unauthenticated zip upload', async () => {
    const file = subtitleFile()
    const original = readSubtitle()
    const payload = Buffer.from(vttCue(scriptBreakout), 'utf8')
    const zip = zipStored([{ name: '../../' + file, data: payload }])
    const writes = watch(file)
    try {
      await uploadZip(app, zip)
      const res = await request(app).get('/promotion')
      await settle()
      assert.equal(writes.sawWrite(), false)
      assert.equal(fs.readFileSync(file).equals(Buffer.from(original)), true)
      assert.equal(res.status, 200)
      assert.equal(res.text.includes(scriptBreakout), false)
    } finally {
      writes.close()
      writeSubtitle(original)
    }
  })
})

function subtitleFile (): string {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  return 'frontend/dist/frontend/assets/public/videos/' + subtitles
}

function readSubtitle (): string {
  const file = subtitleFile()
  fs.mkdirSync(path.dirname(file), { recursive: true })
  if (!fs.existsSync(file)) {
    fs.copyFileSync(path.resolve('data/static/owasp_promo.vtt'), file)
  }
  return fs.readFileSync(file, 'utf8')
}

function writeSubtitle (contents: string): void {
  const file = subtitleFile()
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, contents)
}

function vttCue (text: string): string {
  return 'WEBVTT\n\n00:00:00.000 --> 00:00:01.000\n' + text + '\n'
}

async function uploadZip (application: Express, zip: Buffer) {
  return await request(application)
    .post('/file-upload')
    .attach('file', zip, 'complaint.zip')
}

function watch (file: string): { sawWrite: () => boolean, close: () => void } {
  const dir = path.dirname(path.resolve(file))
  const base = path.basename(file)
  fs.mkdirSync(dir, { recursive: true })
  let wrote = false
  const watcher = fs.watch(dir, (_event, filename) => {
    if (filename === base) wrote = true
  })
  return {
    sawWrite: () => wrote,
    close: () => { watcher.close() }
  }
}

async function settle (): Promise<void> {
  await new Promise((resolve) => { setImmediate(resolve) })
}

function zipStored (entries: Array<{ name: string, data: Buffer }>): Buffer {
  const locals: Buffer[] = []
  const centrals: Buffer[] = []
  let offset = 0
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8')
    const crc = zlib.crc32(entry.data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0x0800, 6)
    local.writeUInt16LE(0, 8)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(entry.data.length, 18)
    local.writeUInt32LE(entry.data.length, 22)
    local.writeUInt16LE(name.length, 26)
    const localRecord = Buffer.concat([local, name, entry.data])
    locals.push(localRecord)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(0x0800, 8)
    central.writeUInt16LE(0, 10)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(entry.data.length, 20)
    central.writeUInt32LE(entry.data.length, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt32LE(offset, 42)
    centrals.push(Buffer.concat([central, name]))
    offset += localRecord.length
  }
  const centralDirectory = Buffer.concat(centrals)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(centralDirectory.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, centralDirectory, end])
}
