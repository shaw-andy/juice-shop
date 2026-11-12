/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { crc32 } from 'node:zlib'
import fs from 'node:fs'
import { mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { challenges } from '../../data/datacache'
import isDocker from '../../lib/is-docker'
import isHeroku from '../../lib/is-heroku'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'

const codeFixesDir = path.resolve('data/static/codefixes')
const knownKey = 'loginAdminChallenge'

let app: Express
let scratch = ''

before(async () => {
  const result = await createTestApp()
  app = result.app
  scratch = await mkdtemp(path.join(os.tmpdir(), 'juice-shop-yaml-load-'))
}, { timeout: 120000 })

after(async () => {
  if (scratch !== '') {
    await rm(scratch, { recursive: true, force: true })
  }
})

void describe('coding challenge verdict YAML loading', () => {
  void it('POST /snippets/verdict does not run a JavaScript type from an unauthenticated zip-planted known challenge file', async () => {
    const marker = path.join(scratch, 'verdict-zip')
    const target = infoPath(knownKey)
    const original = await readFile(target)
    try {
      const upload = await postZip([
        { name: zipEntryName(`${knownKey}.info.yml`), data: Buffer.from(verdictDocument(marker), 'utf8') }
      ])
      assert.equal(upload.status, 204)
      assert.equal(utils.isChallengeEnabled(challenges.fileWriteChallenge), true, `file write challenge disabled (docker=${isDocker()} heroku=${isHeroku()})`)
      assert.equal(fs.readFileSync(target, 'utf8').includes('plant-sentinel'), true)

      const res = await request(app)
        .post('/snippets/verdict')
        .send({ key: knownKey, selectedLines: [] })

      assert.equal(fs.existsSync(marker), false, `JavaScript YAML type ran on /snippets/verdict (status ${res.status})`)
    } finally {
      await restoreFile(target, original)
      await rm(marker, { force: true })
    }
  })

  void it('POST /snippets/verdict does not run a JavaScript type for a key that is not a coding challenge', async () => {
    const marker = path.join(scratch, 'verdict-unknown')
    const key = 'zzYamlLoadUnknown'
    const target = infoPath(key)
    try {
      const upload = await postZip([
        { name: zipEntryName(`${key}.info.yml`), data: Buffer.from(verdictDocument(marker), 'utf8') }
      ])
      assert.equal(upload.status, 204)
      assert.equal(fs.readFileSync(target, 'utf8').includes('plant-sentinel'), true)

      const res = await request(app)
        .post('/snippets/verdict')
        .send({ key, selectedLines: [] })

      assert.equal(res.status, 404)
      assert.equal(fs.existsSync(marker), false, 'JavaScript YAML type ran for an unknown verdict key')
    } finally {
      await rm(target, { force: true })
      await rm(marker, { force: true })
    }
  })

  void it('POST /snippets/fixes does not run a JavaScript type from an unauthenticated zip-planted fix file', async () => {
    const marker = path.join(scratch, 'fixes-zip')
    const key = 'zzYamlLoadProbe'
    const target = infoPath(key)
    const sibling = path.join(codeFixesDir, `${key}_1.txt`)
    try {
      const upload = await postZip([
        { name: zipEntryName(`${key}.info.yml`), data: Buffer.from(fixesDocument(marker), 'utf8') },
        { name: zipEntryName(`${key}_1.txt`), data: Buffer.from('planted fix option', 'utf8') }
      ])
      assert.equal(upload.status, 204)
      assert.equal(fs.readFileSync(target, 'utf8').includes('plant-sentinel'), true)
      assert.equal(fs.existsSync(sibling), true)

      const res = await request(app)
        .post('/snippets/fixes')
        .send({ key, selectedFix: 0 })

      assert.equal(fs.existsSync(marker), false, `JavaScript YAML type ran on /snippets/fixes (status ${res.status})`)
    } finally {
      await rm(target, { force: true })
      await rm(sibling, { force: true })
      await rm(marker, { force: true })
    }
  })

  void it('POST /snippets/fixes does not run a JavaScript type when the planted file replaces a known challenge', async () => {
    const marker = path.join(scratch, 'fixes-known')
    const target = infoPath(knownKey)
    const original = await readFile(target)
    try {
      const upload = await postZip([
        { name: zipEntryName(`${knownKey}.info.yml`), data: Buffer.from(fixesDocument(marker), 'utf8') }
      ])
      assert.equal(upload.status, 204)
      assert.equal(fs.readFileSync(target, 'utf8').includes('plant-sentinel'), true)

      const res = await request(app)
        .post('/snippets/fixes')
        .send({ key: knownKey, selectedFix: 0 })

      assert.equal(fs.existsSync(marker), false, `JavaScript YAML type ran on /snippets/fixes for a known key (status ${res.status})`)
    } finally {
      await restoreFile(target, original)
      await rm(marker, { force: true })
    }
  })

  void it('POST /snippets/fixes does not run a JavaScript type when that key has no fix file', async () => {
    const marker = path.join(scratch, 'fixes-nofile')
    const key = 'zzYamlLoadNoSibling'
    const target = infoPath(key)
    try {
      const upload = await postZip([
        { name: zipEntryName(`${key}.info.yml`), data: Buffer.from(fixesDocument(marker), 'utf8') }
      ])
      assert.equal(upload.status, 204)
      assert.equal(fs.readFileSync(target, 'utf8').includes('plant-sentinel'), true)

      const res = await request(app)
        .post('/snippets/fixes')
        .send({ key, selectedFix: 0 })

      assert.equal(res.status, 404)
      assert.equal(fs.existsSync(marker), false, 'JavaScript YAML type ran for a fixes key with no fix file')
    } finally {
      await rm(target, { force: true })
      await rm(marker, { force: true })
    }
  })

  void it('verdict handlers do not run a JavaScript type when the info file is a symlink to another path', async () => {
    const verdictMarker = path.join(scratch, 'symlink-verdict')
    const fixesMarker = path.join(scratch, 'symlink-fixes')
    const outside = path.join(scratch, 'outside-info.yml')
    const target = infoPath(knownKey)
    const original = await readFile(target)
    await writeFile(outside, verdictAndFixesDocument(verdictMarker, fixesMarker), 'utf8')
    await unlink(target)
    await symlink(outside, target)
    try {
      const verdict = await request(app)
        .post('/snippets/verdict')
        .send({ key: knownKey, selectedLines: [] })
      const fixes = await request(app)
        .post('/snippets/fixes')
        .send({ key: knownKey, selectedFix: 0 })
      const ran = [
        fs.existsSync(verdictMarker) ? `/snippets/verdict (${verdict.status})` : '',
        fs.existsSync(fixesMarker) ? `/snippets/fixes (${fixes.status})` : ''
      ].filter(part => part !== '')

      assert.equal(ran.length, 0, `JavaScript YAML type ran through a symlink on ${ran.join(' and ')}`)
    } finally {
      await restoreFile(target, original)
      await rm(verdictMarker, { force: true })
      await rm(fixesMarker, { force: true })
    }
  })
})

function infoPath (key: string) {
  return path.join(codeFixesDir, `${key}.info.yml`)
}

function zipEntryName (fileName: string) {
  return `../../data/static/codefixes/${fileName}`
}

function verdictDocument (marker: string) {
  return `# plant-sentinel\n${hintsLengthValueOf(marker)}`
}

function fixesDocument (marker: string) {
  return `# plant-sentinel\n${fixesFind(marker)}`
}

function verdictAndFixesDocument (verdictMarker: string, fixesMarker: string) {
  return `${hintsLengthValueOf(verdictMarker)}\n${fixesFind(fixesMarker)}`
}

function hintsLengthValueOf (marker: string) {
  return `hints:\n  length:\n    valueOf: !!js/function ${JSON.stringify(markerWriter(marker))}\n`
}

function fixesFind (marker: string) {
  return `fixes:\n  find: !!js/function ${JSON.stringify(markerWriter(marker))}\n`
}

function markerWriter (marker: string) {
  return `function () { process.getBuiltinModule('fs').writeFileSync(${JSON.stringify(marker)}, '1'); return 0 }`
}

async function postZip (entries: Array<{ name: string, data: Buffer }>) {
  return await request(app)
    .post('/file-upload')
    .attach('file', zipStored(entries), 'complaint.zip')
}

async function restoreFile (target: string, original: Buffer) {
  await rm(target, { force: true })
  await writeFile(target, original)
}

function zipStored (entries: Array<{ name: string, data: Buffer }>) {
  const locals: Buffer[] = []
  const centrals: Buffer[] = []
  let offset = 0
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const crc = crc32(entry.data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
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
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(entry.data.length, 20)
    central.writeUInt32LE(entry.data.length, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt32LE(offset, 42)
    centrals.push(Buffer.concat([central, name]))
    offset += localRecord.length
  }
  const centralDir = Buffer.concat(centrals)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(centralDir.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, centralDir, end])
}
