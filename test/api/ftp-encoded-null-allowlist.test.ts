/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import express from 'express'
import request from 'supertest'
import serveIndex from 'serve-index'
import errorhandler from 'errorhandler'
import type { Express } from 'express'
import type { IncomingMessage } from 'node:http'
import { servePublicFiles } from '../../routes/fileServer'
import { serveQuarantineFiles } from '../../routes/quarantineServer'
import * as antiCheat from '../../lib/antiCheat'
import { challenges } from '../../data/datacache'
import type { ChallengeKey } from '../../models/challenge'

let app: Express

const allowlistedNames = ['acquisitions.md', 'incident-support.kdbx']

const protectedFiles: Array<{ name: string, solvedBy: ChallengeKey[] }> = [
  { name: 'coupons_2013.md.bak', solvedBy: ['forgottenBackupChallenge', 'nullByteChallenge'] },
  { name: 'package.json.bak', solvedBy: ['forgottenDevBackupChallenge', 'nullByteChallenge'] },
  { name: 'package-lock.json.bak', solvedBy: [] },
  { name: 'eastere.gg', solvedBy: ['easterEggLevelOneChallenge', 'nullByteChallenge'] },
  { name: 'suspicious_errors.yml', solvedBy: ['misplacedSignatureFileChallenge', 'nullByteChallenge'] },
  { name: 'encrypt.pyc', solvedBy: ['nullByteChallenge'] }
]

before(() => {
  const tracked = new Set<ChallengeKey>(protectedFiles.flatMap((file) => file.solvedBy))
  for (const key of tracked) {
    challenges[key] = {
      solved: false,
      key,
      save: () => new Promise(() => {})
    } as unknown as typeof challenges[typeof key]
  }

  app = express()
  app.use(antiCheat.checkForPreSolveInteractions())
  app.use('/ftp', serveIndex('ftp', { icons: true }))
  app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  app.use('/ftp/quarantine/:file', serveQuarantineFiles())
  app.use(errorhandler())
})

function digest (bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function readFtpFile (name: string): Buffer {
  return fs.readFileSync(path.resolve('ftp', name))
}

function listFtp (): string[] {
  return fs.readdirSync('ftp', { recursive: true }).map((entry) => entry.toString()).sort()
}

function responseBody (urlPath: string) {
  return request(app)
    .get(urlPath)
    .buffer(true)
    .parse((res: IncomingMessage, callback: (err: Error | null, body: Buffer) => void) => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      res.on('end', () => { callback(null, Buffer.concat(chunks)) })
    })
}

function clearSolved (keys: ChallengeKey[]) {
  for (const key of keys) {
    const challenge = challenges[key]
    assert.ok(challenge, key)
    challenge.solved = false
  }
}

void describe('public ftp allow-list', { concurrency: 1 }, () => {
  for (const name of allowlistedNames) {
    void it(`still serves allow-listed /ftp/${name}`, async () => {
      const expected = readFtpFile(name)
      const res = await responseBody(`/ftp/${name}`)
      const body = Buffer.isBuffer(res.body) ? res.body : Buffer.from('')
      assert.equal(res.status, 200)
      assert.equal(digest(body), digest(expected))
      assert.equal(body.length, expected.length)
    })
  }

  for (const { name, solvedBy } of protectedFiles) {
    void it(`rejects /ftp/${name} without serving it`, async () => {
      clearSolved(solvedBy)
      const before = listFtp()
      const expected = readFtpFile(name)
      const res = await responseBody(`/ftp/${encodeURIComponent(name)}`)
      const body = Buffer.isBuffer(res.body) ? res.body : Buffer.from('')
      const solved = solvedBy.filter((key) => challenges[key].solved)
      assert.equal(res.status, 403)
      assert.notEqual(digest(body), digest(expected))
      assert.deepEqual(solved, [])
      assert.deepEqual(listFtp(), before)
    })
  }
})

void describe('encoded null byte in a public ftp name', { concurrency: 1 }, () => {
  for (const suffix of ['md', 'pdf']) {
    for (const { name, solvedBy } of protectedFiles) {
      void it(`rejects /ftp/${name} when ${suffix} is only a suffix after %2500`, async () => {
        clearSolved(solvedBy)
        const before = listFtp()
        const expected = readFtpFile(name)
        const res = await responseBody(`/ftp/${name}%2500.${suffix}`)
        const body = Buffer.isBuffer(res.body) ? res.body : Buffer.from('')
        const solved = solvedBy.filter((key) => challenges[key].solved)
        const problems: string[] = []
        if (res.status !== 403) problems.push(`status ${res.status} is not a rejection`)
        if (digest(body) === digest(expected)) problems.push(`response body is ${name} (${body.length} bytes)`)
        if (solved.length > 0) problems.push(`marked solved before refusal: ${solved.join(', ')}`)
        if (listFtp().join('\n') !== before.join('\n')) problems.push('ftp directory changed before refusal')
        assert.deepEqual(problems, [])
      })
    }
  }

  void it('does not let an encoded null select a quarantine file', async () => {
    const name = 'juicy_malware_windows_64.exe.url'
    const expected = readFtpFile(path.join('quarantine', name))
    const before = listFtp()
    const res = await responseBody(`/ftp/quarantine/${name}%2500.url`)
    const body = Buffer.isBuffer(res.body) ? res.body : Buffer.from('')
    assert.notEqual(res.status, 200)
    assert.notEqual(digest(body), digest(expected))
    assert.deepEqual(listFtp(), before)
  })
})
