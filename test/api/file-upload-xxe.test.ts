/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'

const CANARY = 'XXE_CANARY_NOT_A_SECRET'

let app: Express
let secretPath = ''
let fileUrl = ''
let dtdUrl = ''

function generalEntityXml (systemId: string, body: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${systemId}">]><foo>${body}</foo>`
}

function assertBodyOmitsCanary (res: Response) {
  assert.equal(res.text.includes(CANARY), false)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  const challenge = challenges.deprecatedInterfaceChallenge
  challenge.disabledEnv = null
  assert.equal(utils.isChallengeEnabled(challenge), true)

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-xxe-upload-'))
  secretPath = path.join(dir, 'local.txt')
  fs.writeFileSync(secretPath, CANARY + 'x'.repeat(2000))
  fileUrl = pathToFileURL(secretPath).href
  const dtdPath = path.join(dir, 'ext.dtd')
  fs.writeFileSync(dtdPath, `<!ENTITY xxe SYSTEM "${fileUrl}">`)
  dtdUrl = pathToFileURL(dtdPath).href
}, { timeout: 60000 })

void describe('POST /file-upload external entities', () => {
  for (const accept of ['application/json', 'text/html', 'text/plain']) {
    void it(`does not return a local file to an anonymous client that accepts ${accept}`, async () => {
      const res = await request(app)
        .post('/file-upload')
        .set('Accept', accept)
        .attach('file', Buffer.from(generalEntityXml(fileUrl, '&xxe;')), { filename: 'complaint.xml', contentType: 'application/xml' })
      assertBodyOmitsCanary(res)
    })
  }

  void it('does not return a local file when the upload name ends in .XML', async () => {
    const res = await request(app)
      .post('/file-upload')
      .set('Accept', 'application/json')
      .attach('file', Buffer.from(generalEntityXml(fileUrl, '&xxe;')), { filename: 'complaint.XML', contentType: 'application/xml' })
    assertBodyOmitsCanary(res)
  })

  void it('does not return a local file referenced by an absolute filesystem path', async () => {
    const res = await request(app)
      .post('/file-upload')
      .set('Accept', 'application/json')
      .attach('file', Buffer.from(generalEntityXml(secretPath, '&xxe;')), { filename: 'complaint.xml', contentType: 'application/xml' })
    assertBodyOmitsCanary(res)
  })

  void it('does not return a local file pulled in by an external DTD', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo SYSTEM "${dtdUrl}"><foo>&xxe;</foo>`
    const res = await request(app)
      .post('/file-upload')
      .set('Accept', 'application/json')
      .attach('file', Buffer.from(xml), { filename: 'complaint.xml', contentType: 'application/xml' })
    assertBodyOmitsCanary(res)
  })

  void it('does not return the start of a local file when the parsed document is longer than the error truncation', async () => {
    const res = await request(app)
      .post('/file-upload')
      .set('Accept', 'text/plain')
      .attach('file', Buffer.from(generalEntityXml(fileUrl, '&xxe;')), { filename: 'complaint.xml', contentType: 'application/xml' })
    assertBodyOmitsCanary(res)
  })
})
