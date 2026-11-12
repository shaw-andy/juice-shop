/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'

let app: Express

const erasureResultMessage = 'Sorry to see you leave'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('POST /dataerasure layout', () => {
  void it('does not render a file next to the views directory when the local-file-read flag is on', async () => {
    const viewsDir = app.get('views') as string
    const id = crypto.randomBytes(8).toString('hex')
    const layout = `../lfr-next-to-views-${id}.txt`
    const renderedPath = path.join(viewsDir, layout)
    const prefix = `LFRPREFIX${id}`
    const suffix = `LFRSUFFIX${id}`
    const created = [renderedPath]

    try {
      assert.equal(utils.isChallengeEnabled(challenges.lfrChallenge), true)
      writeProbe(renderedPath, prefix + 'Y'.repeat(180) + suffix)

      const res = await postErasure(await registerAndLogin(), { layout })

      assert.equal(res.status, 200)
      assert.ok(!res.text.includes(prefix), `response included the start of ${renderedPath}: ${JSON.stringify(res.text.slice(0, 140))}`)
      assert.ok(!res.text.includes(suffix), `response included the tail of ${renderedPath}: ${JSON.stringify(res.text.slice(0, 220))}`)
      assert.ok(res.text.includes(erasureResultMessage))
    } finally {
      removeProbes(created)
    }
  })

  void it('does not render the views-relative file when the block-list path is a different file', async () => {
    const viewsDir = app.get('views') as string
    const id = crypto.randomBytes(8).toString('hex')
    const layout = `../lfr-mismatch-${id}.txt`
    const renderedPath = path.join(viewsDir, layout)
    const checkedPath = path.resolve(layout)
    const sentinel = `LFRSENTINEL${id}`
    const harmless = `LFRHARMLESS${id}`
    const created = [renderedPath, checkedPath]

    try {
      assert.notEqual(path.resolve(renderedPath), path.resolve(checkedPath))
      assert.equal(checkedPath.toLowerCase().includes('ftp'), false)
      assert.equal(checkedPath.toLowerCase().includes('ctf.key'), false)
      assert.equal(checkedPath.toLowerCase().includes('encryptionkeys'), false)
      writeProbe(renderedPath, sentinel + 'Y'.repeat(40))
      writeProbe(checkedPath, harmless + 'N'.repeat(40))

      const res = await postErasure(await registerAndLogin(), { layout })

      assert.equal(res.status, 200)
      assert.ok(!res.text.includes(sentinel), `response included the file hbs reads (${renderedPath}), not the path the block list resolves (${checkedPath}): ${JSON.stringify(res.text.slice(0, 140))}`)
      assert.ok(!res.text.includes(harmless), `response included the block-list path ${checkedPath}: ${JSON.stringify(res.text.slice(0, 140))}`)
      assert.ok(res.text.includes(erasureResultMessage))
    } finally {
      removeProbes(created)
    }
  })

  void it('does not render a block-listed layout name in full when the local-file-read flag is off', async () => {
    const viewsDir = app.get('views') as string
    const id = crypto.randomBytes(8).toString('hex')
    const layout = `not-ftp-probe-${id}/note.txt`
    const renderedPath = path.join(viewsDir, layout)
    const checkedPath = path.resolve(layout)
    const prefix = `LFRBLOCKPREFIX${id}`
    const suffix = `LFRBLOCKSUFFIX${id}`
    const created = [renderedPath]
    const previousDisabledEnv = challenges.lfrChallenge.disabledEnv
    const herokuWasSet = Object.prototype.hasOwnProperty.call(process.env, 'HEROKU')

    try {
      assert.equal(checkedPath.toLowerCase().includes('ftp'), true)
      writeProbe(renderedPath, prefix + 'Z'.repeat(180) + suffix)
      process.env.HEROKU = '1'
      challenges.lfrChallenge.disabledEnv = 'Heroku'
      assert.equal(utils.isChallengeEnabled(challenges.lfrChallenge), false)

      const res = await postErasure(await registerAndLogin(), { layout })

      assert.equal(res.status, 200)
      assert.ok(!res.text.includes(prefix), `response included the start of ${renderedPath} with the flag off: ${JSON.stringify(res.text.slice(0, 160))}`)
      assert.ok(!res.text.includes(suffix), `response included bytes past the 100-character cutoff from ${renderedPath}: ${JSON.stringify(res.text.slice(-80))}`)
      assert.ok(res.text.includes(erasureResultMessage))
    } finally {
      challenges.lfrChallenge.disabledEnv = previousDisabledEnv
      if (!herokuWasSet) {
        delete process.env.HEROKU
      }
      removeProbes(created)
    }
  })

  void it('does not render a layout submitted as a form field', async () => {
    const viewsDir = app.get('views') as string
    const id = crypto.randomBytes(8).toString('hex')
    const layout = `../lfr-form-${id}.txt`
    const renderedPath = path.join(viewsDir, layout)
    const marker = `LFRFORM${id}`
    const created = [renderedPath]

    try {
      writeProbe(renderedPath, marker + 'Y'.repeat(40))

      const token = await registerAndLogin()
      const res = await request(app)
        .post('/dataerasure/')
        .set({ Cookie: 'token=' + token })
        .type('form')
        .send({ layout, email: 'erasure-form@example.test', securityAnswer: 'placeholder-answer' })

      assert.equal(res.status, 200)
      assert.ok(!res.text.includes(marker), `form layout was rendered from ${renderedPath}: ${JSON.stringify(res.text.slice(0, 140))}`)
      assert.ok(res.text.includes(erasureResultMessage))
    } finally {
      removeProbes(created)
    }
  })

  void it('does not render a layout for an anonymous request', async () => {
    const viewsDir = app.get('views') as string
    const id = crypto.randomBytes(8).toString('hex')
    const layout = `../lfr-anon-${id}.txt`
    const renderedPath = path.join(viewsDir, layout)
    const marker = `LFRANON${id}`
    const created = [renderedPath]

    try {
      writeProbe(renderedPath, marker + 'Y'.repeat(40))

      const res = await request(app)
        .post('/dataerasure/')
        .set({ 'content-type': 'application/json' })
        .send({ layout })

      assert.ok(!res.text.includes(marker))
    } finally {
      removeProbes(created)
    }
  })
})

async function registerAndLogin (): Promise<string> {
  const id = crypto.randomBytes(8).toString('hex')
  const email = `lfr-${id}@example.test`
  const password = 'placeholder-password'
  await register(app, { email, password })
  const authentication = await login(app, { email, password })
  return authentication.token
}

async function postErasure (token: string, body: Record<string, string>) {
  return await request(app)
    .post('/dataerasure/')
    .set({ Cookie: 'token=' + token, 'content-type': 'application/json' })
    .send(body)
}

function writeProbe (filePath: string, contents: string) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, contents)
}

function removeProbes (filePaths: string[]) {
  for (const filePath of filePaths) {
    fs.rmSync(filePath, { force: true })
    const parent = path.dirname(filePath)
    if (path.basename(parent).startsWith('not-ftp-probe-')) {
      fs.rmSync(parent, { recursive: true, force: true })
    }
  }
}
