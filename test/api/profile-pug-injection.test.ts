/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as utils from '../../lib/utils'
import { challenges } from '../../data/datacache'

// Command output that does not appear in the username text. The username only
// contains the fromCharCode call that produces this string when it is executed.
const COMMAND_OUTPUT = 'PGM9F3'
const PLACEHOLDER_PASSWORD = 'placeholder-password'

const probeFiles: string[] = []
let app: Express
let childIndent = ''

function profileChildIndent (): string {
  const template = fs.readFileSync('views/userProfile.pug', 'utf8')
  const profileLine = template.split('\n').find(line => line.includes('_username_'))
  if (profileLine == null) {
    throw new Error('views/userProfile.pug has no _username_ placeholder')
  }
  return ' '.repeat(profileLine.search(/\S/) + 2)
}

function probeFileFor (name: string): string {
  const file = path.join(os.tmpdir(), `juice-profile-pug-${name}.txt`)
  probeFiles.push(file)
  fs.rmSync(file, { force: true })
  return file
}

function usernameWithPugStatements (firstLine: string, probeFile: string): string {
  const command = JSON.stringify('node -e "process.stdout.write(String.fromCharCode(80,71,77,57,70,51))"')
  const file = JSON.stringify(probeFile)
  const statements = [
    '- var captured = (process.mainModule && process.mainModule.require ? process.mainModule.require(\'node:child_process\') : process.getBuiltinModule(\'node:child_process\')).execSync(' + command + ').toString(); process.getBuiltinModule(\'node:fs\').writeFileSync(' + file + ', captured)',
    '= captured'
  ]
  return [firstLine, ...statements.map(statement => childIndent + statement)].join('\n')
}

function assertPayloadDidNotRun (probeFile: string, body: string) {
  const wroteFile = fs.existsSync(probeFile)
  const fileContents = wroteFile ? fs.readFileSync(probeFile, 'utf8') : ''
  fs.rmSync(probeFile, { force: true })
  assert.deepEqual(
    { wroteFile, fileContents, returnedOutput: body.includes(COMMAND_OUTPUT) },
    { wroteFile: false, fileContents: '', returnedOutput: false }
  )
}

async function postUsername (cookie: string, username: string) {
  return await request(app)
    .post('/profile')
    .set('Cookie', cookie)
    .type('form')
    .send({ username })
    .redirects(0)
}

async function getProfile (cookie: string) {
  return await request(app)
    .get('/profile')
    .set('Cookie', cookie)
}

before(async () => {
  childIndent = profileChildIndent()
  const result = await createTestApp()
  app = result.app
  // The profile splice runs only while these challenges are enabled. On a
  // non-Docker, non-Heroku install that is the default. Clear any environment
  // disablement so this spec exercises that path wherever it is run.
  challenges.usernameXssChallenge.disabledEnv = null
  challenges.persistedXssUserChallenge.disabledEnv = null
  assert.equal(utils.isChallengeEnabled(challenges.usernameXssChallenge), true)
  assert.equal(utils.isChallengeEnabled(challenges.persistedXssUserChallenge), true)
}, { timeout: 120000 })

after(() => {
  for (const file of probeFiles) {
    fs.rmSync(file, { force: true })
  }
})

void describe('profile username is not compiled as Pug source', () => {
  void it('does not run a Pug statement stored by POST /profile', async () => {
    const email = 'pug-profile-plain@juice-sh.op'
    const probeFile = probeFileFor('plain')
    const username = usernameWithPugStatements('safe', probeFile)
    await register(app, { email, password: PLACEHOLDER_PASSWORD })
    const { token } = await login(app, { email, password: PLACEHOLDER_PASSWORD })
    const cookie = `token=${token}`

    await postUsername(cookie, username)
    const res = await getProfile(cookie)

    assertPayloadDidNotRun(probeFile, res.text)
  })

  void it('does not run a Pug statement when the hash-brace expression throws and the original username is inserted', async () => {
    const email = 'pug-profile-throw@juice-sh.op'
    const probeFile = probeFileFor('throw')
    const username = usernameWithPugStatements('#{noSuchSymbol9f3c}', probeFile)
    await register(app, { email, password: PLACEHOLDER_PASSWORD })
    const { token } = await login(app, { email, password: PLACEHOLDER_PASSWORD })
    const cookie = `token=${token}`

    await postUsername(cookie, username)
    const res = await getProfile(cookie)

    assertPayloadDidNotRun(probeFile, res.text)
  })

  void it('does not run a Pug statement produced by evaluating a hash-brace expression', async () => {
    const email = 'pug-profile-eval@juice-sh.op'
    const probeFile = probeFileFor('eval')
    const executed = usernameWithPugStatements('safe', probeFile)
    const username = '#{' + JSON.stringify(executed) + '}'
    await register(app, { email, password: PLACEHOLDER_PASSWORD })
    const { token } = await login(app, { email, password: PLACEHOLDER_PASSWORD })
    const cookie = `token=${token}`

    await postUsername(cookie, username)
    const res = await getProfile(cookie)

    assertPayloadDidNotRun(probeFile, res.text)
  })

  void it('does not run a Pug statement stored as the username during registration', async () => {
    const email = 'pug-profile-register@juice-sh.op'
    const probeFile = probeFileFor('register')
    const username = usernameWithPugStatements('safe', probeFile)
    const created = await request(app)
      .post('/api/Users/')
      .set('content-type', 'application/json')
      .send({
        email,
        password: PLACEHOLDER_PASSWORD,
        passwordRepeat: PLACEHOLDER_PASSWORD,
        username,
        securityQuestion: null,
        securityAnswer: null
      })
    if (created.status !== 201 && created.status !== 200) {
      throw new Error(`Failed to register '${email}': ${created.status}`)
    }
    const { token } = await login(app, { email, password: PLACEHOLDER_PASSWORD })

    const res = await getProfile(`token=${token}`)

    assertPayloadDidNotRun(probeFile, res.text)
  })
})
