/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import type { Challenge } from '@juice-shop/data/types'

const preset = process.env.SAFETY_PRESET ?? 'ctf'
const runtime = process.env.PROFILE_EVAL_RUNTIME ?? 'docker'
const placeholderKey = 'placeholder-ctf-key-value'

process.env.NODE_ENV = preset
process.env.CTF_KEY = placeholderKey
if (runtime === 'heroku') {
  process.env.HEROKU = '1'
}

const createdStubs: string[] = []

function ensureStartupStubs () {
  const files = [
    'build/server.js',
    'frontend/dist/frontend/index.html',
    'frontend/dist/frontend/styles.css',
    'frontend/dist/frontend/main.js',
    'frontend/dist/frontend/polyfills.js',
    'frontend/dist/frontend/hacking-instructor-stub.js'
  ]
  for (const relative of files) {
    const absolute = path.resolve(relative)
    if (!fs.existsSync(absolute)) {
      fs.mkdirSync(path.dirname(absolute), { recursive: true })
      fs.writeFileSync(absolute, '')
      createdStubs.push(absolute)
    }
  }
}

if (runtime === 'docker') {
  const originalStatSync = fs.statSync.bind(fs)
  fs.statSync = function (target: fs.PathLike, options?: fs.StatSyncOptions) {
    if (target === '/.dockerenv') {
      return originalStatSync('/etc/hosts')
    }
    if (options === undefined) {
      return originalStatSync(target)
    }
    return originalStatSync(target, options)
  } as typeof fs.statSync
}

let app: Express
let safetyMode: string
let challengeEnablement: typeof import('../../lib/utils').getChallengeEnablementStatus

before(async () => {
  ensureStartupStubs()
  const [{ createApp }, configMod, yamlMod, isDockerMod, isHerokuMod, utilsMod] = await Promise.all([
    import('../../server'),
    import('config'),
    import('js-yaml'),
    import('../../lib/is-docker'),
    import('../../lib/is-heroku'),
    import('../../lib/utils')
  ])
  const config = configMod.default
  const presetFile = yamlMod.default.load(fs.readFileSync(path.resolve('config', `${preset}.yml`), 'utf8')) as { application?: { logo?: string } }
  assert.equal(config.get('application.logo'), presetFile.application?.logo)
  safetyMode = config.get('challenges.safetyMode')
  const started = await createApp({ inMemoryDb: true })
  app = started.app
  assert.equal(isDockerMod.default(), runtime === 'docker')
  assert.equal(isHerokuMod.default(), runtime === 'heroku')
  challengeEnablement = utilsMod.getChallengeEnablementStatus
}, { timeout: 120000 })

after(() => {
  for (const stub of createdStubs) {
    fs.rmSync(stub, { force: true })
  }
})

async function profileForUsername (username: string) {
  assert.ok(username.length < 255)
  const email = `participant-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  const password = 'password1'
  const registered = await request(app)
    .post('/api/Users/')
    .set('content-type', 'application/json')
    .send({ email, password, passwordRepeat: password, securityQuestion: null, securityAnswer: null })
  assert.equal(registered.status, 201)

  const login = await request(app)
    .post('/rest/user/login')
    .set('content-type', 'application/json')
    .send({ email, password })
  assert.equal(login.status, 200)

  const posted = await request(app)
    .post('/profile')
    .set('Cookie', `token=${login.body.authentication.token}`)
    .type('form')
    .send({ username })
    .redirects(0)
  assert.equal(posted.status, 302)
  const setCookie = posted.headers['set-cookie']
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(';')[0] ?? `token=${login.body.authentication.token}`

  return await request(app)
    .get('/profile')
    .set('Cookie', cookie)
}

void describe(`profile eval under ${preset} preset (${runtime})`, () => {
  void it('does not enable environment-disabled challenges', () => {
    const environment = {
      isDocker: () => false,
      isHeroku: () => false,
      isWindows: () => false
    }
    const stillEnabled: string[] = []
    for (const disabledEnv of ['Docker', 'Heroku', 'Windows']) {
      const status = challengeEnablement(
        { disabledEnv } as Challenge,
        safetyMode,
        { ...environment, [`is${disabledEnv}`]: () => true }
      )
      if (status.enabled) stillEnabled.push(disabledEnv)
    }
    assert.deepEqual(stillEnabled, [])
  })

  void it('does not place CTF_KEY into the rendered profile', async () => {
    const res = await profileForUsername('#{global.process.env.CTF_KEY}')

    assert.equal(res.status, 200)
    assert.equal(res.text.includes(placeholderKey), false)
  })

  void it('does not run a required filesystem write from the username', async () => {
    const marker = path.join(os.tmpdir(), `js-eval-${process.pid}-${Date.now()}`)
    fs.rmSync(marker, { force: true })
    const username = `#{global.process.mainModule.require('node:fs').writeFileSync(${JSON.stringify(marker)},'1')}`
    try {
      await profileForUsername(username)
      assert.equal(fs.existsSync(marker), false)
    } finally {
      fs.rmSync(marker, { force: true })
    }
  })

  void it('does not run a child process from the username', async () => {
    const marker = path.join(os.tmpdir(), `js-shell-${process.pid}-${Date.now()}`)
    fs.rmSync(marker, { force: true })
    const username = `#{global.process.mainModule.require('node:child_process').execSync(${JSON.stringify(`touch ${marker}`)})}`
    try {
      await profileForUsername(username)
      assert.equal(fs.existsSync(marker), false)
    } finally {
      fs.rmSync(marker, { force: true })
    }
  })
})
