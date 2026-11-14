/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, mock } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import config from 'config'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import * as antiCheat from '../../lib/antiCheat'
import * as security from '../../lib/insecurity'
import logger from '../../lib/logger'
import { type ChallengeKey } from '../../models/challenge'

type Client = ReturnType<typeof request.agent>

interface Probe {
  method: 'GET' | 'POST'
  path: string
  status?: number | number[]
  body?: Record<string, string>
  authorize?: boolean
}

const ROT13_EASTER_EGG = '/gur/qrif/ner/fb/shaal/gurl/uvq/na/rnfgre/rtt/jvguva/gur/rnfgre/rtt'
const REAL_EASTER_EGG = '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'
const CAT_PHOTO = '/assets/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg'
const CAT_FRAGMENT = '/assets/public/images/uploads/%F0%9F%98%BC-'
const RCE_LOOP = '(function dos() { while(true); })()'
const RCE_OCCUPY = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'

let app: Express
let webhook: http.Server
const delivered = new Map<string, number[]>()
const waiting = new Map<string, (score: number) => void>()
const loggedLines: string[] = []
const originalInfo = logger.info.bind(logger)

before(async () => {
  logger.info = (message: unknown) => {
    loggedLines.push(String(message))
    return originalInfo(message)
  }

  webhook = http.createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
    req.on('end', () => {
      res.writeHead(204)
      res.end()
      let challengeKey: string | undefined
      let cheatScore: number | undefined
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
          solution?: { challenge?: unknown, cheatScore?: unknown }
        }
        if (typeof body.solution?.challenge === 'string') challengeKey = body.solution.challenge
        if (typeof body.solution?.cheatScore === 'number') cheatScore = body.solution.cheatScore
      } catch {
        return
      }
      if (challengeKey === undefined || cheatScore === undefined) return
      const queued = delivered.get(challengeKey) ?? []
      queued.push(cheatScore)
      delivered.set(challengeKey, queued)
      const waiter = waiting.get(challengeKey)
      if (waiter !== undefined) {
        waiting.delete(challengeKey)
        waiter(cheatScore)
      }
    })
  })
  await new Promise<void>((resolve) => { webhook.listen(0, '127.0.0.1', resolve) })
  const address = webhook.address()
  if (address === null || typeof address === 'string') throw new Error('webhook failed to listen')
  process.env.SOLUTIONS_WEBHOOK = `http://127.0.0.1:${address.port}/solutions`

  const started = await createTestApp()
  app = started.app
}, { timeout: 60000 })

after(async () => {
  logger.info = originalInfo
  delete process.env.SOLUTIONS_WEBHOOK
  mock.timers.reset()
  await new Promise<void>((resolve, reject) => {
    webhook.close((error) => { error ? reject(error) : resolve() })
  })
})

void describe('expected URL interactions are per client', () => {
  void it('does not let another visitor satisfy directoryListingChallenge by opening /ftp', async () => {
    await assertIsolated({
      key: 'directoryListingChallenge',
      probes: [{ method: 'GET', path: '/ftp', status: 200 }],
      solve: (client) => client.get('/ftp/acquisitions.md'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy forgottenDevBackupChallenge by requesting the forbidden backup', async () => {
    await assertIsolated({
      key: 'forgottenDevBackupChallenge',
      probes: [{ method: 'GET', path: '/ftp/package.json.bak', status: 403 }],
      solve: (client) => client.get('/ftp/package.json.bak%2500.md'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy forgottenDevBackupChallenge by opening the file listing', async () => {
    await assertIsolated({
      key: 'forgottenDevBackupChallenge',
      probes: [{ method: 'GET', path: '/ftp', status: 200 }],
      solve: (client) => client.get('/ftp/package.json.bak%2500.md'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy forgottenBackupChallenge by requesting the forbidden backup', async () => {
    await assertIsolated({
      key: 'forgottenBackupChallenge',
      probes: [{ method: 'GET', path: '/ftp/coupons_2013.md.bak', status: 403 }],
      solve: (client) => client.get('/ftp/coupons_2013.md.bak%2500.md'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy easterEggLevelOneChallenge by requesting the forbidden egg file', async () => {
    await assertIsolated({
      key: 'easterEggLevelOneChallenge',
      probes: [{ method: 'GET', path: '/ftp/eastere.gg', status: 403 }],
      solve: (client) => client.get('/ftp/eastere.gg%2500.md'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy misplacedSignatureFileChallenge by requesting the forbidden signature', async () => {
    await assertIsolated({
      key: 'misplacedSignatureFileChallenge',
      probes: [{ method: 'GET', path: '/ftp/suspicious_errors.yml', status: 403 }],
      solve: (client) => client.get('/ftp/suspicious_errors.yml%2500.md'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy easterEggLevelTwoChallenge by requesting its expected paths', async () => {
    await assertIsolated({
      key: 'easterEggLevelTwoChallenge',
      probes: [
        { method: 'GET', path: '/ftp', status: 200 },
        { method: 'GET', path: ROT13_EASTER_EGG }
      ],
      solve: (client) => client.get(REAL_EASTER_EGG)
    })
  })

  void it('does not let another visitor satisfy misplacedIacFiles by opening /infrastructure', async () => {
    await assertIsolated({
      key: 'misplacedIacFiles',
      probes: [{ method: 'GET', path: '/infrastructure', status: 200 }],
      solve: (client) => client.get('/infrastructure/terraform/main.tf'),
      solveStatus: 200
    })
  })

  void it('does not let another visitor satisfy missingEncodingChallenge by requesting the expected upload prefix', async () => {
    await assertIsolated({
      key: 'missingEncodingChallenge',
      probes: [{ method: 'GET', path: CAT_FRAGMENT }],
      solve: (client) => client.get(CAT_PHOTO)
    })
  })

  void it('does not let another visitor satisfy rceChallenge by opening /api-docs', async () => {
    await assertIsolated({
      key: 'rceChallenge',
      probes: [{ method: 'GET', path: '/api-docs', status: [200, 301] }],
      solve: (client) => client.post('/b2b/v2/orders').set(bearer()).send({ orderLinesData: RCE_LOOP }),
      solveStatus: 500
    })
  })

  void it('does not let another visitor satisfy rceOccupyChallenge by opening /api-docs', async () => {
    await assertIsolated({
      key: 'rceOccupyChallenge',
      probes: [{ method: 'GET', path: '/api-docs', status: [200, 301] }],
      solve: (client) => client.post('/b2b/v2/orders').set(bearer()).send({ orderLinesData: RCE_OCCUPY }),
      solveStatus: 503
    })
  })

  void it('counts a forbidden backup request and the file listing as separate steps for the client who made them', async () => {
    const solve = (client: Client) => client.get('/ftp/package.json.bak%2500.md')
    const baseline = await measure('forgottenDevBackupChallenge', [], solve, 'none', 200)
    const ownListing = await measure('forgottenDevBackupChallenge', [{ method: 'GET', path: '/ftp', status: 200 }], solve, 'same', 200)
    const ownForbidden = await measure('forgottenDevBackupChallenge', [{ method: 'GET', path: '/ftp/package.json.bak', status: 403 }], solve, 'same', 200)
    const ownBoth = await measure('forgottenDevBackupChallenge', [
      { method: 'GET', path: '/ftp', status: 200 },
      { method: 'GET', path: '/ftp/package.json.bak', status: 403 }
    ], solve, 'same', 200)
    const strangerForbidden = await measure('forgottenDevBackupChallenge', [{ method: 'GET', path: '/ftp/package.json.bak', status: 403 }], solve, 'other', 200)

    assert.ok(ownListing < baseline, `own listing score ${ownListing} should be below untouched score ${baseline}`)
    assert.equal(ownForbidden, ownListing, `one satisfied step should score the same whichever expected URL the solver requested (listing ${ownListing}, forbidden file ${ownForbidden})`)
    assert.ok(ownBoth < ownForbidden, `both of the solver's own steps should score below one step (both ${ownBoth}, one ${ownForbidden})`)
    assert.equal(strangerForbidden, baseline, `a different client's 403 should leave the score at the untouched value ${baseline}, got ${strangerForbidden}`)
  })
})

function bearer () {
  return { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
}

async function assertIsolated (options: {
  key: ChallengeKey
  probes: Probe[]
  solve: (client: Client) => request.Test
  solveStatus?: number
}) {
  const baseline = await measure(options.key, options.probes, options.solve, 'none', options.solveStatus)
  const other = await measure(options.key, options.probes, options.solve, 'other', options.solveStatus)
  const same = await measure(options.key, options.probes, options.solve, 'same', options.solveStatus)

  assert.ok(same < baseline, `${options.key}: the solving client's own requests should lower the webhook cheat score (own ${same}, untouched ${baseline})`)
  assert.ok(baseline - same > 0.05, `${options.key}: own-request reduction was only ${baseline - same}`)
  assert.equal(other, baseline, `${options.key}: another client's requests should not change the webhook cheat score (other ${other}, untouched ${baseline})`)
}

async function measure (
  key: ChallengeKey,
  probes: Probe[],
  solve: (client: Client) => request.Test,
  who: 'none' | 'other' | 'same',
  solveStatus: number | undefined
) {
  challenges.errorHandlingChallenge.solved = true
  challenges.nullByteChallenge.solved = true
  const challenge = challenges[key]
  challenge.solved = false
  await challenge.save()
  delivered.set(key, [])
  loggedLines.length = 0

  mock.timers.enable({ apis: ['Date'], now: Date.now() })
  try {
    antiCheat.reset()
    mock.timers.tick(halfExpectedMilliseconds(challenge))

    const solver = request.agent(app)
    const stranger = request.agent(app)
    if (who !== 'none') {
      const prober = who === 'same' ? solver : stranger
      for (const probe of probes) {
        await send(prober, probe)
      }
      assert.equal(challenge.solved, false, `${key} must still be unsolved after the expected URL requests`)
    }

    const scorePromise = nextWebhookScore(key)
    const response = await solve(solver)
    if (solveStatus !== undefined) {
      assert.equal(response.status, solveStatus, `${key} solve response`)
    }
    const score = await scorePromise
    const logged = loggedLines.map(stripAnsi).some((line) => line.includes(key) && line.includes(String(score)))
    assert.equal(logged, true, `${key} cheat score ${score} was not logged`)
    return score
  } finally {
    waiting.delete(key)
    mock.timers.reset()
  }
}

async function send (client: Client, probe: Probe) {
  const req = probe.method === 'POST' ? client.post(probe.path) : client.get(probe.path)
  if (probe.authorize === true) req.set(bearer())
  if (probe.body !== undefined) req.send(probe.body)
  const response = await req
  if (probe.status !== undefined) {
    const allowed = Array.isArray(probe.status) ? probe.status : [probe.status]
    assert.ok(allowed.includes(response.status), `${probe.path} status ${response.status} not in ${allowed.join(', ')}`)
  }
  return response
}

function nextWebhookScore (key: string) {
  const queued = delivered.get(key) ?? []
  const already = queued.shift()
  if (already !== undefined) return Promise.resolve(already)
  return new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => { reject(new Error(`no solutions webhook score for ${key}`)) }, 15000)
    waiting.set(key, (score) => {
      clearTimeout(timer)
      resolve(score)
    })
  })
}

function halfExpectedMilliseconds (challenge: { difficulty: number, tutorialOrder?: number | null }) {
  let timeFactor = 2
  timeFactor *= (config.get('challenges.showHints') ? 1 : 1.5)
  timeFactor *= (challenge.tutorialOrder && config.get('hackingInstructor.isEnabled') ? 0.5 : 1)
  const minutesExpected = challenge.difficulty * timeFactor
  return minutesExpected * 0.5 * 60 * 1000
}

function stripAnsi (value: string) {
  const escape = String.fromCharCode(27)
  return value.replace(new RegExp(escape + '\\[[0-9;]*m', 'g'), '')
}
