/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * These tests specify the safe behavior of progress restore. They fail while a
 * client can forge a continue code from parameters in the route source and
 * write the instance-wide challenge table without a login.
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, before, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import Hashids from 'hashids/cjs'
import { createTestApp } from './helpers/setup'
import { challenges, users } from '../../data/datacache'
import { ChallengeModel } from '../../models/challenge'
import * as challengeUtils from '../../lib/challengeUtils'
import * as security from '../../lib/insecurity'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const continueCodeRoutes = [
  'routes/restoreProgress.ts',
  'routes/continueCode.ts'
]

interface ScoreRow {
  id: number
  key: string
  solved: boolean
  codingChallengeStatus: number
}

interface ApplyTarget {
  name: string
  url: (code: string) => string
}

const applyTargets: ApplyTarget[] = [
  {
    name: 'continue code',
    url: (code) => `/rest/continue-code/apply/${code}`
  },
  {
    name: 'find-it continue code',
    url: (code) => `/rest/continue-code-findIt/apply/${code}`
  },
  {
    name: 'fix-it continue code',
    url: (code) => `/rest/continue-code-fixIt/apply/${code}`
  }
]

let app: Express
let baseline: ScoreRow[]

before(async () => {
  const result = await createTestApp()
  app = result.app
  baseline = snapshot()
  assert.ok(baseline.length > 0)
  assert.ok(baseline.every((row) => row.solved === false))
  assert.ok(baseline.every((row) => row.codingChallengeStatus === 0))
}, { timeout: 60000 })

afterEach(async () => {
  await restore(baseline)
})

void describe('continue-code apply does not write the shared scoreboard', () => {
  for (const target of applyTargets) {
    void it(`anonymous ${target.name} apply leaves every challenge unsolved`, async () => {
      await assertForgedCodesDoNotChangeScoreboard(target, {})
    })

    void it(`a logged-in user's ${target.name} apply leaves the shared scoreboard unchanged`, async () => {
      const token = tokenForAdmin()
      await assertForgedCodesDoNotChangeScoreboard(target, { Authorization: 'Bearer ' + token })
    })
  }

  void it('anonymous continue-code apply of the sentinel id does not solve that challenge', async () => {
    const codecs = codecsFromRoutes()
    assert.ok(codecs.length > 0)
    for (const codec of codecs) {
      const code = codec.encode(999)
      assert.match(code, /^[a-zA-Z0-9]+$/)
      assert.deepEqual(codec.decode(code).map(Number), [999])
      await withSettledSaves(async () => {
        await request(app).put(`/rest/continue-code/apply/${code}`)
      })
      await assertScoreboardUnchanged()
    }
  })
})

void describe('public continue-code responses do not reveal solved challenge ids', () => {
  void it('GET /rest/continue-code does not disclose the solved set', async () => {
    const target = Object.values(challenges)[0]
    await challengeUtils.solve(target)
    const res = await request(app).get('/rest/continue-code')
    assertDoesNotReveal(res.status, res.body, Number(target.id))
  })

  void it('GET /rest/continue-code-findIt does not disclose find-it progress', async () => {
    const target = Object.values(challenges)[0]
    await ChallengeModel.update({ codingChallengeStatus: 1 }, { where: { id: target.id } })
    const res = await request(app).get('/rest/continue-code-findIt')
    assertDoesNotReveal(res.status, res.body, Number(target.id))
  })

  void it('GET /rest/continue-code-fixIt does not disclose fix-it progress', async () => {
    const target = Object.values(challenges)[0]
    await ChallengeModel.update({ codingChallengeStatus: 2 }, { where: { id: target.id } })
    const res = await request(app).get('/rest/continue-code-fixIt')
    assertDoesNotReveal(res.status, res.body, Number(target.id))
  })
})

async function assertForgedCodesDoNotChangeScoreboard (target: ApplyTarget, headers: Record<string, string>) {
  const ids = baseline.map((row) => row.id).filter((id) => id !== 999)
  const codecs = codecsFromRoutes()
  if (codecs.length === 0) {
    await withSettledSaves(async () => {
      await request(app).put(target.url('clientSuppliedContinueCode')).set(headers)
    })
    await assertScoreboardUnchanged()
    return
  }
  for (const codec of codecs) {
    for (const chunk of chunks(ids, 25)) {
      const code = codec.encode(chunk)
      assert.match(code, /^[a-zA-Z0-9]+$/)
      assert.deepEqual(codec.decode(code).map(Number), chunk)
      await withSettledSaves(async () => {
        await request(app).put(target.url(code)).set(headers)
      })
      await assertScoreboardUnchanged()
    }
  }
}

function assertDoesNotReveal (status: number, body: unknown, challengeId: number) {
  if (status !== 200) {
    return
  }
  const payload = body as { continueCode?: unknown, data?: unknown }
  const serialized = JSON.stringify(payload)
  assert.equal(serialized.includes(`"id":${challengeId}`), false)
  const code = payload.continueCode
  if (typeof code !== 'string' || code.length === 0) {
    return
  }
  for (const codec of codecsFromRoutes()) {
    let decoded: number[] = []
    try {
      decoded = codec.decode(code).map(Number)
    } catch {
      decoded = []
    }
    assert.equal(decoded.includes(challengeId), false)
  }
}

function codecsFromRoutes (): Hashids[] {
  const codecs: Hashids[] = []
  for (const relativePath of continueCodeRoutes) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8')
    const calls = source.matchAll(/new Hashids\(\s*'((?:\\'|[^'])*)'\s*,\s*(\d+)\s*,\s*([^)]*)\)/g)
    for (const call of calls) {
      const minLength = Number(call[2])
      const alphabetArg = call[3].trim()
      let alphabet: string
      if ((alphabetArg.startsWith("'") && alphabetArg.endsWith("'")) || (alphabetArg.startsWith('"') && alphabetArg.endsWith('"'))) {
        alphabet = alphabetArg.slice(1, -1)
      } else {
        const declared = source.match(new RegExp(`const ${alphabetArg} = '([^']*)'`))
        assert.ok(declared, `alphabet ${alphabetArg} was not found in ${relativePath}`)
        alphabet = declared[1]
      }
      codecs.push(new Hashids(call[1], minLength, alphabet))
    }
  }
  return codecs
}

function snapshot (): ScoreRow[] {
  return Object.values(challenges).map((challenge) => ({
    id: Number(challenge.id),
    key: challenge.key,
    solved: challenge.solved === true,
    codingChallengeStatus: Number(challenge.codingChallengeStatus)
  }))
}

async function restore (rows: ScoreRow[]) {
  for (const row of rows) {
    await ChallengeModel.update({
      solved: row.solved,
      codingChallengeStatus: row.codingChallengeStatus
    }, { where: { id: row.id } })
    const cached = challenges[row.key as keyof typeof challenges]
    if (cached) {
      cached.solved = row.solved
      cached.codingChallengeStatus = row.codingChallengeStatus
    }
  }
}

async function assertScoreboardUnchanged () {
  const listed = await request(app).get('/api/Challenges')
  assert.equal(listed.status, 200)
  assert.ok(Array.isArray(listed.body.data))
  for (const item of listed.body.data as Array<{ key: string, solved: unknown, codingChallengeStatus?: unknown }>) {
    assert.equal(markedSolved(item.solved), false, `${item.key} is solved on the public scoreboard`)
    assert.equal(Number(item.codingChallengeStatus ?? 0), 0, `${item.key} coding progress changed on the public scoreboard`)
  }
  const stored = await ChallengeModel.findAll()
  for (const row of stored) {
    assert.equal(markedSolved(row.solved), false, `${row.key} was persisted as solved`)
    assert.equal(Number(row.codingChallengeStatus), 0, `${row.key} coding progress was persisted`)
  }
  for (const row of baseline) {
    const cached = challenges[row.key as keyof typeof challenges]
    assert.equal(cached.solved === true, false, `${row.key} was marked solved in the process-wide challenge table`)
    assert.equal(Number(cached.codingChallengeStatus), 0, `${row.key} coding progress changed in the process-wide challenge table`)
  }
}

async function withSettledSaves<T> (fn: () => Promise<T>): Promise<T> {
  const pending: Array<Promise<unknown>> = []
  const originalSave = ChallengeModel.prototype.save
  ChallengeModel.prototype.save = function (this: ChallengeModel, ...args: Parameters<typeof originalSave>) {
    const pendingSave = originalSave.apply(this, args)
    pending.push(Promise.resolve(pendingSave))
    return pendingSave
  }
  try {
    const value = await fn()
    await Promise.all(pending)
    return value
  } finally {
    ChallengeModel.prototype.save = originalSave
  }
}

function tokenForAdmin (): string {
  const admin = users.admin
  assert.ok(admin)
  const authenticatedUser = {
    data: {
      id: admin.id,
      email: admin.email,
      role: admin.role
    },
    bid: 1
  }
  const token = security.authorize(authenticatedUser)
  security.authenticatedUsers.put(token, authenticatedUser as unknown as { data: typeof admin, bid: number })
  return token
}

function markedSolved (value: unknown): boolean {
  return value === true || value === 1
}

function chunks (ids: number[], size: number): number[][] {
  const groups: number[][] = []
  for (let i = 0; i < ids.length; i += size) {
    groups.push(ids.slice(i, i + size))
  }
  return groups
}
