/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach, after, mock } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import v8 from 'node:v8'
import request from 'supertest'
import { Op } from 'sequelize'
import type { Express } from 'express'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import * as antiCheat from '../../lib/antiCheat'
import * as metrics from '../../routes/metrics'
import { readFixes } from '../../routes/vulnCodeFixes'
import { retrieveCodeSnippet } from '../../routes/vulnCodeSnippet'
import { ChallengeModel } from '../../models/challenge'

const REPEATS = 8
const FIX_FROM_ZERO = 'resetPasswordBenderChallenge'
const FIND_FROM_ZERO = 'directoryListingChallenge'
const FIX_AFTER_FIND = 'loginAdminChallenge'
const PHASES = new Set(['server start', 'hack it', 'find it', 'fix it'])

interface HistoryEntry {
  challenge?: { key?: string }
  phase?: string
  cheatScore?: number
  timestamp?: Date
}

interface HistoryReport {
  matches: number
  scannedLength: number | null
}

let app: Express
let server: http.Server
let serverPort: number
let socket: Socket
let findItLines: number[] = []
let metricsLoopStarted = false

const fixesDir = path.resolve('data/static/codefixes')

function correctFixIndex (key: string): number {
  const match = fs.readdirSync(fixesDir).find((file) => {
    const parts = file.split('_')
    return file.startsWith(`${key}_`) && parts.length === 3 && parts[2].startsWith('correct')
  })
  if (match == null) {
    throw new Error(`No public correct-fix file for ${key}`)
  }
  return parseInt(match.split('_')[1], 10) - 1
}

function looksLikeHistory (value: unknown): value is HistoryEntry[] {
  if (!Array.isArray(value) || value.length === 0) return false
  return value.every((entry) => {
    if (entry == null || typeof entry !== 'object') return false
    const record = entry as HistoryEntry
    return typeof record.phase === 'string' &&
      PHASES.has(record.phase) &&
      typeof record.cheatScore === 'number' &&
      record.timestamp instanceof Date
  })
}

function countInHistory (entries: HistoryEntry[], key: string, phase: string): number {
  return entries.filter((entry) => entry.phase === phase && entry.challenge?.key === key).length
}

function installHistoryScan () {
  const originalMap = Array.prototype.map
  const seen: { entries: HistoryEntry[] | null } = { entries: null }
  // The metrics path reads the private score list only by mapping it inside totalCheatScore.
  // eslint-disable-next-line no-extend-native
  Array.prototype.map = function (callback: (value: unknown, index: number, array: unknown[]) => unknown, thisArg?: unknown) {
    if (looksLikeHistory(this)) seen.entries = Array.from(this)
    return originalMap.call(this, callback, thisArg)
  }
  return {
    seen,
    restore () {
      // eslint-disable-next-line no-extend-native
      Array.prototype.map = originalMap
    }
  }
}

function historyScannedByTotalCheatScore (): HistoryEntry[] | null {
  const scan = installHistoryScan()
  try {
    antiCheat.totalCheatScore()
    return scan.seen.entries
  } finally {
    scan.restore()
  }
}

function countRetainedHistory (key: string, phase: string): number {
  const file = v8.writeHeapSnapshot(path.join(os.tmpdir(), `juice-history-${process.pid}-${Date.now()}.heapsnapshot`))
  try {
    const snap = JSON.parse(fs.readFileSync(file, 'utf8'))
    const nodeFields = snap.snapshot.meta.node_fields.length
    const edgeFields = snap.snapshot.meta.edge_fields.length
    const nodeTypes: string[] = snap.snapshot.meta.node_types[0]
    const edgeTypes: string[] = snap.snapshot.meta.edge_types[0]
    const typeObject = nodeTypes.indexOf('object')
    const stringTypes = new Set(['string', 'concatenated string', 'sliced string'].map((name) => nodeTypes.indexOf(name)))
    const edgeProperty = edgeTypes.indexOf('property')
    const nodes: number[] = snap.nodes
    const edges: number[] = snap.edges
    const strings: string[] = snap.strings
    const nodeCount: number = snap.snapshot.node_count
    const stringValue = new Map<number, string>()
    const props = new Map<number, Map<string, number>>()
    let edgeCursor = 0
    for (let i = 0; i < nodeCount; i++) {
      const base = i * nodeFields
      const type = nodes[base]
      const edgeCount = nodes[base + 4]
      if (stringTypes.has(type)) stringValue.set(i, strings[nodes[base + 1]])
      let objProps: Map<string, number> | null = null
      for (let e = 0; e < edgeCount; e++) {
        const edgeBase = edgeCursor * edgeFields
        const edgeType = edges[edgeBase]
        const edgeName = edges[edgeBase + 1]
        const to = edges[edgeBase + 2] / nodeFields
        edgeCursor++
        if (type === typeObject && edgeType === edgeProperty) {
          if (objProps === null) objProps = new Map()
          objProps.set(strings[edgeName], to)
        }
      }
      if (objProps !== null) props.set(i, objProps)
    }
    const keyOf = (ordinal: number): string | undefined => {
      const own = props.get(ordinal)
      if (own == null) return undefined
      if (own.has('key')) {
        const direct = stringValue.get(own.get('key') as number)
        if (direct != null) return direct
      }
      if (own.has('dataValues')) {
        const values = props.get(own.get('dataValues') as number)
        if (values?.has('key')) return stringValue.get(values.get('key') as number)
      }
      return undefined
    }
    let count = 0
    for (const obj of props.values()) {
      if (!obj.has('phase') || !obj.has('timestamp') || !obj.has('challenge')) continue
      if (stringValue.get(obj.get('phase') as number) !== phase) continue
      if (keyOf(obj.get('challenge') as number) !== key) continue
      const timestamp = obj.get('timestamp') as number
      const timestampType = nodes[timestamp * nodeFields]
      const timestampName = strings[nodes[timestamp * nodeFields + 1]]
      if (timestampType !== typeObject || timestampName !== 'Date') continue
      count++
    }
    return count
  } finally {
    fs.unlinkSync(file)
  }
}

function historyReport (key: string, phase: string): HistoryReport {
  const scanned = historyScannedByTotalCheatScore()
  if (scanned !== null) {
    return { matches: countInHistory(scanned, key, phase), scannedLength: scanned.length }
  }
  return { matches: countRetainedHistory(key, phase), scannedLength: null }
}

async function repeatRequests (times: number, parallel: boolean, send: () => Promise<{ status: number, body: { verdict?: boolean } }>) {
  const responses = []
  if (parallel) {
    responses.push(...await Promise.all(Array.from({ length: times }, send)))
  } else {
    for (let i = 0; i < times; i++) responses.push(await send())
  }
  for (const res of responses) {
    assert.equal(res.status, 200)
    assert.equal(res.body.verdict, true)
  }
  return responses.length
}

async function postFixes (key: string, selectedFix: number, times: number, parallel: boolean) {
  return await repeatRequests(times, parallel, async () => await request(app).post('/snippets/fixes').send({ key, selectedFix }))
}

async function postVerdicts (key: string, selectedLines: number[], times: number, parallel: boolean) {
  return await repeatRequests(times, parallel, async () => await request(app).post('/snippets/verdict').send({ key, selectedLines }))
}

function codingEvents (key: string, status: number) {
  return (socket as Socket & { codingEvents?: Array<{ key: string, codingChallengeStatus: number }> }).codingEvents
    ?.filter((event) => event.key === key && event.codingChallengeStatus === status).length ?? 0
}

async function setCodingStatus (key: string, status: number) {
  const [updated] = await ChallengeModel.update({ codingChallengeStatus: status }, { where: { key } })
  assert.equal(updated, 1)
}

async function matchesScannedByMetricsLoop (key: string, phase: string): Promise<number> {
  if (metricsLoopStarted) {
    throw new Error('metrics update loop can only be registered once per process')
  }
  metricsLoopStarted = true
  const registered = metrics.observeMetrics()
  const scan = installHistoryScan()
  mock.timers.enable({ apis: ['setInterval'] })
  const loop = registered.updateLoop()
  mock.timers.tick(5000)
  clearInterval(loop)
  mock.timers.reset()
  try {
    const deadline = Date.now() + 10000
    let waiting = scan.seen.entries === null
    while (waiting && Date.now() < deadline) {
      await new Promise<void>((resolve) => { setTimeout(resolve, 20) })
      waiting = scan.seen.entries === null
    }
  } finally {
    scan.restore()
  }
  assert.ok(scan.seen.entries, 'metrics update loop did not scan the anti-cheat history')
  return countInHistory(scan.seen.entries, key, phase)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
  const snippet = await retrieveCodeSnippet(FIND_FROM_ZERO)
  assert.ok(snippet, `missing code snippet for ${FIND_FROM_ZERO}`)
  findItLines = snippet.vulnLines
  assert.ok(findItLines.length > 0)
  for (const key of [FIX_FROM_ZERO, FIND_FROM_ZERO, FIX_AFTER_FIND]) {
    assert.equal(correctFixIndex(key), readFixes(key).correct)
  }
  await new Promise<void>((resolve) => {
    server = http.createServer(app)
    registerWebsocketEvents(server)
    server.listen(0, () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') serverPort = addr.port
      resolve()
    })
  })
}, { timeout: 60000 })

after(() => {
  socket?.disconnect()
  server?.close()
})

beforeEach(async () => {
  antiCheat.reset()
  socket?.disconnect()
  const codingEvents: Array<{ key: string, codingChallengeStatus: number }> = []
  await new Promise<void>((resolve) => {
    socket = ioClient(`http://localhost:${serverPort}`, { reconnectionDelay: 0, forceNew: true })
    socket.on('code challenge solved', (data: { key: string, codingChallengeStatus: number }) => {
      codingEvents.push(data)
    })
    ;(socket as Socket & { codingEvents?: typeof codingEvents }).codingEvents = codingEvents
    socket.on('connect', () => { resolve() })
  })
  await ChallengeModel.update(
    { codingChallengeStatus: 0 },
    { where: { key: { [Op.in]: [FIX_FROM_ZERO, FIND_FROM_ZERO, FIX_AFTER_FIND] } } }
  )
})

void describe('repeatable coding-challenge solves', { concurrency: 1 }, () => {
  void it('keeps a single fix-it anti-cheat score when anonymous clients resubmit the public correct fix', async () => {
    const selectedFix = correctFixIndex(FIX_FROM_ZERO)
    await postFixes(FIX_FROM_ZERO, selectedFix, REPEATS, true)
    await postFixes(FIX_FROM_ZERO, selectedFix, REPEATS, false)

    const report = historyReport(FIX_FROM_ZERO, 'fix it')
    assert.equal(report.matches, 1)
    assert.equal(codingEvents(FIX_FROM_ZERO, 2), 1)
    if (report.scannedLength != null) {
      assert.ok(report.scannedLength < REPEATS * 2)
    }
  })

  void it('keeps a single find-it anti-cheat score when anonymous clients resubmit the known vulnerable lines', async () => {
    await postVerdicts(FIND_FROM_ZERO, findItLines, REPEATS, true)
    await postVerdicts(FIND_FROM_ZERO, findItLines, REPEATS, false)

    const report = historyReport(FIND_FROM_ZERO, 'find it')
    assert.equal(report.matches, 1)
    assert.equal(codingEvents(FIND_FROM_ZERO, 1), 1)
    if (report.scannedLength != null) {
      assert.ok(report.scannedLength < REPEATS * 2)
    }
  })

  void it('still records one fix-it score when find-it is already solved and many fix submissions race', async () => {
    await setCodingStatus(FIX_AFTER_FIND, 1)
    await postFixes(FIX_AFTER_FIND, correctFixIndex(FIX_AFTER_FIND), REPEATS, true)

    const report = historyReport(FIX_AFTER_FIND, 'fix it')
    assert.equal(report.matches, 1)
    assert.equal(codingEvents(FIX_AFTER_FIND, 2), 1)
  })

  void it('does not score or broadcast a phase that the stored coding-challenge status already marks solved', async () => {
    await setCodingStatus(FIND_FROM_ZERO, 2)
    await postVerdicts(FIND_FROM_ZERO, findItLines, REPEATS, true)
    await postFixes(FIND_FROM_ZERO, correctFixIndex(FIND_FROM_ZERO), REPEATS, true)

    assert.equal(historyReport(FIND_FROM_ZERO, 'find it').matches, 0)
    assert.equal(historyReport(FIND_FROM_ZERO, 'fix it').matches, 0)
    assert.equal(codingEvents(FIND_FROM_ZERO, 1), 0)
    assert.equal(codingEvents(FIND_FROM_ZERO, 2), 0)
  })

  void it('makes the metrics update loop scan one fix-it score after repeated correct fixes', async () => {
    await postFixes(FIX_FROM_ZERO, correctFixIndex(FIX_FROM_ZERO), REPEATS, true)

    const matches = await matchesScannedByMetricsLoop(FIX_FROM_ZERO, 'fix it')
    assert.equal(matches, 1)
  })
})
