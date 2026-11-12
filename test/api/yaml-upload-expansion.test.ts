/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { Worker } from 'node:worker_threads'
import request from 'supertest'
import type { Express } from 'express'
import type { Response } from 'supertest'
import { challenges } from '../../data/datacache'
import { createTestApp } from './helpers/setup'

const LEAF = 'lol'
const LEAF_COUNT = 9
const COMPLAINTS_DIR = path.resolve('uploads/complaints')
const RSS_GROWTH_LIMIT_KB = 64 * 1024

const rssSamplerSource = `
const { parentPort, workerData } = require('node:worker_threads')
const fs = require('node:fs')
let peak = 0
const timer = setInterval(() => {
  const status = fs.readFileSync('/proc/' + workerData.pid + '/status', 'utf8')
  const match = /VmRSS:\\s+(\\d+)/.exec(status)
  if (match) peak = Math.max(peak, Number(match[1]))
}, 10)
parentPort.postMessage('ready')
parentPort.on('message', () => {
  clearInterval(timer)
  parentPort.postMessage(peak)
})
`

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function nestedAliasYaml (levels: number): string {
  const names = 'abcdefghijklmnopqrstuvwxyz'
  const leaf = Array.from({ length: LEAF_COUNT }, () => `"${LEAF}"`).join(',')
  const lines = [`a: &a [${leaf}]`]
  for (let level = 1; level < levels; level++) {
    const previous = names[level - 1]
    const current = names[level]
    const refs = Array.from({ length: LEAF_COUNT }, () => `*${previous}`).join(',')
    lines.push(`${current}: &${current} [${refs}]`)
  }
  return lines.join('\n') + '\n'
}

function complaintFiles (): string[] {
  if (!fs.existsSync(COMPLAINTS_DIR)) return []
  return fs.readdirSync(COMPLAINTS_DIR).sort()
}

function readRssKb (): number {
  const status = fs.readFileSync('/proc/self/status', 'utf8')
  const match = /VmRSS:\s+(\d+)/.exec(status)
  assert.ok(match)
  return Number(match[1])
}

async function postAnonymousComplaint (filename: string, contents: string): Promise<Response> {
  return await request(app)
    .post('/file-upload')
    .attach('file', Buffer.from(contents), { filename, contentType: 'application/octet-stream' })
}

async function measurePeakRssKb (work: () => Promise<void>): Promise<number> {
  const worker = new Worker(rssSamplerSource, { eval: true, workerData: { pid: process.pid } })
  await new Promise<void>((resolve, reject) => {
    const onMessage = (message: unknown) => {
      if (message === 'ready') {
        worker.off('message', onMessage)
        resolve()
      }
    }
    worker.on('message', onMessage)
    worker.once('error', reject)
  })
  let workError: unknown
  try {
    await work()
  } catch (error) {
    workError = error
  }
  worker.postMessage('stop')
  const peak = await new Promise<number>((resolve, reject) => {
    worker.once('message', (message: unknown) => { resolve(Number(message)) })
    worker.once('error', reject)
  })
  await worker.terminate()
  if (workError != null) throw workError
  return peak
}

function assertAliasDocumentWasNotExpanded (res: Response, filename: string, startedAt: number, filesBefore: string[]) {
  const elapsedMs = Date.now() - startedAt
  const reflectedLeaves = res.text.match(new RegExp(LEAF, 'g'))?.length ?? 0
  assert.notEqual(res.status, 503, `${filename} was handled as a memory bomb`)
  assert.equal(res.text.includes('temporarily not available'), false)
  assert.ok(reflectedLeaves <= LEAF_COUNT, `${filename} reflected ${reflectedLeaves} copies of the leaf`)
  assert.ok(elapsedMs < 1000, `${filename} took ${elapsedMs}ms`)
  assert.deepEqual(complaintFiles(), filesBefore)
  assert.equal(challenges.yamlBombChallenge.solved, false)
}

void describe('YAML complaint uploads', () => {
  void it('does not expand nested aliases in an anonymous .yaml upload', async () => {
    const filesBefore = complaintFiles()
    const startedAt = Date.now()
    const res = await postAnonymousComplaint('complaint.yaml', nestedAliasYaml(6))
    assertAliasDocumentWasNotExpanded(res, 'complaint.yaml', startedAt, filesBefore)
    const health = await request(app).get('/rest/admin/application-version')
    assert.equal(health.status, 200)
  })

  void it('does not expand nested aliases in an anonymous .YML upload', async () => {
    const filesBefore = complaintFiles()
    const startedAt = Date.now()
    const res = await postAnonymousComplaint('complaint.YML', nestedAliasYaml(6))
    assertAliasDocumentWasNotExpanded(res, 'complaint.YML', startedAt, filesBefore)
  })

  void it('does not expand nested aliases in an anonymous .YAML upload', async () => {
    const filesBefore = complaintFiles()
    const startedAt = Date.now()
    const res = await postAnonymousComplaint('complaint.YAML', nestedAliasYaml(4))
    assertAliasDocumentWasNotExpanded(res, 'complaint.YAML', startedAt, filesBefore)
  })

  void it('does not turn an anonymous .yml alias bomb into a 503 or a large allocation', async () => {
    const filesBefore = complaintFiles()
    const document = nestedAliasYaml(9)
    assert.ok(Buffer.byteLength(document) < 200000)
    let res: Response | undefined
    const baselineRssKb = readRssKb()
    const startedAt = Date.now()
    const peakRssKb = await measurePeakRssKb(async () => {
      res = await postAnonymousComplaint('complaint.yml', document)
    })
    const growthKb = peakRssKb - baselineRssKb
    assert.ok(growthKb < RSS_GROWTH_LIMIT_KB, `resident set grew by ${growthKb}kB`)
    assert.ok(res)
    assertAliasDocumentWasNotExpanded(res, 'complaint.yml', startedAt, filesBefore)
    const health = await request(app).get('/rest/admin/application-version')
    assert.equal(health.status, 200)
  }, { timeout: 20000 })
})
