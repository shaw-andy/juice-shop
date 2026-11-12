/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'
import tls from 'node:tls'
import v8 from 'node:v8'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

const originalTlsConnect = tls.connect
tls.connect = function (this: unknown, ...args: any[]) {
  const first = args[0]
  const host = typeof first === 'string' ? first : first?.host
  if (typeof host === 'string' && host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    const inner = new net.Socket()
    const socket = new tls.TLSSocket(inner)
    socket.on('error', () => {})
    inner.on('error', () => {})
    return socket
  }
  return originalTlsConnect.apply(this, args)
} as typeof tls.connect

const endpoint = '/rest/web3/walletExploitAddress'
const posts = 12
const maxRetainedCopies = 5

let app: Express

function countRetained (marker: string): number {
  assert.equal(typeof global.gc, 'function', 'run this file with node --expose-gc')
  global.gc()
  global.gc()
  const snap = v8.writeHeapSnapshot()
  try {
    const text = fs.readFileSync(snap)
    let found = 0
    let idx = 0
    while ((idx = text.indexOf(marker, idx)) !== -1) {
      found++
      idx += marker.length
    }
    return found
  } finally {
    fs.unlinkSync(snap)
  }
}

async function postJson (body: unknown): Promise<number> {
  const res = await request(app)
    .post(endpoint)
    .set('Content-Type', 'application/json')
    .send(body as object)
  return res.status
}

async function postForm (walletAddress: string): Promise<number> {
  const res = await request(app)
    .post(endpoint)
    .type('form')
    .send({ walletAddress })
  return res.status
}

void describe('wallet exploit address retention', () => {
  before(async () => {
    const result = await createTestApp()
    app = result.app
    const warmup = await postJson({ walletAddress: 'warmup' })
    assert.notEqual(warmup, 413)
  }, { timeout: 120000 })

  void it('does not keep every distinct anonymous json walletAddress string', async () => {
    const repeated = 'json-repeat-q7' + 'a'.repeat(2000)
    const statuses: number[] = []
    for (let i = 0; i < posts; i++) {
      statuses.push(await postJson({ walletAddress: repeated }))
    }
    const repeatedCopies = countRetained('json-repeat-q7')

    const distinctMarker = 'json-distinct-q7-'
    for (let i = 0; i < posts; i++) {
      statuses.push(await postJson({ walletAddress: `${distinctMarker}${i}${'b'.repeat(2000)}` }))
    }
    const distinctCopies = countRetained(distinctMarker)

    assert.ok(statuses.every((status) => status !== 413), `body parser rejected a payload: ${statuses.join(',')}`)
    assert.ok(repeatedCopies < maxRetainedCopies, `repeated value was copied ${repeatedCopies} times; measurement is not isolating retention`)
    assert.ok(distinctCopies < maxRetainedCopies, `retained ${distinctCopies} copies of ${posts} distinct json walletAddress values`)
  }, { timeout: 120000 })

  void it('does not keep every distinct anonymous form walletAddress string', async () => {
    const repeated = 'form-repeat-q7' + 'c'.repeat(2000)
    const statuses: number[] = []
    for (let i = 0; i < posts; i++) {
      statuses.push(await postForm(repeated))
    }
    const repeatedCopies = countRetained('form-repeat-q7')

    const distinctMarker = 'form-distinct-q7-'
    for (let i = 0; i < posts; i++) {
      statuses.push(await postForm(`${distinctMarker}${i}${'d'.repeat(2000)}`))
    }
    const distinctCopies = countRetained(distinctMarker)

    assert.ok(statuses.every((status) => status !== 413), `body parser rejected a payload: ${statuses.join(',')}`)
    assert.ok(repeatedCopies < maxRetainedCopies, `repeated form value was copied ${repeatedCopies} times; measurement is not isolating retention`)
    assert.ok(distinctCopies < maxRetainedCopies, `retained ${distinctCopies} copies of ${posts} distinct form walletAddress values`)
  }, { timeout: 120000 })

  void it('does not keep every distinct anonymous non-string walletAddress', async () => {
    const repeated = 'object-repeat-q7' + 'e'.repeat(2000)
    const statuses: number[] = []
    for (let i = 0; i < posts; i++) {
      statuses.push(await postJson({ walletAddress: { note: repeated } }))
    }
    const repeatedCopies = countRetained('object-repeat-q7')

    const distinctMarker = 'object-distinct-q7-'
    for (let i = 0; i < posts; i++) {
      statuses.push(await postJson({ walletAddress: { note: `${distinctMarker}${i}${'f'.repeat(2000)}` } }))
    }
    const distinctCopies = countRetained(distinctMarker)

    assert.ok(statuses.every((status) => status !== 413), `body parser rejected a payload: ${statuses.join(',')}`)
    assert.ok(repeatedCopies < maxRetainedCopies, `repeated object was copied ${repeatedCopies} times; measurement is not isolating retention`)
    assert.ok(distinctCopies < maxRetainedCopies, `retained ${distinctCopies} copies of ${posts} distinct walletAddress objects`)
  }, { timeout: 120000 })
})
