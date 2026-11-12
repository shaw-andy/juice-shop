/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, unlinkSync } from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { IncomingMessage } from 'node:http'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { type UserModel } from '../../models/user'

let app: Express

const customerAEmail = 'customer-a@example.test'
const customerBEmail = 'customer-b@example.test'
const basketProductName = 'Raspberry Juice (1000ml)'

const directlyServed = [
  'ftp/acquisitions.md',
  'ftp/announcement_encrypted.md',
  'ftp/incident-support.kdbx',
  'encryptionkeys/jwt.pub',
  'encryptionkeys/premium.key',
  'ftp/quarantine/juicy_malware_linux_amd_64.url',
  'ftp/quarantine/juicy_malware_linux_arm_64.url',
  'ftp/quarantine/juicy_malware_macos_64.url',
  'ftp/quarantine/juicy_malware_windows_64.exe.url'
]

const extensionBypassTargets = [
  'ftp/coupons_2013.md.bak',
  'ftp/package.json.bak',
  'ftp/package-lock.json.bak',
  'ftp/suspicious_errors.yml',
  'ftp/eastere.gg',
  'ftp/encrypt.pyc'
]

let orderId = ''
let orderPdfName = ''
let tokenB = ''

before(async () => {
  const result = await createTestApp()
  app = result.app

  const customerA = {
    data: { id: 2, email: customerAEmail, role: 'customer' } as UserModel,
    bid: 2
  }
  const customerB = {
    data: { id: 3, email: customerBEmail, role: 'customer' } as UserModel,
    bid: 3
  }
  const tokenA = security.authorize(customerA)
  tokenB = security.authorize(customerB)
  security.authenticatedUsers.put(tokenA, customerA)
  security.authenticatedUsers.put(tokenB, customerB)

  const checkout = await request(app)
    .post('/rest/basket/2/checkout')
    .set({ Authorization: 'Bearer ' + tokenA, 'content-type': 'application/json' })
    .send({})
  assert.equal(checkout.status, 200)
  orderId = String(checkout.body.orderConfirmation)
  orderPdfName = `order_${orderId}.pdf`
}, { timeout: 60000 })

after(() => {
  const written = path.join('ftp', orderPdfName)
  if (orderPdfName !== '' && existsSync(written)) {
    unlinkSync(written)
  }
})

function bufferParser (res: IncomingMessage, callback: (err: Error | null, body?: Buffer) => void) {
  const chunks: Buffer[] = []
  res.on('data', (chunk: Buffer | string) => {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  })
  res.on('end', () => {
    callback(null, Buffer.concat(chunks))
  })
}

function requestHeaders (token?: string) {
  const headers: Record<string, string> = { 'Accept-Encoding': 'identity' }
  if (token !== undefined) {
    headers.Authorization = 'Bearer ' + token
  }
  return headers
}

async function fetchRaw (urlPath: string, token?: string) {
  return await request(app)
    .get(urlPath)
    .set(requestHeaders(token))
    .buffer(true)
    .parse(bufferParser)
}

async function fetchListing (urlPath: string) {
  return await request(app).get(urlPath)
}

function rawBody (res: request.Response): Buffer {
  if (Buffer.isBuffer(res.body)) {
    return res.body
  }
  return Buffer.from(res.text ?? '')
}

function sha256 (buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex')
}

function pdfStreams (buf: Buffer): string {
  const latin = buf.toString('latin1')
  let text = ''
  let from = 0
  while (from < latin.length) {
    const start = latin.indexOf('stream', from)
    if (start < 0) break
    let dataStart = start + 'stream'.length
    if (latin.charCodeAt(dataStart) === 13) dataStart++
    if (latin.charCodeAt(dataStart) === 10) dataStart++
    const end = latin.indexOf('endstream', dataStart)
    if (end < 0) break
    let dataEnd = end
    if (dataEnd > dataStart && latin.charCodeAt(dataEnd - 1) === 10) dataEnd--
    if (dataEnd > dataStart && latin.charCodeAt(dataEnd - 1) === 13) dataEnd--
    const slice = buf.subarray(dataStart, dataEnd)
    try {
      text += zlib.inflateSync(slice).toString('latin1')
    } catch {
      text += slice.toString('latin1')
    }
    from = end + 'endstream'.length
  }
  return text
}

function pdfText (buf: Buffer): string {
  const raw = pdfStreams(buf)
  const parts = raw.match(/<([0-9A-Fa-f]+)>/g) ?? []
  return parts.map(part => {
    const hex = part.slice(1, -1)
    let text = ''
    for (let i = 0; i + 1 < hex.length; i += 2) {
      text += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16))
    }
    return text
  }).join('')
}

function assertNotTheFile (res: request.Response, diskPath: string) {
  const encoding = res.headers['content-encoding']
  assert.ok(encoding === undefined || encoding === 'identity', `content-encoding ${String(encoding)}`)
  const served = sha256(rawBody(res))
  const onDisk = sha256(readFileSync(diskPath))
  assert.notEqual(served, onDisk, `status ${res.status} returned ${diskPath}`)
}

void describe('sensitive files without authentication', () => {
  void it('does not publish a directory listing of /ftp', async () => {
    const res = await fetchListing('/ftp')
    const listing = res.text
    assert.equal(listing.includes('acquisitions.md'), false)
    assert.equal(listing.includes('incident-support.kdbx'), false)
    assert.equal(listing.includes('coupons_2013.md.bak'), false)
    assert.equal(listing.includes('announcement_encrypted.md'), false)
    assert.equal(listing.includes('<title>listing directory /ftp</title>'), false)
  })

  void it('does not publish a directory listing of /ftp/quarantine', async () => {
    const res = await fetchListing('/ftp/quarantine')
    const listing = res.text
    assert.equal(listing.includes('juicy_malware_linux_amd_64.url'), false)
    assert.equal(listing.includes('juicy_malware_windows_64.exe.url'), false)
  })

  void it('does not publish a directory listing of /encryptionkeys', async () => {
    const res = await fetchListing('/encryptionkeys')
    const listing = res.text
    assert.equal(listing.includes('premium.key'), false)
    assert.equal(listing.includes('jwt.pub'), false)
    assert.equal(listing.includes('<title>listing directory /encryptionkeys</title>'), false)
  })

  for (const diskPath of directlyServed) {
    const urlPath = '/' + diskPath
    void it(`does not return ${urlPath} to an anonymous caller`, async () => {
      const res = await fetchRaw(urlPath)
      assertNotTheFile(res, diskPath)
    })
  }

  for (const diskPath of extensionBypassTargets) {
    const base = path.basename(diskPath)
    for (const suffix of ['.md', '.pdf']) {
      void it(`does not return ${base} when a ${suffix} suffix is appended after %00`, async () => {
        const res = await fetchRaw('/ftp/' + base + '%2500' + suffix)
        assertNotTheFile(res, diskPath)
      })
    }
  }

  void it('does not write an order PDF into the public ftp directory', () => {
    assert.equal(existsSync(path.join('ftp', orderPdfName)), false)
  })

  void it('does not list another customer order PDF under /ftp', async () => {
    const res = await fetchListing('/ftp')
    assert.equal(res.text.includes(orderPdfName), false)
  })

  void it('does not serve another customer order PDF without that customer credentials', async () => {
    const pdfPath = path.join('ftp', orderPdfName)
    const anonymous = await fetchRaw('/ftp/' + orderPdfName)
    const otherCustomer = await fetchRaw('/ftp/' + orderPdfName, tokenB)
    const anonText = pdfText(rawBody(anonymous))
    const otherText = pdfText(rawBody(otherCustomer))
    assert.deepEqual(
      [
        anonText.includes(customerAEmail),
        otherText.includes(customerAEmail),
        anonText.includes(basketProductName),
        otherText.includes(basketProductName)
      ],
      [false, false, false, false]
    )
    if (existsSync(pdfPath)) {
      assertNotTheFile(anonymous, pdfPath)
      assertNotTheFile(otherCustomer, pdfPath)
    }
  })
})
