/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

// Public parameters from test/files/encrypt.py. The private exponent is not used.
const PUBLISHED_MODULUS = BigInt('145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053')
const PUBLISHED_EXPONENT = 65537n

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function responseText (res: request.Response): string {
  return res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf-8') : '')
}

function modPow (base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n
  let factor = base % modulus
  let remaining = exponent
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = (result * factor) % modulus
    factor = (factor * factor) % modulus
    remaining >>= 1n
  }
  return result
}

interface PublicParameters {
  modulus: bigint
  exponent: bigint
}

function parameterSets (): PublicParameters[] {
  const sets = new Map<string, PublicParameters>()
  const add = (modulus: bigint, exponent: bigint) => {
    sets.set(`${modulus.toString()}:${exponent.toString()}`, { modulus, exponent })
  }
  add(PUBLISHED_MODULUS, PUBLISHED_EXPONENT)
  for (const relative of ['test/files/encrypt.py', 'test/files/decrypt_bruteforce.py']) {
    const full = path.resolve(relative)
    if (!fs.existsSync(full)) continue
    const source = fs.readFileSync(full, 'utf8')
    const modulus = source.match(/^N = (\d+)\s*$/m)?.[1]
    const exponent = source.match(/^e = (\d+)\s*$/m)?.[1]
    if (modulus != null && exponent != null) add(BigInt(modulus), BigInt(exponent))
  }
  return [...sets.values()]
}

function characterDictionary (parameters: PublicParameters): Map<string, string> {
  const dict = new Map<string, string>()
  const chars: string[] = []
  for (let code = 33; code < 126; code++) chars.push(String.fromCharCode(code))
  chars.push(' ', '\n', '\t')
  for (const char of chars) {
    const codePoint = char.codePointAt(0)
    if (codePoint === undefined) continue
    dict.set(modPow(BigInt(codePoint), parameters.exponent, parameters.modulus).toString(), char)
  }
  return dict
}

function invertPerCharacterRsa (body: string, dict: Map<string, string>): string | null {
  const lines = body.split('\n')
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  if (lines.length === 0) return null
  let recovered = ''
  for (const line of lines) {
    const trimmed = line.trim()
    if (!/^\d+$/.test(trimmed)) return null
    const char = dict.get(trimmed)
    if (char === undefined) return null
    recovered += char
  }
  return recovered
}

function shiftJoin (values: number[], offset: number): string {
  const copy = values.slice()
  const base = copy.shift()
  if (base === undefined) return ''
  return copy.reverse().map((code, index) => String.fromCharCode(code - base - offset - index)).join('')
}

function hiddenSaleRoute (): string {
  const source = fs.readFileSync(path.resolve('frontend/src/app/app.routing.ts'), 'utf8')
  const token1Offset = Number(source.match(/function token1[\s\S]*?fromCharCode\(C - D - (\d+) - A\)/)?.[1])
  const token2Offset = Number(source.match(/function token2[\s\S]*?fromCharCode\(m - M - (\d+) - H\)/)?.[1])
  const line = source.split('\n').find((entry) => entry.includes('token1(') && entry.includes('token2('))
  const first = line?.match(/token1\(([^)]*)\)/)
  const second = line?.match(/token2\(([^)]*)\)/)
  const radixParts = line == null ? [] : [...line.matchAll(/\((\d+)\)\.toString\(36\)/g)]
  if (!Number.isFinite(token1Offset) || !Number.isFinite(token2Offset) || first == null || second == null || radixParts.length < 2) {
    throw new Error('token sale route matcher was not found')
  }
  const args1 = first[1].split(',').map((part) => Number(part.trim()))
  const args2 = second[1].split(',').map((part) => Number(part.trim()))
  return shiftJoin(args1, token1Offset) +
    Number(radixParts[0][1]).toString(36).toLowerCase() +
    shiftJoin(args2, token2Offset) +
    Number(radixParts[1][1]).toString(36).toLowerCase()
}

function revealsAnnouncement (body: string, dictionaries: Map<string, string>[]): boolean {
  const route = hiddenSaleRoute()
  if (route.length > 0 && body.includes(route)) return true
  const plainPath = path.resolve('test/files/announcement.md')
  const plain = fs.existsSync(plainPath) ? fs.readFileSync(plainPath, 'utf8') : null
  if (plain != null && body === plain) return true
  for (const dict of dictionaries) {
    if (invertPerCharacterRsa(body, dict) != null) return true
  }
  return false
}

function listedFileNames (html: string): string[] {
  const names: string[] = []
  const anchors = html.matchAll(/<a href="[^"]*" class="([^"]*)" title="([^"]*)"/g)
  for (const anchor of anchors) {
    const classes = anchor[1]
    const name = anchor[2]
    if (name === '..' || name.includes('/') || name.includes('\\')) continue
    if (classes.includes('icon-directory')) continue
    names.push(name)
  }
  return names
}

async function anonymousFileBodies (): Promise<Array<{ url: string, body: string }>> {
  const urls = ['/ftp/announcement_encrypted.md']
  const listing = await request(app).get('/ftp')
  if (listing.status === 200) {
    for (const name of listedFileNames(listing.text)) {
      urls.push('/ftp/' + encodeURIComponent(name))
    }
  }
  const bodies: Array<{ url: string, body: string }> = []
  const seen = new Set<string>()
  for (const url of urls) {
    if (seen.has(url)) continue
    seen.add(url)
    const res = await request(app).get(url).buffer(true)
    if (res.status === 200) bodies.push({ url, body: responseText(res) })
  }
  return bodies
}

void describe('confidential announcement', () => {
  void it('is not recoverable from an anonymous public file response', async () => {
    const dictionaries = parameterSets().map((parameters) => characterDictionary(parameters))
    const leaking = (await anonymousFileBodies())
      .filter((item) => revealsAnnouncement(item.body, dictionaries))
      .map((item) => item.url)
    assert.deepEqual(leaking, [], 'an anonymous client recovered the confidential announcement from a public file response')
  })
})
