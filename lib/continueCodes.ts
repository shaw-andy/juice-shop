/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

export type ContinueCodeScope = 'hacking' | 'findIt' | 'fixIt'

const keyFile = path.resolve('data/continueCode.key')
const keyLength = 32
const ivLength = 12
const tagLength = 16
const hexRegexp = /^(?:[0-9a-f]{2})+$/

let key: Buffer | undefined

function getKey (): Buffer {
  key ??= loadOrCreateKey()
  return key
}

// The key is unique per instance and kept on disk so continue codes survive a restart of that instance
function loadOrCreateKey (): Buffer {
  try {
    const stored = fs.readFileSync(keyFile)
    if (stored.length === keyLength) return stored
  } catch {}
  const generated = crypto.randomBytes(keyLength)
  try {
    fs.writeFileSync(keyFile, generated, { mode: 0o600 })
  } catch {}
  return generated
}

export function encrypt (scope: ContinueCodeScope, ids: number[]): string {
  const iv = crypto.randomBytes(ivLength)
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv, { authTagLength: tagLength })
  cipher.setAAD(Buffer.from(scope))
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(ids), 'utf8'), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('hex')
}

export function decrypt (scope: ContinueCodeScope, hex: string): number[] {
  if (typeof hex !== 'string' || !hexRegexp.test(hex)) return []
  const data = Buffer.from(hex, 'hex')
  if (data.length <= ivLength + tagLength) return []
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), data.subarray(0, ivLength), { authTagLength: tagLength })
    decipher.setAAD(Buffer.from(scope))
    decipher.setAuthTag(data.subarray(ivLength, ivLength + tagLength))
    const plaintext = Buffer.concat([decipher.update(data.subarray(ivLength + tagLength)), decipher.final()])
    const ids: unknown = JSON.parse(plaintext.toString('utf8'))
    return Array.isArray(ids) && ids.every(Number.isInteger) ? ids : []
  } catch {
    return []
  }
}
