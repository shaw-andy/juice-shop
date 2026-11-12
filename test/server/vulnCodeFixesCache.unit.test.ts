/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import v8 from 'node:v8'
import vm from 'node:vm'
import { readFixes } from '../../routes/vulnCodeFixes'

v8.setFlagsFromString('--expose-gc')
const collectGarbage: () => void = vm.runInNewContext('gc')

const keyLength = 512

function writeUnknownKey (file: string, length: number) {
  const unique = `notachallenge${process.hrtime.bigint().toString(16)}${Math.random().toString(16).slice(2)}`
  assert.ok(unique.length < length)
  fs.writeFileSync(file, unique + 'x'.repeat(length - unique.length))
}

function lookupUnknownKey (file: string) {
  const key = fs.readFileSync(file, 'utf8')
  const found = readFixes(key)
  assert.equal(found.fixes.length, 0)
  assert.equal(found.correct, -1)
}

function heapSnapshot (dir: string) {
  collectGarbage()
  collectGarbage()
  const snapFile = path.join(dir, 'heap.heapsnapshot')
  v8.writeHeapSnapshot(snapFile)
  return fs.readFileSync(snapFile)
}

void describe('readFixes cache', () => {
  void it('serves fixes for a known coding challenge', () => {
    const found = readFixes('resetPasswordBenderChallenge')
    assert.ok(found.fixes.length >= 3)
    assert.ok(found.correct > -1)
  })

  void it('does not retain keys that match no fix file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fixes-cache-'))
    try {
      const files: string[] = []
      for (let i = 0; i < 12; i++) {
        const file = path.join(dir, `key-${i}.txt`)
        writeUnknownKey(file, keyLength)
        files.push(file)
        lookupUnknownKey(file)
      }
      const control = path.join(dir, 'control.txt')
      writeUnknownKey(control, keyLength)
      const snap = heapSnapshot(dir)
      assert.equal(snap.includes(fs.readFileSync(control)), false)
      const retained = files.filter((file) => snap.includes(fs.readFileSync(file)))
      assert.equal(retained.length, 0)
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })
})
