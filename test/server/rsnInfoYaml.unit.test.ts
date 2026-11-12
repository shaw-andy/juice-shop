/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { computeChallengeDiff } from '../../rsn/rsnUtil'
import { printChallengeDiff } from '../../rsn/rsnOutput'

const infoFile = path.resolve('data/static/codefixes/loginAdminChallenge.info.yml')
const codefixFile = path.resolve('data/static/codefixes/loginAdminChallenge_1.ts')
const infoBackup = fs.readFileSync(infoFile)
const codefixBackup = fs.readFileSync(codefixFile)

// A JavaScript function type whose body writes a marker only if it is invoked.
// The marker path comes from the environment so the document contains no fixed path.
const infoWithJavaScriptFunction = [
  'fixes:',
  '  - id: 1',
  '    explanation:',
  '      toString: !<tag:yaml.org,2002:js/function> "function () { var fs = process.getBuiltinModule(\'node:fs\'); fs.writeFileSync(process.env.RSN_MARKER, \'ran\'); return \'x\' }"',
  'hints: []',
  ''
].join('\n')

function markerPath () {
  return path.join(os.tmpdir(), `rsn-yaml-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`)
}

function installPayload () {
  fs.appendFileSync(codefixFile, '\n// safety-net probe\n')
  fs.writeFileSync(infoFile, infoWithJavaScriptFunction)
}

function restore () {
  fs.writeFileSync(infoFile, infoBackup)
  fs.writeFileSync(codefixFile, codefixBackup)
  delete process.env.RSN_MARKER
}

void describe('refactoring safety net challenge info YAML', () => {
  afterEach(() => {
    restore()
  })

  void it('does not execute a JavaScript function from the info file when the safety-net command runs', () => {
    const marker = markerPath()
    fs.rmSync(marker, { force: true })
    process.env.RSN_MARKER = marker
    try {
      installPayload()
      const result = spawnSync(process.execPath, ['--import', 'tsx', 'rsn/rsn.ts'], {
        cwd: path.resolve('.'),
        env: { ...process.env, RSN_MARKER: marker },
        encoding: 'utf8',
        timeout: 120000
      })
      assert.equal(result.error, undefined)
      assert.equal(typeof result.status, 'number')
      const output = `${result.stdout}\n${result.stderr}`
      assert.match(output, /loginAdminChallenge|Refactoring Safety Net|unknown tag|YAMLException/)
      assert.equal(fs.existsSync(marker), false)
    } finally {
      fs.rmSync(marker, { force: true })
    }
  })

  void it('does not execute a JavaScript function from the info file when a changed codefix diff is printed', async () => {
    const marker = markerPath()
    fs.rmSync(marker, { force: true })
    process.env.RSN_MARKER = marker
    try {
      installPayload()
      try {
        const diff = await computeChallengeDiff('loginAdminChallenge_1.ts')
        if (diff != null) printChallengeDiff(diff)
      } catch (error) {
        void error
      }
      assert.equal(fs.existsSync(marker), false)
    } finally {
      fs.rmSync(marker, { force: true })
    }
  })
})
