/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

interface Counts { frontendReads: number, backendReads: number, parses: number, directoryLists: number }
interface Result {
  startup: Counts
  first: { status: number, languages: number, counts: Counts, hasEnglish: boolean }
  second: { status: number, languages: number, counts: Counts, elapsedMs: number, hasEnglish: boolean }
  variedPercentage: boolean
}

function runProbe (): Promise<{ code: number | null, output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      '--import', path.join(root, 'test/api/helpers/test-env.mjs'),
      '--import', path.join(root, 'test/api/helpers/count-translation-reads.mjs'),
      '--import', 'tsx',
      path.join(root, 'test/api/helpers/languages-reread-probe.ts')
    ], {
      cwd: root,
      env: { ...process.env, NODE_ENV: 'test' }
    })
    const chunks: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk))
    child.stderr.on('data', (chunk: Buffer) => chunks.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => {
      resolve({ code, output: Buffer.concat(chunks).toString('utf8') })
    })
  })
}

void describe('GET /rest/languages', () => {
  void it('serves the language list without reading and parsing every translation file again', async () => {
    const { code, output } = await runProbe()
    const line = output.split('\n').find((entry) => entry.startsWith('LANGUAGES_REREAD_RESULT '))
    assert.equal(code, 0, output)
    assert.ok(line, output)
    const result = JSON.parse(line.slice('LANGUAGES_REREAD_RESULT '.length)) as Result
    const observedFrontendReads = result.startup.frontendReads + result.first.counts.frontendReads

    assert.equal(result.first.status, 200)
    assert.equal(result.second.status, 200)
    assert.equal(result.first.hasEnglish, true)
    assert.equal(result.second.hasEnglish, true)
    assert.ok(result.first.languages >= 40, `language list was ${result.first.languages}`)
    assert.equal(result.second.languages, result.first.languages)
    assert.equal(result.variedPercentage, true)
    assert.ok(observedFrontendReads >= 40, `translation files were read ${observedFrontendReads} times; the probe did not see the route read them`)
    assert.equal(result.second.counts.frontendReads, 0, JSON.stringify(result))
    assert.equal(result.second.counts.backendReads, 0, JSON.stringify(result))
    assert.equal(result.second.counts.parses, 0, JSON.stringify(result))
  }, { timeout: 180000 })
})
