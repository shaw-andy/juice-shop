/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
process.chdir(root)

interface Counts { frontendReads: number, backendReads: number, parses: number, directoryLists: number, wrapperHits: number }
interface ProbeApi {
  snapshot: () => Counts
  resetCounts: () => void
  setWatching: (value: boolean) => void
  wrapperHits: number
}

const probe = (globalThis as { __translationReadProbe?: ProbeApi }).__translationReadProbe
if (probe === undefined) {
  throw new Error('Translation read probe was not installed. Load test/api/helpers/count-translation-reads.mjs before the application.')
}

function ensureRuntimeFiles () {
  const destination = path.resolve('frontend/dist/frontend/assets/i18n')
  if (!fs.existsSync(path.join(destination, 'en.json'))) {
    fs.mkdirSync(destination, { recursive: true })
    fs.cpSync(path.resolve('frontend/src/assets/i18n'), destination, { recursive: true })
  }
  const required = [
    'build/server.js',
    'frontend/dist/frontend/index.html',
    'frontend/dist/frontend/styles.css',
    'frontend/dist/frontend/main.js',
    'frontend/dist/frontend/polyfills.js',
    'frontend/dist/frontend/hacking-instructor-placeholder.js'
  ]
  for (const relative of required) {
    const full = path.resolve(relative)
    if (!fs.existsSync(full)) {
      fs.mkdirSync(path.dirname(full), { recursive: true })
      fs.writeFileSync(full, '')
    }
  }
}

function summarize (res: { status: number, body: unknown }, counts: Counts) {
  const body = Array.isArray(res.body) ? res.body as Array<{ key?: string, percentage?: number }> : []
  return {
    status: res.status,
    languages: body.length,
    counts,
    hasEnglish: body.some((lang) => lang.key === 'en'),
    body
  }
}

async function main () {
  const promises = await import('node:fs/promises')
  const hitsBefore = probe.wrapperHits
  await promises.readFile(path.resolve('package.json'), 'utf8')
  if (probe.wrapperHits <= hitsBefore) {
    throw new Error('The readFile wrapper was not called')
  }

  ensureRuntimeFiles()
  probe.setWatching(true)
  const { createTestApp } = await import('./setup')
  const { app } = await createTestApp()
  const startup = probe.snapshot()
  probe.resetCounts()

  const request = (await import('supertest')).default
  const first = await request(app).get('/rest/languages')
  const afterFirst = probe.snapshot()
  probe.resetCounts()

  const secondStarted = performance.now()
  const second = await request(app).get('/rest/languages')
  const secondElapsedMs = performance.now() - secondStarted
  const afterSecond = probe.snapshot()
  probe.setWatching(false)

  const firstSummary = summarize(first, afterFirst)
  const secondSummary = summarize(second, afterSecond)
  const result = {
    startup,
    first: { status: firstSummary.status, languages: firstSummary.languages, counts: firstSummary.counts, hasEnglish: firstSummary.hasEnglish },
    second: { status: secondSummary.status, languages: secondSummary.languages, counts: secondSummary.counts, hasEnglish: secondSummary.hasEnglish, elapsedMs: secondElapsedMs },
    variedPercentage: firstSummary.body.some((lang) => typeof lang.percentage === 'number' && lang.percentage > 0 && lang.percentage < 100)
  }
  console.log('LANGUAGES_REREAD_RESULT ' + JSON.stringify(result))
}

main().catch((err: unknown) => {
  console.error(err)
  process.exit(2)
})
