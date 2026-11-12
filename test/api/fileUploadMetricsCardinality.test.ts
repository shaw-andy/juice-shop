/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import * as Prometheus from 'prom-client'
import { createTestApp } from './helpers/setup'
import * as metricsRoute from '../../routes/metrics'

const DISTINCT_TYPES = 12
const MAX_NEW_FILE_TYPE_SERIES = 1
const UPLOAD_DIR = path.resolve('frontend/dist/frontend/assets/public/images/uploads')

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
  // createTestApp clears the global registry. Production keeps the counters
  // registered for the life of the process; put that same registry state back
  // before any upload so GET /metrics observes the middleware's counters.
  metricsRoute.reRegisterMetrics()
}, { timeout: 60000 })

void describe('file upload Prometheus label cardinality', { concurrency: 1 }, () => {
  void it('anonymous complaint uploads do not keep a success series per client Content-Type', async () => {
    const beforeUploads = await fileTypeLabels('file_uploads_count')
    const successTypes = distinctTypes('application/x-jstps')

    for (const contentType of successTypes) {
      await request(app)
        .post('/file-upload')
        .attach('file', Buffer.from('complaint'), { filename: 'note.pdf', contentType })
    }

    await assertClientTypesStayBounded('file_uploads_count', beforeUploads, successTypes)
  })

  void it('anonymous complaint uploads do not keep an error series per client Content-Type', async () => {
    const beforeErrors = await fileTypeLabels('file_upload_errors')
    const errorTypes = distinctTypes('application/x-jstpe')

    for (const contentType of errorTypes) {
      await request(app)
        .post('/file-upload')
        .attach('file', Buffer.from('<c/>'), { filename: 'note.xml', contentType })
    }

    await assertClientTypesStayBounded('file_upload_errors', beforeErrors, errorTypes)
  })

  void it('anonymous profile image uploads do not keep a series per client Content-Type', async () => {
    const beforeErrors = await fileTypeLabels('file_upload_errors')
    const profileTypes = distinctTypes('application/x-jstpp')

    for (const contentType of profileTypes) {
      await request(app)
        .post('/profile/image/file')
        .attach('file', Buffer.from('not-an-image'), { filename: 'avatar.bin', contentType })
    }

    await assertClientTypesStayBounded('file_upload_errors', beforeErrors, profileTypes)
  })

  void it('memory uploads do not keep a series per client Content-Type or write a file', async () => {
    const beforeUploads = await fileTypeLabels('file_uploads_count')
    const beforeErrors = await fileTypeLabels('file_upload_errors')
    const beforeFiles = await uploadFileNames()
    const memoryTypes = distinctTypes('application/x-jstpm')

    for (const contentType of memoryTypes) {
      await request(app)
        .post('/rest/memories')
        .attach('image', Buffer.from('not-an-image'), { filename: 'memory.png', contentType })
    }

    const afterFiles = await uploadFileNames()

    await assertClientTypesStayBounded('file_uploads_count', beforeUploads, memoryTypes)
    await assertClientTypesStayBounded('file_upload_errors', beforeErrors, memoryTypes)
    assert.deepEqual(afterFiles.filter(name => !beforeFiles.includes(name)), [])
  })
})

function distinctTypes (prefix: string): string[] {
  return Array.from({ length: DISTINCT_TYPES }, (_unused, index) => `${prefix}${index}`)
}

async function assertClientTypesStayBounded (metricName: string, before: string[], attackerTypes: string[]) {
  const after = await fileTypeLabels(metricName)
  const metrics = await request(app).get('/metrics')
  const known = new Set(before)
  const added = [...new Set(after)].filter(type => !known.has(type))
  const inCounter = attackerTypes.filter(type => added.includes(type))
  const inMetricsPage = attackerTypes.filter(type => metrics.text.includes(`file_type="${type}"`))

  assert.equal(metrics.status, 200)
  assert.deepEqual({
    metricName,
    inCounter,
    inMetricsPage,
    withinCap: added.length <= MAX_NEW_FILE_TYPE_SERIES
  }, {
    metricName,
    inCounter: [],
    inMetricsPage: [],
    withinCap: true
  })
}

async function fileTypeLabels (name: string): Promise<string[]> {
  const metric = Prometheus.register.getSingleMetric(name) as { get?: () => Promise<{ values: Array<{ labels: Record<string, string | number> }> }> } | undefined
  if (metric?.get == null) return []
  const snapshot = await metric.get()
  return snapshot.values
    .map(value => value.labels.file_type)
    .filter((type): type is string => typeof type === 'string')
}

async function uploadFileNames (): Promise<string[]> {
  try {
    return await fs.readdir(UPLOAD_DIR)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
    throw error
  }
}
