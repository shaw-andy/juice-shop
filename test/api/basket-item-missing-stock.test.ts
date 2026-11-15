/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'

// The API test runner installs its own unhandledRejection listener, which
// stops Node from exiting. These probes run in a fresh process so a rejected
// stock check is visible as a process exit.
function runProbe (mode: string) {
  return new Promise<{ code: number | null, stdout: string, stderr: string }>((resolve) => {
    const child = spawn(process.execPath, [
      '--import', './test/api/helpers/test-env.mjs',
      '--import', 'tsx',
      './test/api/helpers/missing-stock-probe.ts',
      mode
    ], {
      cwd: process.cwd(),
      env: { ...process.env, NODE_ENV: 'test' }
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString() })
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString() })
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
    }, 90000)
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
  })
}

function probeResult (stdout: string) {
  const line = stdout.split('\n').find((entry) => entry.startsWith('PROBE_RESULT '))
  assert.ok(line, 'probe exited without a result')
  return JSON.parse(line.slice('PROBE_RESULT '.length)) as Record<string, unknown>
}

void describe('basket item stock check', () => {
  void it('keeps the cart line on the product id the stock check validated', async () => {
    const result = await runProbe('customer')
    assert.equal(result.code, 0, `customer probe failed\n${result.stderr.slice(-4000)}\n${result.stdout.slice(-4000)}`)
    const body = probeResult(result.stdout)
    assert.equal(body.role, 'customer')
    assert.equal(body.uncheckedProductPersisted, false)
    assert.equal(body.followUpStatus, 200)
    assert.equal(body.userStillPresent, true)
    assert.notEqual(body.checkedProductId, body.uncheckedProductId)
  }, { timeout: 120000 })

  void it('returns an error when updating a line whose product has no stock row and keeps serving', async () => {
    const result = await runProbe('update')
    assert.equal(result.code, 0, `update probe failed\n${result.stderr.slice(-4000)}\n${result.stdout.slice(-4000)}`)
    const body = probeResult(result.stdout)
    assert.ok(body.putStatus === 400 || body.putStatus === 500)
    assert.equal(body.quantity, 1)
    assert.equal(body.followUpStatus, 200)
    assert.equal(body.userStillPresent, true)
  }, { timeout: 120000 })
})
