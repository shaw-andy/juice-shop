/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import config from 'config'
import type { Product as ProductConfig } from '../../lib/config.schema'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const serverScript = path.join(repoRoot, 'test/api/helpers/listen-test-app.ts')
const tamperUrl = config.get<ProductConfig[]>('products').find((product) => product.urlForProductTamperingChallenge != null)?.urlForProductTamperingChallenge

assert.equal(typeof tamperUrl, 'string')

interface RunningApp {
  child: ChildProcessWithoutNullStreams
  port: number
  stderr: () => string
  stop: () => Promise<void>
}

function waitForExit (child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<number | null> {
  if (child.exitCode !== null) {
    return Promise.resolve(child.exitCode)
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.off('exit', onExit)
      resolve(child.exitCode)
    }, timeoutMs)
    const onExit = (code: number | null) => {
      clearTimeout(timer)
      resolve(code)
    }
    child.once('exit', onExit)
  })
}

async function startApp (env: Record<string, string> = {}): Promise<RunningApp> {
  const child = spawn(process.execPath, ['--import', 'tsx', serverScript], {
    cwd: repoRoot,
    env: { ...process.env, NODE_ENV: 'test', ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let stderr = ''
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk
  })
  const port = await new Promise<number>((resolve, reject) => {
    let stdout = ''
    const timer = setTimeout(() => {
      reject(new Error(`Test server did not start\n${stderr.slice(-2000)}`))
    }, 60000)
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk
      const match = stdout.match(/READY (\d+)/)
      if (match != null) {
        clearTimeout(timer)
        resolve(Number(match[1]))
      }
    })
    child.once('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`Test server exited during startup with code ${code}\n${stderr.slice(-2000)}`))
    })
  })

  return {
    child,
    port,
    stderr: () => stderr,
    stop: async () => {
      if (child.exitCode !== null || child.signalCode != null) {
        return
      }
      child.kill('SIGTERM')
      await waitForExit(child, 5000)
      if (child.exitCode === null) {
        child.kill('SIGKILL')
      }
    }
  }
}

async function readBody (response: Response): Promise<any> {
  const text = await response.text()
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

async function assertStillServing (app: RunningApp, detail: string) {
  const exitCode = await waitForExit(app.child, 1500)
  assert.equal(exitCode, null, `${detail}\n${app.stderr().slice(-2500)}`)
  const challenges = await fetch(`http://127.0.0.1:${app.port}/api/Challenges`)
  assert.equal(challenges.status, 200)
  const body = await readBody(challenges)
  assert.equal(Array.isArray(body?.data), true)
}

const followPaths = [
  '/api/Products',
  '/rest/products/search?q=',
  '/api/Challenges',
  '/score-board'
]

void describe('null tampering-product description', { concurrency: 1 }, () => {
  for (const followPath of followPaths) {
    void it(`keeps serving after an anonymous null description and ${followPath}`, async () => {
      const app = await startApp()
      try {
        const list = await fetch(`http://127.0.0.1:${app.port}/api/Products`)
        assert.equal(list.status, 200)
        const listed = await readBody(list)
        const product = listed?.data?.find((item: { description?: unknown }) => {
          return typeof item.description === 'string' && item.description.includes(tamperUrl)
        })
        assert.ok(product, 'startup did not seed the tampering product with its link')
        assert.equal(typeof product.id, 'number')

        const put = await fetch(`http://127.0.0.1:${app.port}/api/Products/${product.id}`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ description: null })
        })
        const updated = await readBody(put)
        const storedNull = put.status === 200 && updated?.data?.description === null
        if (put.status === 200) {
          assert.equal(updated?.data?.id, product.id)
        }

        let triggerFailed: unknown
        try {
          await fetch(`http://127.0.0.1:${app.port}${followPath}`)
        } catch (err) {
          triggerFailed = err
        }

        await assertStillServing(
          app,
          `server exited after PUT description null on product ${product.id} (storedNull=${storedNull}) and GET ${followPath}\n${triggerFailed instanceof Error ? triggerFailed.message : ''}`
        )
      } finally {
        await app.stop()
      }
    })
  }

  void it('keeps serving when the stored description is null before the challenge check reloads it', async () => {
    const app = await startApp({ NULL_TAMPER_PRODUCT: '1' })
    try {
      let triggerFailed: unknown
      try {
        await fetch(`http://127.0.0.1:${app.port}/api/Challenges`)
      } catch (err) {
        triggerFailed = err
      }
      await assertStillServing(
        app,
        `server exited after a request reloaded a tampering product whose stored description was null\n${triggerFailed instanceof Error ? triggerFailed.message : ''}`
      )
    } finally {
      await app.stop()
    }
  })
})
