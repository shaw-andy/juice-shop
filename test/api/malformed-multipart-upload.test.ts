/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'

const repoRoot = path.resolve(__dirname, '../..')
const serverScript = path.resolve(__dirname, 'helpers/malformed-multipart-server.ts')
const uploadDir = path.resolve(repoRoot, 'frontend/dist/frontend/assets/public/images/uploads')

const multipartRoutes = [
  { urlPath: '/file-upload', field: 'file' },
  { urlPath: '/profile/image/file', field: 'file' },
  { urlPath: '/profile/image/url', field: 'file' },
  { urlPath: '/rest/memories', field: 'image' }
]

function truncatedFilePart (field: string) {
  const boundary = '----juiceshopbound'
  // A file part (application/octet-stream) with no filename, and no closing
  // boundary. busboy leaves that file stream open, then destroys it with the
  // "Unexpected end of form" error when the request ends.
  const body = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="${field}"\r\n` +
    'Content-Type: application/octet-stream\r\n' +
    '\r\n' +
    'AAAA\r\n'
  )
  return { boundary, body }
}

function listUploadFiles () {
  if (!fs.existsSync(uploadDir)) return []
  return fs.readdirSync(uploadDir).sort()
}

function postTruncatedMultipart (port: number, urlPath: string, field: string) {
  const { boundary, body } = truncatedFilePart(field)
  return new Promise<{ status: number, body: string }>((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: urlPath,
      method: 'POST',
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary}`,
        'content-length': body.length
      }
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => chunks.push(chunk))
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') })
      })
    })
    req.setTimeout(10000, () => {
      req.destroy(new Error('timed out waiting for a response'))
    })
    req.on('error', reject)
    req.end(body)
  })
}

function getPath (port: number, urlPath: string) {
  return new Promise<{ status: number }>((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: urlPath,
      method: 'GET'
    }, res => {
      res.resume()
      res.on('end', () => resolve({ status: res.statusCode ?? 0 }))
    })
    req.setTimeout(10000, () => {
      req.destroy(new Error('timed out waiting for a response'))
    })
    req.on('error', reject)
    req.end()
  })
}

async function startServer () {
  const child = spawn(process.execPath, [
    '--import', './test/api/helpers/test-env.mjs',
    '--import', 'tsx',
    serverScript
  ], {
    cwd: repoRoot,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let stdout = ''
  let stderr = ''
  let exitCode: number | null = null
  child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8') })
  child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8') })
  child.on('exit', code => { exitCode = code ?? 0 })

  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`server did not become ready\nstdout:\n${stdout}\nstderr:\n${stderr}`))
    }, 90000)
    const check = () => {
      if (exitCode !== null) {
        clearTimeout(timer)
        reject(new Error(`server exited ${exitCode} before listening\nstdout:\n${stdout}\nstderr:\n${stderr}`))
        return
      }
      const match = stdout.match(/MULTER_TEST_READY (\d+)/)
      if (match != null) {
        clearTimeout(timer)
        resolve(Number(match[1]))
        return
      }
      setTimeout(check, 50)
    }
    check()
  })

  return {
    child,
    port,
    exitCode: () => exitCode,
    output: () => `stdout:\n${stdout.slice(-2000)}\nstderr:\n${stderr.slice(-2000)}`
  }
}

async function stopServer (child: ChildProcess) {
  if (child.exitCode != null) return
  child.kill('SIGKILL')
  await new Promise(resolve => child.once('exit', resolve))
}

void describe('malformed multipart uploads', () => {
  for (const route of multipartRoutes) {
    void it(`POST ${route.urlPath} rejects a truncated file part with no filename without crashing`, async () => {
      const before = listUploadFiles()
      let server: Awaited<ReturnType<typeof startServer>> | undefined
      try {
        server = await startServer()
        let response: { status: number, body: string }
        try {
          response = await postTruncatedMultipart(server.port, route.urlPath, route.field)
        } catch (err) {
          await new Promise(resolve => setTimeout(resolve, 300))
          const message = err instanceof Error ? err.message : String(err)
          assert.fail(
            `${route.urlPath} must answer the malformed multipart request with an HTTP error while the process keeps running. ` +
            `Request failed (${message}), child exit ${String(server.exitCode())}.\n${server.output()}`
          )
        }
        await new Promise(resolve => setTimeout(resolve, 300))
        assert.ok(
          response.status >= 400 && response.status <= 599,
          `${route.urlPath} must refuse the malformed upload, got ${response.status}: ${response.body.slice(0, 300)}`
        )
        assert.equal(
          server.exitCode(),
          null,
          `${route.urlPath} must keep the process alive after the malformed upload.\n${server.output()}`
        )
        assert.deepEqual(
          listUploadFiles(),
          before,
          `${route.urlPath} must not create an uploaded file before refusing the malformed request`
        )
        const follow = await getPath(server.port, '/rest/memories')
        assert.equal(follow.status, 200, `${route.urlPath} left the server unable to answer a later request`)
        assert.equal(server.exitCode(), null, `${route.urlPath} crashed after the follow-up request`)
      } finally {
        if (server != null) await stopServer(server.child)
      }
    }, { timeout: 120000 })
  }
})
