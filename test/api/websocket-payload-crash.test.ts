/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { io as ioClient, type Socket } from 'socket.io-client'

const serverScript = fileURLToPath(new URL('./helpers/websocket-payload-server.ts', import.meta.url))
const testEnv = fileURLToPath(new URL('./helpers/test-env.mjs', import.meta.url))
const children: ChildProcessWithoutNullStreams[] = []

interface RunningServer {
  child: ChildProcessWithoutNullStreams
  port: number
  output: () => string
}

async function startServer (): Promise<RunningServer> {
  const child = spawn(process.execPath, [
    '--import', testEnv,
    '--import', 'tsx',
    serverScript
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NODE_ENV: 'test' }
  }) as ChildProcessWithoutNullStreams
  children.push(child)
  let output = ''
  child.stdout.on('data', (chunk: Buffer) => {
    output += chunk.toString()
  })
  child.stderr.on('data', (chunk: Buffer) => {
    output += chunk.toString()
  })

  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`socket payload server did not become ready\n${output}`))
    }, 60000)
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      clearTimeout(timer)
      reject(new Error(`socket payload server exited before ready (${code ?? signal})\n${output}`))
    }
    child.once('exit', onExit)
    child.stdout.on('data', () => {
      const match = output.match(/READY (\d+)/)
      if (match != null) {
        clearTimeout(timer)
        child.removeListener('exit', onExit)
        resolve(Number(match[1]))
      }
    })
  })

  return {
    child,
    port,
    output: () => output
  }
}

function connect (port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = ioClient(`http://127.0.0.1:${port}`, {
      reconnection: false,
      forceNew: true,
      timeout: 10000
    })
    const timer = setTimeout(() => {
      socket.close()
      reject(new Error('socket connection timed out'))
    }, 10000)
    socket.once('connect', () => {
      clearTimeout(timer)
      resolve(socket)
    })
    socket.once('connect_error', (error: Error) => {
      clearTimeout(timer)
      socket.close()
      reject(error)
    })
  })
}

async function emitAndRequireProcessToStayUp (eventName: string, payload: unknown) {
  const server = await startServer()
  const socket = await connect(server.port)
  try {
    socket.emit(eventName, payload)
    const exit = await Promise.race([
      once(server.child, 'exit').then(([code, signal]) => ({ code, signal })),
      new Promise<null>(resolve => {
        setTimeout(() => { resolve(null) }, 1000)
      })
    ])
    assert.equal(
      exit,
      null,
      `${eventName} payload ${JSON.stringify(payload)} exited the server: ${JSON.stringify(exit)}\n${server.output()}`
    )
    const response = await fetch(`http://127.0.0.1:${server.port}/health`, {
      signal: AbortSignal.timeout(2000)
    })
    assert.equal(response.status, 200)
  } finally {
    socket.close()
    if (server.child.exitCode == null && server.child.signalCode == null) {
      server.child.kill('SIGKILL')
    }
  }
}

void describe('websocket challenge payloads', { concurrency: 1 }, () => {
  after(() => {
    for (const child of children) {
      if (child.exitCode == null && child.signalCode == null) {
        child.kill('SIGKILL')
      }
    }
  })

  void it('keeps running when verifyLocalXssChallenge receives a string', async () => {
    await emitAndRequireProcessToStayUp('verifyLocalXssChallenge', 'plain text')
  })

  void it('keeps running when verifySvgInjectionChallenge receives a string', async () => {
    await emitAndRequireProcessToStayUp('verifySvgInjectionChallenge', 'plain text')
  })

  void it('keeps running when verifyLocalXssChallenge receives a number', async () => {
    await emitAndRequireProcessToStayUp('verifyLocalXssChallenge', 0)
  })

  void it('keeps running when verifyLocalXssChallenge receives an object', async () => {
    await emitAndRequireProcessToStayUp('verifyLocalXssChallenge', { injected: true })
  })

  void it('keeps running when verifyLocalXssChallenge receives a boolean', async () => {
    await emitAndRequireProcessToStayUp('verifyLocalXssChallenge', true)
  })

  void it('keeps running when verifySvgInjectionChallenge receives a number', async () => {
    await emitAndRequireProcessToStayUp('verifySvgInjectionChallenge', 0)
  })

  void it('keeps running when verifySvgInjectionChallenge receives an object', async () => {
    await emitAndRequireProcessToStayUp('verifySvgInjectionChallenge', { to: 'https://cataas.com/cat' })
  })

  void it('keeps running when verifySvgInjectionChallenge receives an array', async () => {
    await emitAndRequireProcessToStayUp('verifySvgInjectionChallenge', ['../../redirect'])
  })

  void it('keeps running when verifySvgInjectionChallenge receives a boolean', async () => {
    await emitAndRequireProcessToStayUp('verifySvgInjectionChallenge', false)
  })
})
