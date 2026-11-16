/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as http from 'node:http'
import path from 'node:path'
import { createRequire } from 'node:module'
import type { Server as IoServer } from 'socket.io'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'

const require = createRequire(path.join(process.cwd(), 'package.json'))
const engineEntry = require.resolve('engine.io')
// Same package engine.io loads for the HTTP upgrade, not another copy of ws.
const WebSocket = require(require.resolve('ws', {
  paths: [path.dirname(engineEntry)]
}))

// Patched ws 7.5.11 defaults maxFragments to 128 * 1024 and closes with 1008
// on the next 1-byte fragment. engine.io 4.1.2 only sets maxPayload from
// maxHttpBufferSize (1e6), so this count is still under the payload-byte cap.
const PATCHED_FRAGMENT_CAP = 128 * 1024
const FLOOD_FRAGMENTS = PATCHED_FRAGMENT_CAP + 1
const SHORT_FRAGMENTS = 32

const globalWithIo = global as typeof globalThis & { io: IoServer }

interface SocketClient {
  readonly OPEN: number
  readonly CLOSED: number
  readyState: number
  _socket: { localPort: number }
  once: (event: string, listener: (...args: any[]) => void) => void
  on: (event: string, listener: (...args: any[]) => void) => void
  send: (data: Buffer, options: { fin: boolean }, cb: (err?: Error) => void) => void
  close: () => void
  terminate: () => void
}

function retainedFragments (io: IoServer, remotePort: number): number | null {
  const clients = (io as any).engine.clients as Record<string, any>
  for (const id of Object.keys(clients)) {
    const socket = clients[id].transport?.socket
    if (socket?._socket?.remotePort === remotePort) {
      return socket._receiver._fragments.length as number
    }
  }
  return null
}

function sendOneByteFragments (ws: SocketClient, count: number): Promise<void> {
  const data = Buffer.from([0x41])
  const options = { fin: false }
  return new Promise((resolve, reject) => {
    let sent = 0
    const pump = () => {
      let batch = 0
      const step = () => {
        if (ws.readyState !== WebSocket.OPEN) {
          resolve()
          return
        }
        if (sent >= count) {
          resolve()
          return
        }
        if (batch >= 64) {
          setImmediate(pump)
          return
        }
        batch++
        sent++
        ws.send(data, options, (err) => {
          if (err) {
            if (ws.readyState !== WebSocket.OPEN) resolve()
            else reject(err)
            return
          }
          step()
        })
      }
      step()
    }
    pump()
  })
}

async function openUnauthenticated (port: number): Promise<SocketClient> {
  const ws = new WebSocket(
    `ws://127.0.0.1:${port}/socket.io/?EIO=4&transport=websocket`
  ) as SocketClient
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => { resolve() })
    ws.once('error', reject)
  })
  return ws
}

async function waitForFragments (io: IoServer, remotePort: number, expected: number): Promise<number | null> {
  const deadline = Date.now() + 2000
  let seen: number | null = null
  while (Date.now() < deadline) {
    seen = retainedFragments(io, remotePort)
    if (seen === expected) return seen
    await new Promise((resolve) => { setTimeout(resolve, 10) })
  }
  return seen
}

void describe('websocket small-fragment handling', () => {
  let server: http.Server
  let port: number
  let io: IoServer

  before(async () => {
    server = http.createServer()
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => { resolve() })
    })
    const addr = server.address()
    if (addr === null || typeof addr === 'string') {
      throw new Error('expected the test server to listen on a TCP port')
    }
    port = addr.port
    registerWebsocketEvents(server)
    io = globalWithIo.io
  })

  after(() => {
    io.close()
    server.close()
  })

  void it('closes an unauthenticated one-byte fragment flood at the patched cap', async () => {
    const probe = await openUnauthenticated(port)
    const probePort = probe._socket.localPort
    assert.ok((io as any).engine.clientsCount >= 1)
    await sendOneByteFragments(probe, SHORT_FRAGMENTS)
    const held = await waitForFragments(io, probePort, SHORT_FRAGMENTS)
    assert.equal(probe.readyState, WebSocket.OPEN)
    assert.equal(held, SHORT_FRAGMENTS)
    probe.terminate()

    const flood = await openUnauthenticated(port)
    const floodPort = flood._socket.localPort
    let closeCode: number | null = null
    flood.on('close', (code: number) => { closeCode = code })
    await sendOneByteFragments(flood, FLOOD_FRAGMENTS)
    if (closeCode === null) {
      await new Promise((resolve) => { setTimeout(resolve, 500) })
    }
    const stillHeld = retainedFragments(io, floodPort)
    assert.equal(
      closeCode,
      1008,
      `fragment flood left the socket open (close=${String(closeCode)}, retained=${String(stillHeld)})`
    )
    flood.terminate()
  })
})
