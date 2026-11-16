/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as http from 'node:http'
import { createRequire } from 'node:module'
import { type Server } from 'socket.io'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'

const require = createRequire(import.meta.url)
const WebSocket = require('ws') as typeof import('ws')

// socket.io-parser 4.2.7 refuses a declared attachment count above this before it
// creates a reconstructor. The parser this server loads (4.0.5) stores the count
// and appends every following binary frame.
const PATCHED_MAX_ATTACHMENTS = 10
const CHUNK = Buffer.from('attachment-bytes')
const DISALLOWED_ORIGIN = 'https://attacker.example'

const globalWithSocketIO = global as typeof globalThis & { io: Server }

interface AttachmentDecoder {
  reconstructor?: { buffers?: Array<{ length: number }> } | null
}

interface LiveSocket {
  client: { decoder: AttachmentDecoder }
  connected: boolean
  disconnected: boolean
  on: (event: string, listener: (...args: unknown[]) => void) => void
}

let server: http.Server
let port: number

before(async () => {
  server = http.createServer((_req, res) => {
    res.writeHead(404)
    res.end()
  })
  registerWebsocketEvents(server)
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => { resolve() })
  })
  const addr = server.address()
  if (addr == null || typeof addr === 'string') {
    throw new Error('test server did not bind a port')
  }
  port = addr.port
})

after(async () => {
  globalWithSocketIO.io?.close()
  if (server.listening) {
    await new Promise<void>((resolve) => {
      server.close(() => { resolve() })
    })
  }
})

function heldAttachmentBytes (socket: LiveSocket): number {
  const buffers = socket.client.decoder.reconstructor?.buffers
  if (!Array.isArray(buffers)) return 0
  let total = 0
  for (const buf of buffers) total += buf.length
  return total
}

async function waitUntil (predicate: () => boolean, timeoutMs = 2000): Promise<boolean> {
  const start = Date.now()
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) return false
    await new Promise((resolve) => { setImmediate(resolve) })
  }
  return true
}

function nextSocket (): Promise<LiveSocket> {
  return new Promise((resolve) => {
    globalWithSocketIO.io.once('connection', (socket) => {
      socket.on('error', () => {})
      resolve(socket as unknown as LiveSocket)
    })
  })
}

function binaryEventFrame (count: number, eventName: string, placeholders: boolean): string {
  const data: unknown[] = [eventName]
  if (placeholders) {
    for (let i = 0; i < count; i++) {
      data.push({ _placeholder: true, num: i })
    }
  }
  // Engine.IO message (4) + Socket.IO BINARY_EVENT (5) + attachment count.
  return `45${count}-${JSON.stringify(data)}`
}

function binaryAckFrame (count: number): string {
  return `46${count}-[]`
}

async function openWebSocket (): Promise<{ ws: WebSocket, socket: LiveSocket }> {
  const socketPromise = nextSocket()
  const ws = new WebSocket(`ws://127.0.0.1:${port}/socket.io/?EIO=4&transport=websocket`, {
    headers: { Origin: DISALLOWED_ORIGIN }
  })
  const textMessages: string[] = []
  ws.on('message', (data, isBinary) => {
    if (isBinary) return
    const text = data.toString()
    if (text === '2') {
      ws.send('3')
      return
    }
    textMessages.push(text)
  })
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => { resolve() })
    ws.once('error', reject)
  })
  const opened = await waitUntil(() => textMessages.some((message) => message.startsWith('0')))
  assert.equal(opened, true, 'engine.io handshake did not arrive')
  ws.send('40')
  const socket = await socketPromise
  const connected = await waitUntil(() => textMessages.some((message) => message.startsWith('40')))
  assert.equal(connected, true, 'socket.io namespace connect was not acknowledged')
  return { ws, socket }
}

async function assertCountIsRejected (options: {
  socket: LiveSocket
  declared: number
  sendHeader: () => Promise<void>
  sendChunk: () => Promise<void>
  isClosed: () => boolean
  delivered: () => number
  // Polling applies the packet before the POST response returns. Websocket delivery is async.
  headerIsAppliedBeforeReturn: boolean
  settle?: () => Promise<void>
}): Promise<void> {
  let peak = 0
  const sample = () => {
    peak = Math.max(peak, heldAttachmentBytes(options.socket))
  }
  const headerWasAccepted = async () => {
    if (options.headerIsAppliedBeforeReturn) return options.socket.client.decoder.reconstructor != null
    return await waitUntil(() => {
      sample()
      return options.isClosed() || options.socket.client.decoder.reconstructor != null
    })
  }
  await options.sendHeader()
  sample()
  const accepted = await headerWasAccepted()
  sample()
  if (accepted && !options.isClosed()) {
    const chunks = 4
    for (let i = 0; i < chunks; i++) {
      await options.sendChunk()
      sample()
      if (!options.headerIsAppliedBeforeReturn) {
        await waitUntil(() => {
          sample()
          return options.isClosed() || heldAttachmentBytes(options.socket) >= (i + 1) * CHUNK.length
        })
      }
      sample()
    }
  }
  if (options.settle != null && peak === 0) await options.settle()
  await waitUntil(() => options.isClosed() || peak > 0)
  sample()
  assert.equal(peak, 0, `parser retained ${peak} attachment bytes for a declared count of ${options.declared}`)
  assert.equal(options.delivered(), 0, 'application handler must not run for an over-limit binary packet')
  assert.equal(options.isClosed(), true, 'connection must close when the declared attachment count is over the limit')
}

function request (method: string, path: string, body?: string): Promise<{ status: number, body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        Origin: DISALLOWED_ORIGIN,
        'Content-Type': 'text/plain;charset=UTF-8',
        ...(body != null ? { 'Content-Length': Buffer.byteLength(body) } : {})
      }
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') })
      })
    })
    req.on('error', reject)
    if (body != null) req.write(body)
    req.end()
  })
}

async function openPolling (): Promise<{ sid: string, socket: LiveSocket }> {
  const socketPromise = nextSocket()
  const handshake = await request('GET', '/socket.io/?EIO=4&transport=polling')
  assert.equal(handshake.status, 200)
  assert.equal(handshake.body.startsWith('0'), true, `unexpected handshake ${handshake.body}`)
  const open = JSON.parse(handshake.body.slice(1)) as { sid: string }
  const sid = encodeURIComponent(open.sid)
  const connect = await request('POST', `/socket.io/?EIO=4&transport=polling&sid=${sid}`, '40')
  assert.equal(connect.status, 200)
  const socket = await socketPromise
  return { sid, socket }
}

void describe('Socket.IO binary attachment limit', () => {
  void it('delivers a binary event whose attachment count is at the patched limit', async () => {
    const { ws, socket } = await openWebSocket()
    try {
      const received: Buffer[][] = []
      socket.on('withinLimit', (...args: unknown[]) => {
        received.push(args.filter((arg): arg is Buffer => Buffer.isBuffer(arg)))
      })
      const chunks = Array.from({ length: PATCHED_MAX_ATTACHMENTS }, (_unused, index) => {
        return Buffer.from(`chunk-${index}`)
      })
      ws.send(binaryEventFrame(PATCHED_MAX_ATTACHMENTS, 'withinLimit', true))
      for (const chunk of chunks) ws.send(chunk)
      const delivered = await waitUntil(() => received.length === 1)
      assert.equal(delivered, true, 'a binary event at the attachment limit was not delivered')
      assert.equal(received[0].length, PATCHED_MAX_ATTACHMENTS)
      for (let i = 0; i < chunks.length; i++) {
        assert.equal(Buffer.compare(received[0][i], chunks[i]), 0)
      }
      assert.equal(socket.connected, true)
    } finally {
      ws.close()
    }
  })

  void it('does not buffer a websocket binary event that declares more attachments than the patched limit', async () => {
    const declared = 1000
    const { ws, socket } = await openWebSocket()
    try {
      let delivered = 0
      socket.on('overLimit', () => { delivered += 1 })
      await assertCountIsRejected({
        socket,
        declared,
        sendHeader: async () => { ws.send(binaryEventFrame(declared, 'overLimit', false)) },
        sendChunk: async () => { ws.send(CHUNK) },
        isClosed: () => socket.disconnected || ws.readyState === WebSocket.CLOSED,
        delivered: () => delivered,
        headerIsAppliedBeforeReturn: false
      })
    } finally {
      ws.close()
    }
  })

  void it('does not buffer a websocket binary ack that declares more attachments than the patched limit', async () => {
    const declared = PATCHED_MAX_ATTACHMENTS + 1
    const { ws, socket } = await openWebSocket()
    try {
      let delivered = 0
      socket.on('overLimitAck', () => { delivered += 1 })
      await assertCountIsRejected({
        socket,
        declared,
        sendHeader: async () => { ws.send(binaryAckFrame(declared)) },
        sendChunk: async () => { ws.send(CHUNK) },
        isClosed: () => socket.disconnected || ws.readyState === WebSocket.CLOSED,
        delivered: () => delivered,
        headerIsAppliedBeforeReturn: false
      })
    } finally {
      ws.close()
    }
  })

  void it('does not buffer a polling binary event that declares more attachments than the patched limit', async () => {
    const declared = PATCHED_MAX_ATTACHMENTS + 1
    const { sid, socket } = await openPolling()
    let delivered = 0
    socket.on('overLimitPoll', () => { delivered += 1 })
    await assertCountIsRejected({
      socket,
      declared,
      sendHeader: async () => {
        const posted = await request('POST', `/socket.io/?EIO=4&transport=polling&sid=${sid}`, binaryEventFrame(declared, 'overLimitPoll', false))
        assert.equal(posted.status, 200)
      },
      sendChunk: async () => {
        const posted = await request('POST', `/socket.io/?EIO=4&transport=polling&sid=${sid}`, `b${CHUNK.toString('base64')}`)
        assert.equal(posted.status, 200)
      },
      isClosed: () => socket.disconnected,
      delivered: () => delivered,
      headerIsAppliedBeforeReturn: true,
      settle: async () => { await pollUntilClosed(sid, socket) }
    })
  })

  void it('does not buffer a polling binary ack that declares more attachments than the patched limit', async () => {
    const declared = 1000
    const { sid, socket } = await openPolling()
    await assertCountIsRejected({
      socket,
      declared,
      sendHeader: async () => {
        const posted = await request('POST', `/socket.io/?EIO=4&transport=polling&sid=${sid}`, binaryAckFrame(declared))
        assert.equal(posted.status, 200)
      },
      sendChunk: async () => {
        const posted = await request('POST', `/socket.io/?EIO=4&transport=polling&sid=${sid}`, `b${CHUNK.toString('base64')}`)
        assert.equal(posted.status, 200)
      },
      isClosed: () => socket.disconnected,
      delivered: () => 0,
      headerIsAppliedBeforeReturn: true,
      settle: async () => { await pollUntilClosed(sid, socket) }
    })
  })
})

async function pollUntilClosed (sid: string, socket: LiveSocket): Promise<void> {
  // Engine.IO cannot flush a polling close until a GET is in flight, and a close
  // requested while the connect packet is still queued waits for one more poll.
  for (let attempt = 0; attempt < 3 && !socket.disconnected; attempt++) {
    await request('GET', `/socket.io/?EIO=4&transport=polling&sid=${sid}`)
    await waitUntil(() => socket.disconnected, 500)
  }
}
