/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as http from 'http'
import { Worker } from 'node:worker_threads'
import express from 'express'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { challenges } from '../../data/datacache'
import type { ChallengeModel } from '../../models/challenge'

// Tens of thousands of ordinary characters make the unanchored leading
// wildcard stall the event loop. The budget sits above localhost latency
// and below that stall, including on a faster machine.
const LONG_PAYLOAD_CHARS = 80_000
const SHORT_PAYLOAD_CHARS = 64
const MAX_STALL_MS = 500

interface ProbeResult {
  connected: boolean
  sentBytes: number
  maxHttpMs: number
  probeError?: string
}

let server: http.Server
let serverPort: number

before(async () => {
  challenges.svgInjectionChallenge = { solved: false, key: 'svgInjectionChallenge' } as ChallengeModel
  const app = express()
  app.get('/event-loop-probe', (_req, res) => {
    res.status(204).end()
  })
  await new Promise<void>((resolve) => {
    server = http.createServer(app)
    registerWebsocketEvents(server)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') {
        serverPort = addr.port
      }
      resolve()
    })
  })
}, { timeout: 30000 })

after(() => {
  if (server) {
    server.close()
  }
})

function probe (port: number, chars: number, sampleWindowMs: number): Promise<ProbeResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(`
      const { parentPort, workerData } = require('node:worker_threads')
      const http = require('node:http')
      const { io } = require('socket.io-client')

      const payload = 'a'.repeat(workerData.chars)
      let sentBytes = 0
      let finished = false

      const socket = io('http://127.0.0.1:' + workerData.port, {
        transports: ['websocket'],
        reconnection: false,
        timeout: 10000
      })

      function finish (result) {
        if (finished) return
        finished = true
        try { socket.close() } catch (err) {}
        parentPort.postMessage(result)
      }

      socket.on('connect_error', (err) => {
        finish({
          connected: false,
          sentBytes,
          maxHttpMs: 0,
          probeError: String(err && err.message ? err.message : err)
        })
      })

      socket.on('connect', () => {
        const ws = socket.io.engine.transport.ws
        const originalSend = ws.send.bind(ws)
        ws.send = function (data, opts, cb) {
          if (typeof data === 'string') sentBytes += Buffer.byteLength(data)
          else if (data) sentBytes += data.length
          return originalSend(data, opts, cb)
        }
        socket.emit('verifySvgInjectionChallenge', payload)
        setTimeout(sampleHttp, 50)
      })

      function sampleHttp () {
        const samples = []
        const deadline = Date.now() + workerData.sampleWindowMs
        function once () {
          const started = Date.now()
          const req = http.get('http://127.0.0.1:' + workerData.port + '/event-loop-probe', (res) => {
            res.resume()
            res.on('end', () => {
              samples.push(Date.now() - started)
              const maxHttpMs = Math.max(...samples)
              if (maxHttpMs > ${MAX_STALL_MS} || Date.now() >= deadline) {
                finish({ connected: true, sentBytes, maxHttpMs })
              } else {
                setTimeout(once, 30)
              }
            })
          })
          req.on('error', (err) => {
            finish({
              connected: socket.connected,
              sentBytes,
              maxHttpMs: Date.now() - started,
              probeError: String(err && err.message ? err.message : err)
            })
          })
          req.setTimeout(20000, () => {
            req.destroy()
            finish({
              connected: socket.connected,
              sentBytes,
              maxHttpMs: Date.now() - started,
              probeError: 'http timeout'
            })
          })
        }
        once()
      }

      setTimeout(() => {
        finish({ connected: socket.connected, sentBytes, maxHttpMs: 0, probeError: 'probe timeout' })
      }, 25000)
    `, {
      eval: true,
      workerData: { port, chars, sampleWindowMs }
    })

    worker.once('message', (message: ProbeResult) => {
      resolve(message)
      void worker.terminate()
    })
    worker.once('error', (err) => {
      void worker.terminate()
      reject(err)
    })
  })
}

void describe('verifySvgInjectionChallenge availability', () => {
  void it('evaluates a short ordinary payload from an unauthenticated websocket', async () => {
    const challenge = challenges.svgInjectionChallenge
    assert.ok(challenge, 'svgInjectionChallenge was not loaded')
    challenge.solved = false

    let evaluated = false
    const original = challenges.svgInjectionChallenge
    challenges.svgInjectionChallenge = new Proxy(original, {
      get (target, prop, receiver) {
        if (prop === 'solved') evaluated = true
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      }
    })

    try {
      const result = await probe(serverPort, SHORT_PAYLOAD_CHARS, 200)
      assert.equal(result.probeError, undefined, result.probeError)
      assert.equal(result.connected, true)
      assert.ok(result.sentBytes > SHORT_PAYLOAD_CHARS, 'client did not send the short payload: ' + result.sentBytes)
      assert.equal(evaluated, true)
      assert.ok(result.maxHttpMs < MAX_STALL_MS, 'short payload stalled HTTP for ' + result.maxHttpMs + 'ms')
      assert.equal(original.solved, false)
    } finally {
      challenges.svgInjectionChallenge = original
    }
  }, { timeout: 30000 })

  void it('does not stall the event loop on a long ordinary verifySvgInjectionChallenge payload', async () => {
    const challenge = challenges.svgInjectionChallenge
    assert.ok(challenge, 'svgInjectionChallenge was not loaded')
    challenge.solved = false

    const result = await probe(serverPort, LONG_PAYLOAD_CHARS, 1000)

    assert.equal(result.probeError, undefined, result.probeError)
    assert.equal(result.connected, true)
    assert.ok(
      result.sentBytes > LONG_PAYLOAD_CHARS,
      'client did not send the long payload: ' + result.sentBytes
    )
    assert.ok(
      result.maxHttpMs < MAX_STALL_MS,
      'HTTP stalled for ' + result.maxHttpMs + 'ms after an unauthenticated websocket sent ' + LONG_PAYLOAD_CHARS + ' ordinary characters to verifySvgInjectionChallenge'
    )
    assert.equal(challenge.solved, false)
  }, { timeout: 30000 })
})
