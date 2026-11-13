/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { describe, it, before } from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const composePath = path.join(repoRoot, 'infrastructure/docker-compose.yml')

// docker-library/redis 7.4 Dockerfile (commit 7eaf5cd704 for 7.4.4, and the
// 7.4.5 update) compiles this default from 1 to 0. The compose command does
// not pass a config file, so the image's compiled default is what runs.
const PROTECTED_MODE_DEFAULT = /^( *createBoolConfig\("protected-mode",.*, *)1( *,.*\)),$/m

const HLL_REGISTERS = 16384
const XZERO_MAX = 16384

describe('deployed Redis HyperLogLog commands', { timeout: 600_000 }, () => {
  /** @type {string} */
  let serverBinary
  /** @type {string[]} */
  let serverArgs

  before(async () => {
    const service = readRedisService(composePath)
    const version = redisVersionFromImage(service.image)
    serverBinary = await buildRedisLikeImage(version)
    serverArgs = service.command.slice(1)
  })

  // hllSparseRegHisto: one-key PFCOUNT. A cursor that wraps to HLL_REGISTERS
  // is accepted by 7.4.4 and rejected once the overflow check is present.
  it('rejects a sparse string whose register cursor wraps on PFCOUNT', async () => {
    await expectRejected(['PFCOUNT', 'hll'], histogramPayload())
  })

  // hllMerge writes past the stack register array.
  it('rejects a sparse string on multi-key PFCOUNT without exiting', async () => {
    await expectRejected(['PFCOUNT', 'hll', 'hll'], crashPayload())
  })

  it('rejects a sparse string on PFMERGE without exiting', async () => {
    await expectRejected(['PFMERGE', 'dest', 'hll'], crashPayload())
  })

  // hllSparseToDense writes past the heap dense buffer. PFADD promotes a
  // sparse value larger than hll-sparse-max-bytes into that conversion.
  it('rejects a sparse string on PFADD without exiting', async () => {
    await expectRejected(['PFADD', 'hll', 'element'], crashPayload())
  })

  it('rejects a sparse string on PFDEBUG TODENSE without exiting', async () => {
    await expectRejected(['PFDEBUG', 'TODENSE', 'hll'], crashPayload())
  })

  it('rejects a sparse string on PFDEBUG GETREG without exiting', async () => {
    await expectRejected(['PFDEBUG', 'GETREG', 'hll'], crashPayload())
  })

  async function expectRejected (command, payload) {
    const session = await startServer(serverBinary, serverArgs)
    try {
      assert.equal(await session.command('PING'), '+PONG')
      const setReply = await session.command('SET', 'hll', payload)
      assert.equal(setReply, '+OK')
      let reply
      try {
        reply = await session.command(...command)
      } catch {
        await session.exited
        assert.fail(`${command[0]} dropped the connection (signal ${session.signalCode ?? 'none'}, exit ${session.exitCode ?? 'none'})`)
      }
      assert.equal(session.exitCode, null)
      assert.equal(session.signalCode, null)
      assert.match(
        String(reply),
        /^-(?:INVALIDOBJ |NOPERM |ERR unknown command)/,
        `${command[0]} processed the crafted HyperLogLog string (${reply})`
      )
      assert.equal(await session.command('PING'), '+PONG')
    } finally {
      await session.stop()
    }
  }
})

function readRedisService (file) {
  const lines = fs.readFileSync(file, 'utf8').split(/\n/)
  let inRedis = false
  let image
  let command
  for (const line of lines) {
    if (/^ {2}redis:\s*$/.test(line)) {
      inRedis = true
      continue
    }
    if (inRedis && /^ {2}\S/.test(line)) break
    if (!inRedis) continue
    const imageMatch = /^ {4}image:\s*['"]?([^'"\s]+)['"]?\s*$/.exec(line)
    if (imageMatch) image = imageMatch[1]
    const commandMatch = /^ {4}command:\s*(\[.*\])\s*$/.exec(line)
    if (commandMatch) command = JSON.parse(commandMatch[1])
  }
  assert.ok(image, `redis image missing from ${file}`)
  assert.ok(Array.isArray(command) && command[0] === 'redis-server', `redis command missing from ${file}`)
  return { image, command }
}

function redisVersionFromImage (image) {
  const match = /^redis:(\d+\.\d+\.\d+)(?:-alpine)?$/.exec(image)
  assert.ok(match, `redis image ${image} is not a pinned official tag`)
  return match[1]
}

async function buildRedisLikeImage (version) {
  const root = path.join(os.tmpdir(), 'juice-shop-redis-hll', version)
  const binary = path.join(root, 'src', 'redis-server')
  const marker = path.join(root, '.image-defaults-applied')
  if (fs.existsSync(binary) && fs.existsSync(marker)) return binary

  fs.rmSync(root, { recursive: true, force: true })
  fs.mkdirSync(root, { recursive: true })
  const tarball = path.join(root, `redis-${version}.tar.gz`)
  const response = await fetch(`https://github.com/redis/redis/archive/refs/tags/${version}.tar.gz`)
  assert.equal(response.ok, true, `redis ${version} source download failed (${response.status})`)
  fs.writeFileSync(tarball, Buffer.from(await response.arrayBuffer()))
  await run('tar', ['-xzf', tarball, '-C', root, '--strip-components=1'])

  const configPath = path.join(root, 'src', 'config.c')
  const config = fs.readFileSync(configPath, 'utf8')
  assert.match(config, PROTECTED_MODE_DEFAULT, 'redis config.c has no protected-mode default to patch')
  fs.writeFileSync(configPath, config.replace(PROTECTED_MODE_DEFAULT, (_match, prefix, suffix) => `${prefix}0${suffix},`))
  assert.match(fs.readFileSync(configPath, 'utf8'), /createBoolConfig\("protected-mode".*, 0,/)
  fs.writeFileSync(marker, 'protected-mode default 0\n')

  await run('make', ['-C', root, '-j', String(os.cpus().length), 'MALLOC=jemalloc', 'BUILD_TLS=no', 'all'])
  assert.equal(fs.existsSync(binary), true)
  return binary
}

function sparseHeader () {
  const header = Buffer.alloc(16)
  header.write('HYLL')
  header[4] = 1
  header[15] = 0x80
  return header
}

function xzero (len) {
  const stored = len - 1
  return Buffer.from([(stored >> 8) | 0x40, stored & 0xff])
}

// Number of max-length XZERO opcodes whose run lengths sum to `cursor`
// once truncated to a signed 32-bit register index.
function xzeroCountForCursor (cursor) {
  const mod = 2 ** 32
  let sum = cursor < 0 ? cursor + mod : cursor
  if (sum <= HLL_REGISTERS) sum += mod
  assert.equal(sum % XZERO_MAX, 0)
  return sum / XZERO_MAX
}

function xzeroRun (cursor) {
  const count = xzeroCountForCursor(cursor)
  const opcode = xzero(XZERO_MAX)
  const body = Buffer.alloc(count * opcode.length)
  for (let offset = 0; offset < body.length; offset += opcode.length) opcode.copy(body, offset)
  return body
}

function histogramPayload () {
  return Buffer.concat([sparseHeader(), xzeroRun(HLL_REGISTERS)])
}

function crashPayload () {
  // int32 truncation of this run length is a large negative index, so the
  // VAL opcode's bounds check does not fire and the following write is
  // outside the register array.
  const value = Buffer.from([0x80])
  return Buffer.concat([sparseHeader(), xzeroRun(-(2 ** 30)), value])
}

async function startServer (binary, args) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redis-hll-'))
  const port = await freePort()
  const proc = spawn(binary, [
    ...args,
    '--port', String(port),
    '--dir', dir,
    '--dbfilename', 'dump.rdb',
    '--save', '',
    '--appendonly', 'no',
    '--daemonize', 'no'
  ], { cwd: dir, stdio: ['ignore', 'ignore', 'ignore'] })
  const exited = new Promise((resolve) => {
    proc.on('exit', (code, signal) => resolve({ code, signal }))
  })
  const client = await connectWhenReady(proc, port)
  return {
    get exitCode () { return proc.exitCode },
    get signalCode () { return proc.signalCode },
    exited,
    command: (...parts) => client.command(...parts),
    async stop () {
      client.socket.destroy()
      if (proc.exitCode === null && proc.signalCode === null) {
        proc.kill('SIGTERM')
        await Promise.race([
          exited,
          new Promise((resolve) => setTimeout(resolve, 2000))
        ])
        if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL')
      }
      fs.rmSync(dir, { recursive: true, force: true })
    }
  }
}

function connectWhenReady (proc, port) {
  return new Promise((resolve, reject) => {
    const started = Date.now()
    const attempt = () => {
      if (proc.exitCode !== null || proc.signalCode !== null) {
        reject(new Error(`redis exited before accepting connections (${proc.signalCode ?? proc.exitCode})`))
        return
      }
      const socket = net.connect({ host: '127.0.0.1', port })
      socket.once('error', () => {
        socket.destroy()
        if (Date.now() - started > 10000) reject(new Error('redis did not accept connections'))
        else setTimeout(attempt, 20)
      })
      socket.once('connect', () => resolve(new RedisClient(socket)))
    }
    attempt()
  })
}

class RedisClient {
  constructor (socket) {
    this.socket = socket
    this.buffer = Buffer.alloc(0)
    this.waiters = []
    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk])
      this.drain()
    })
    socket.on('error', (error) => this.fail(error))
    socket.on('close', () => this.fail(new Error('connection closed')))
  }

  command (...args) {
    const payload = encodeCommand(args)
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject, timer: setTimeout(() => reject(new Error('command timed out')), 10000) })
      this.socket.write(payload)
    })
  }

  fail (error) {
    const waiters = this.waiters.splice(0)
    for (const waiter of waiters) {
      clearTimeout(waiter.timer)
      waiter.reject(error)
    }
  }

  drain () {
    while (this.waiters.length > 0) {
      const parsed = parseReply(this.buffer)
      if (!parsed) return
      this.buffer = this.buffer.subarray(parsed.bytes)
      const waiter = this.waiters.shift()
      clearTimeout(waiter.timer)
      waiter.resolve(parsed.value)
    }
  }
}

function encodeCommand (args) {
  const chunks = [Buffer.from(`*${args.length}\r\n`)]
  for (const arg of args) {
    const value = Buffer.isBuffer(arg) ? arg : Buffer.from(String(arg))
    chunks.push(Buffer.from(`$${value.length}\r\n`), value, Buffer.from('\r\n'))
  }
  return Buffer.concat(chunks)
}

function parseReply (buffer) {
  if (buffer.length < 3) return null
  const kind = String.fromCharCode(buffer[0])
  const lineEnd = buffer.indexOf('\r\n')
  if (lineEnd < 0) return null
  const line = buffer.toString('utf8', 1, lineEnd)
  if (kind === '+' || kind === '-' || kind === ':') {
    return { value: kind + line, bytes: lineEnd + 2 }
  }
  if (kind === '$') {
    const length = Number(line)
    if (length < 0) return { value: null, bytes: lineEnd + 2 }
    const start = lineEnd + 2
    if (buffer.length < start + length + 2) return null
    return { value: buffer.subarray(start, start + length).toString('utf8'), bytes: start + length + 2 }
  }
  if (kind === '*') {
    const count = Number(line)
    let cursor = lineEnd + 2
    for (let index = 0; index < count; index++) {
      const item = parseReply(buffer.subarray(cursor))
      if (!item) return null
      cursor += item.bytes
    }
    return { value: `*${count}`, bytes: cursor }
  }
  return null
}

function freePort () {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      server.close(() => resolve(address.port))
    })
  })
}

function run (cmd, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', (chunk) => { output += chunk })
    child.stderr.on('data', (chunk) => { output += chunk })
    child.on('error', reject)
    child.on('close', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`${cmd} ${args.join(' ')} exited ${code}\n${output.slice(-2000)}`))
    })
  })
}
