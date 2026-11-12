/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'fs'
import path from 'path'
import zlib from 'zlib'
import { load } from 'js-yaml'

// Tags whose message_compressor_zlib.cpp returns the zlib byte count, and whose
// message_compressor_manager.cpp rejects that count when it is not the claimed size.
const VERIFIED_FIXED = new Set(['4.4.30', '6.0.27', '7.0.28', '8.0.17', '8.2.3'])

const OP_COMPRESSED = 2012
const OP_MSG = 2013
const ZLIB_ID = 2
const SENTINEL = 0xA5
const OID_SIZE = 12
const DECIMAL_SIZE = 16

const EOO = 0
const MIN_KEY = -1
const MAX_KEY = 127
const NUMBER_DOUBLE = 1
const STRING = 2
const OBJECT = 3
const ARRAY = 4
const BIN_DATA = 5
const UNDEFINED = 6
const OID = 7
const BOOL = 8
const DATE = 9
const NULL_TYPE = 10
const REGEX = 11
const DB_REF = 12
const CODE = 13
const SYMBOL = 14
const CODE_W_SCOPE = 15
const NUMBER_INT = 16
const TIMESTAMP = 17
const NUMBER_LONG = 18
const NUMBER_DECIMAL = 19

// Undersize zlib OP_COMPRESSED body from message_compressor_manager_test.cpp at r4.4.30.
const UNDERSIZE_ZLIB_MESSAGE = Buffer.from([
  0x3c, 0x00, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0x07, 0x00,
  0x00, 0xdd, 0x07, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x02, 0x78, 0xda, 0x63, 0x60, 0x00,
  0x82, 0xdf, 0xf2, 0x0c, 0x0c, 0xac, 0xf1, 0x99, 0x29, 0x0c, 0x0c, 0x02, 0x40, 0x9e, 0x87,
  0xab, 0x63, 0x80, 0x8f, 0xab, 0xa3, 0x37, 0x03, 0x12, 0x00, 0x00, 0x6d, 0x26, 0x04, 0x97
])

const COMPOSE_PATH = path.resolve(__dirname, '../../infrastructure/docker-compose.yml')

interface Disclosure {
  disclosed: boolean
  leakedBytes: number
  reason: string
}

class Reader {
  buffer: Buffer
  position: number
  maxLength: number

  constructor (buffer: Buffer, maxLength: number) {
    this.buffer = buffer
    this.position = 0
    this.maxLength = maxLength
  }

  readBytes (size: number) {
    if (this.position + size > this.maxLength) return null
    const out = this.buffer.subarray(this.position, this.position + size)
    this.position += size
    return out
  }

  readSignedByte () {
    const raw = this.readBytes(1)
    if (!raw) return null
    return raw[0] > 127 ? raw[0] - 256 : raw[0]
  }

  readInt32 () {
    const raw = this.readBytes(4)
    if (!raw) return null
    return raw.readInt32LE(0)
  }

  readCString () {
    const start = this.position
    const end = this.buffer.subarray(0, this.maxLength).indexOf(0, start)
    if (end < 0) return null
    const text = this.buffer.toString('utf8', start, end)
    this.position = end + 1
    return text
  }

  skip (size: number) {
    this.position += size
    return this.position < this.maxLength
  }
}

interface IdElem {
  text: string
  leakedBytes: number
}

function hexByte (value: number) {
  return value.toString(16).padStart(2, '0').toUpperCase()
}

function captureId (buffer: Buffer, elemStart: number, messageOffset: number, inflatedLength: number): IdElem | null {
  if (buffer[elemStart] !== BIN_DATA) return null
  let cursor = elemStart + 1
  const nameStart = cursor
  while (cursor < buffer.length && buffer[cursor] !== 0) cursor++
  const name = buffer.toString('utf8', nameStart, cursor)
  cursor++
  const len = buffer.readInt32LE(cursor)
  const subtype = buffer[cursor + 4]
  const dataStart = cursor + 5
  let hex = ''
  let leakedBytes = 0
  for (let i = 0; i < len; i++) {
    const messageIndex = messageOffset + dataStart + i
    const byte = buffer[dataStart + i]
    if (messageIndex >= inflatedLength) leakedBytes++
    hex += hexByte(byte)
  }
  return { text: `${name}: BinData(${subtype}, ${hex})`, leakedBytes }
}

function makeError (base: string, idElem: IdElem | null, elemName: string) {
  let msg = base
  if (elemName) msg += ` in element with field name '${elemName}'`
  msg += idElem ? ` in object with ${idElem.text}` : ' in object with unknown _id'
  return { ok: false as const, error: msg, leakedBytes: idElem ? idElem.leakedBytes : 0 }
}

function validateElement (reader: Reader, idElem: IdElem | null) {
  const type = reader.readSignedByte()
  if (type === null) return { ...makeError('invalid bson', idElem, ''), next: 0 }
  if (type === EOO) return { ok: true as const, next: 'end', elemName: '' }

  const elemName = reader.readCString()
  if (elemName === null) return { ...makeError('no end of c-string', idElem, ''), next: 0 }

  const invalid = (text: string) => ({ ...makeError(text, idElem, elemName), next: 0 })
  if (type === MIN_KEY || type === MAX_KEY || type === NULL_TYPE || type === UNDEFINED) {
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === OID) {
    if (!reader.skip(OID_SIZE)) return invalid('invalid bson')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === NUMBER_INT) {
    if (!reader.skip(4)) return invalid('invalid bson')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === BOOL) {
    const value = reader.readBytes(1)
    if (!value) return invalid('invalid bson')
    if (value[0] !== 0 && value[0] !== 1) return invalid('invalid boolean value')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === NUMBER_DOUBLE || type === NUMBER_LONG || type === TIMESTAMP || type === DATE) {
    if (!reader.skip(8)) return invalid('invalid bson')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === NUMBER_DECIMAL) {
    if (!reader.skip(DECIMAL_SIZE)) return invalid('Invalid bson')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === STRING || type === CODE || type === SYMBOL) {
    const size = reader.readInt32()
    if (size === null || size <= 0) return invalid('invalid bson')
    if (!reader.skip(size - 1)) return invalid('invalid bson')
    const terminator = reader.readBytes(1)
    if (!terminator) return invalid('invalid bson')
    if (terminator[0] !== 0) return invalid('not null terminated string')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === REGEX) {
    if (reader.readCString() === null || reader.readCString() === null) return invalid('invalid bson')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === DB_REF) {
    const size = reader.readInt32()
    if (size === null || size <= 0 || !reader.skip(size)) return invalid('invalid bson')
    if (!reader.skip(OID_SIZE)) return invalid('invalid bson length')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === BIN_DATA) {
    const size = reader.readInt32()
    if (size === null) return invalid('invalid bson')
    if (size < 0 || size === 2147483647) return invalid('invalid size in bson')
    if (!reader.skip(1 + size)) return invalid('invalid bson')
    return { ok: true as const, next: 'within', elemName }
  }
  if (type === CODE_W_SCOPE) return { ok: true as const, next: 'code', elemName }
  if (type === OBJECT || type === ARRAY) return { ok: true as const, next: 'begin', elemName }
  return invalid('invalid bson type')
}

function validateBson (bson: Buffer, messageOffset: number, inflatedLength: number) {
  if (bson.length < 5) {
    return { error: 'bson data has to be at least 5 bytes', leakedBytes: 0 }
  }
  const reader = new Reader(bson, bson.length)
  const frames: Array<{ start: number, expected: number, code: boolean }> = []
  let state = 'begin'
  let idElemStart = 0
  let idElem: IdElem | null = null

  while (state !== 'done') {
    if (state === 'begin' || state === 'code') {
      if (frames.length > 200) return { error: 'BSONObj exceeded maximum nested object depth', leakedBytes: 0 }
      const start = reader.position
      const expected = reader.readInt32()
      if (expected === null) {
        const why = state === 'code' ? 'invalid bson CodeWScope size' : 'bson size is larger than buffer size'
        return makeError(why, idElem, '')
      }
      if (state === 'code') {
        if (reader.readInt32() === null) return makeError('invalid bson', idElem, '')
      }
      frames.push({ start, expected, code: state === 'code' })
      state = 'within'
    }

    if (state === 'within') {
      const atTop = frames.length === 1
      if (atTop && idElemStart) {
        idElem = captureId(bson, idElemStart, messageOffset, inflatedLength)
        idElemStart = 0
      }
      const elemStart = reader.position
      const info = validateElement(reader, idElem)
      if (!info.ok) return info
      if (info.next !== 'end' && !idElem && atTop && info.elemName === '_id') idElemStart = elemStart
      if (info.next === 'end') state = 'end'
      else if (info.next === 'begin') state = 'begin'
      else if (info.next === 'code') state = 'code'
      else state = 'within'
      if (state !== 'within') continue
    }

    if (state === 'end') {
      const curr = frames[frames.length - 1]
      const actual = reader.position - curr.start
      if (actual !== curr.expected) {
        const why = curr.code ? 'bson length for CodeWScope doesn\'t match what we found' : 'bson length doesn\'t match what we found'
        return makeError(why, idElem, '')
      }
      frames.pop()
      if (frames.length === 0) state = 'done'
      else state = frames[frames.length - 1].code ? 'end-code' : 'within'
    }

    if (state === 'end-code') {
      const curr = frames[frames.length - 1]
      const actual = reader.position - curr.start
      if (actual !== curr.expected) return makeError('bson length for CodeWScope doesn\'t match what we found', idElem, '')
      frames.pop()
      state = frames.length === 0 ? 'done' : 'within'
    }
  }
  return { error: '', leakedBytes: 0 }
}

function clientErrmsg (body: Buffer, inflatedLength: number) {
  if (body.length < 5) return { error: 'short message', leakedBytes: 0 }
  const kind = body[4]
  if (kind !== 0) return { error: `Unknown section kind ${kind}`, leakedBytes: kind === SENTINEL ? 1 : 0 }
  return validateBson(body.subarray(5), 5, inflatedLength)
}

function argvOf (command: string | string[] | undefined) {
  if (!command) return ['mongod']
  if (Array.isArray(command)) return command.map(String)
  return command.split(/\s+/).filter(Boolean)
}

function hasArg (argv: string[], name: string) {
  return argv.some((arg, index) => arg === name || arg.startsWith(`${name}=`) || (index > 0 && argv[index - 1] === name))
}

function argValue (argv: string[], name: string) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === name) return argv[i + 1]
    if (argv[i].startsWith(`${name}=`)) return argv[i].slice(name.length + 1)
  }
  return undefined
}

function envMap (environment: unknown) {
  const out: Record<string, string> = {}
  if (!environment) return out
  if (Array.isArray(environment)) {
    for (const entry of environment) {
      const text = String(entry)
      const eq = text.indexOf('=')
      if (eq > 0) out[text.slice(0, eq)] = text.slice(eq + 1)
    }
    return out
  }
  for (const [key, value] of Object.entries(environment as Record<string, unknown>)) {
    out[key] = value == null ? '' : String(value)
  }
  return out
}

function imageVersion (image: string) {
  const match = image.match(/:(\d+\.\d+\.\d+)(?:[^0-9.]|$)/)
  return match ? match[1] : ''
}

function officialMongoImage (image: string) {
  const name = image.split('@')[0].split(':')[0]
  return name === 'mongo' || name.endsWith('/mongo')
}

function networkNames (service: any) {
  if (!service.networks) return ['default']
  if (Array.isArray(service.networks)) return service.networks.map(String)
  return Object.keys(service.networks)
}

function sharesNetwork (services: Record<string, any>, name: string) {
  const mine = new Set(networkNames(services[name]))
  return Object.keys(services).some((other) => other !== name && networkNames(services[other]).some((net) => mine.has(net)))
}

function publishedToHost (service: any) {
  const ports = service.ports || []
  return ports.some((port: unknown) => String(port).includes('27017'))
}

function configFromCompose (service: any, composeDir: string) {
  const argv = argvOf(service.command)
  const configArg = argValue(argv, '--config')
  if (!configArg) return null
  const volumes = service.volumes || []
  for (const volume of volumes) {
    if (typeof volume !== 'string') continue
    const [source, target] = volume.split(':')
    if (target !== configArg || !source || source.startsWith('/') || !source.includes('/')) continue
    const file = path.resolve(composeDir, source)
    if (!fs.existsSync(file)) continue
    return load(fs.readFileSync(file, 'utf8')) as any
  }
  return null
}

function compressorsOf (service: any, composeDir: string) {
  const argv = argvOf(service.command)
  const config = configFromCompose(service, composeDir)
  const raw = argValue(argv, '--networkMessageCompressors') ??
    config?.net?.compression?.compressors ??
    'snappy,zstd,zlib'
  if (raw === 'disabled') return []
  return String(raw).split(/[,\s]+/).filter(Boolean)
}

function reachableFromComposeNetwork (services: Record<string, any>, name: string) {
  const service = services[name]
  const argv = argvOf(service.command)
  const bind = argValue(argv, '--bind_ip')
  const bindAll = hasArg(argv, '--bind_ip_all') ||
    (officialMongoImage(String(service.image || '')) && !bind)
  const loopbackOnly = !bindAll && !!bind && bind.split(',').every((ip) => ip === '127.0.0.1' || ip === 'localhost' || ip === '::1')
  if (loopbackOnly) return false
  return publishedToHost(service) || sharesNetwork(services, name)
}

function disclosureOf (services: Record<string, any>, composeDir: string): Disclosure {
  const service = services.mongo
  if (!service) return { disclosed: false, leakedBytes: 0, reason: 'no mongo service' }
  if (!reachableFromComposeNetwork(services, 'mongo')) {
    return { disclosed: false, leakedBytes: 0, reason: 'not reachable from the compose network' }
  }
  const compressors = compressorsOf(service, composeDir)
  if (!compressors.includes('zlib')) {
    return { disclosed: false, leakedBytes: 0, reason: 'zlib is not an enabled compressor' }
  }
  if (UNDERSIZE_ZLIB_MESSAGE.readInt32LE(12) !== OP_COMPRESSED) {
    throw new Error('fixture opcode changed')
  }
  if (UNDERSIZE_ZLIB_MESSAGE.readInt32LE(16) !== OP_MSG || UNDERSIZE_ZLIB_MESSAGE[24] !== ZLIB_ID) {
    throw new Error('fixture is not a zlib OP_MSG')
  }
  const claimed = UNDERSIZE_ZLIB_MESSAGE.readInt32LE(20)
  const inflated = zlib.inflateSync(UNDERSIZE_ZLIB_MESSAGE.subarray(25))
  const version = imageVersion(String(service.image || ''))
  const returnsActualLength = VERIFIED_FIXED.has(version)
  if (returnsActualLength && inflated.length !== claimed) {
    return { disclosed: false, leakedBytes: 0, reason: 'Decompressing message returned less data than expected' }
  }
  const body = Buffer.alloc(claimed, SENTINEL)
  inflated.copy(body)
  const parsed = clientErrmsg(body, inflated.length)
  return {
    disclosed: parsed.leakedBytes > 0,
    leakedBytes: parsed.leakedBytes,
    reason: parsed.error
  }
}

function loadCompose () {
  return load(fs.readFileSync(COMPOSE_PATH, 'utf8')) as { services: Record<string, any> }
}

void describe('compose MongoDB zlib disclosure', () => {
  void it('does not return bytes past the zlib output to a client on the compose network', () => {
    const result = disclosureOf(loadCompose().services, path.dirname(COMPOSE_PATH))
    assert.equal(result.disclosed, false, `errmsg included ${result.leakedBytes} bytes zlib did not write`)
  })

  void it('rejects the same message when the image is 4.4.30', () => {
    const services = loadCompose().services
    services.mongo.image = 'mongo:4.4.30'
    const result = disclosureOf(services, path.dirname(COMPOSE_PATH))
    assert.equal(result.disclosed, false)
    assert.match(result.reason, /less data than expected/)
  })

  void it('rejects the message before parsing when zlib is omitted', () => {
    const services = loadCompose().services
    services.mongo.command = ['mongod', '--networkMessageCompressors', 'snappy,zstd']
    const result = disclosureOf(services, path.dirname(COMPOSE_PATH))
    assert.equal(result.disclosed, false)
    assert.match(result.reason, /zlib is not an enabled compressor/)
  })

  void it('still returns those bytes when a root user is configured on 4.4.29', () => {
    const services = loadCompose().services
    services.mongo.environment = {
      ...envMap(services.mongo.environment),
      MONGO_INITDB_ROOT_USERNAME: 'placeholder',
      MONGO_INITDB_ROOT_PASSWORD: 'placeholder'
    }
    const result = disclosureOf(services, path.dirname(COMPOSE_PATH))
    assert.equal(result.disclosed, true)
    assert.ok(result.leakedBytes > 20)
  })

  void it('is not reachable from another service when mongod binds only loopback', () => {
    const services = loadCompose().services
    services.mongo.command = ['mongod', '--bind_ip', '127.0.0.1']
    delete services.mongo.ports
    const result = disclosureOf(services, path.dirname(COMPOSE_PATH))
    assert.equal(result.disclosed, false)
    assert.match(result.reason, /not reachable/)
  })
})
