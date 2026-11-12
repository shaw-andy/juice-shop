/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import zlib from 'node:zlib'

// Stored-method zip whose central-directory name is the given string.
// The product reads that name back unchanged (unzipper Open.buffer).
export function storedZip (entryName: string, content: Buffer | string): Buffer {
  const nameBuf = Buffer.from(entryName, 'utf8')
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content)
  const crc = zlib.crc32(data) >>> 0
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0)
  local.writeUInt16LE(20, 4)
  local.writeUInt32LE(crc, 14)
  local.writeUInt32LE(data.length, 18)
  local.writeUInt32LE(data.length, 22)
  local.writeUInt16LE(nameBuf.length, 26)
  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0)
  central.writeUInt16LE(20, 4)
  central.writeUInt16LE(20, 6)
  central.writeUInt32LE(crc, 16)
  central.writeUInt32LE(data.length, 20)
  central.writeUInt32LE(data.length, 24)
  central.writeUInt16LE(nameBuf.length, 28)
  const centralOffset = 30 + nameBuf.length + data.length
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(1, 8)
  eocd.writeUInt16LE(1, 10)
  eocd.writeUInt32LE(46 + nameBuf.length, 12)
  eocd.writeUInt32LE(centralOffset, 16)
  return Buffer.concat([local, nameBuf, data, central, nameBuf, eocd])
}
