/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { existsSync, mkdirSync, writeFileSync, writeSync } from 'node:fs'
import http from 'node:http'
import path from 'node:path'

const placeholderFiles = [
  'build/server.js',
  'frontend/dist/frontend/index.html',
  'frontend/dist/frontend/styles.css',
  'frontend/dist/frontend/main.js',
  'frontend/dist/frontend/polyfills.js',
  'frontend/dist/frontend/hacking-instructor-placeholder.js'
]

for (const relative of placeholderFiles) {
  const absolute = path.resolve(relative)
  mkdirSync(path.dirname(absolute), { recursive: true })
  if (!existsSync(absolute)) {
    writeFileSync(absolute, '')
  }
}

setInterval(() => {
  writeSync(1, 'tick\n')
}, 200)

async function main (): Promise<void> {
  const { createApp } = await import('../../../server')
  const { app } = await createApp({ inMemoryDb: true })
  const server = http.createServer(app)

  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    if (address == null || typeof address === 'string') {
      writeSync(2, 'profile image server failed to listen\n')
      process.exit(1)
    }
    writeSync(1, `ready ${address.port}\n`)
  })
}

void main()
