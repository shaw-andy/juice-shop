/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { writeFileSync } from 'node:fs'
import { createTestApp } from './setup'

const portFile = process.env.CHANGE_PASSWORD_ENCODING_PORT_FILE
if (portFile == null || portFile.length === 0) {
  throw new Error('CHANGE_PASSWORD_ENCODING_PORT_FILE is not set')
}

void createTestApp().then(async ({ app }) => {
  const server = http.createServer(app)
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve()
    })
  })
  const address = server.address()
  if (address == null || typeof address === 'string') {
    throw new Error('change-password encoding harness did not bind a port')
  }
  writeFileSync(portFile, String(address.port))
}).catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
