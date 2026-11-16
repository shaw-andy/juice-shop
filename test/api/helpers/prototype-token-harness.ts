/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { createApp } from '../../../server'

const portFile = process.argv[2]
if (!portFile) {
  throw new Error('port file path is required')
}

fs.mkdirSync('logs', { recursive: true })

void createApp({ inMemoryDb: true }).then(({ app }) => {
  const server = app.listen(0, '127.0.0.1', () => {
    const address = server.address()
    if (address === null || typeof address === 'string') {
      throw new Error('expected a TCP port')
    }
    fs.writeFileSync(portFile, String(address.port))
  })
})
