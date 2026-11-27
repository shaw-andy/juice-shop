/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { type AddressInfo } from 'node:net'
import { createApp } from '../../../server'

const uploadDir = 'frontend/dist/frontend/assets/public/images/uploads'
fs.mkdirSync(uploadDir, { recursive: true })

void (async () => {
  const { app } = await createApp({ inMemoryDb: true })
  const server = app.listen(0, '127.0.0.1', () => {
    const address = server.address() as AddressInfo | null
    if (address == null) {
      throw new Error('profile image server failed to bind')
    }
    if (process.send == null) {
      throw new Error('profile image server must be started with an IPC channel')
    }
    process.send({ port: address.port })
  })
})()
