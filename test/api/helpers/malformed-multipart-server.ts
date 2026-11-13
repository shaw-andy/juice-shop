/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { createApp } from '../../../server'

async function main () {
  const { app } = await createApp({ inMemoryDb: true })
  const server = app.listen(0, '127.0.0.1', () => {
    const address = server.address()
    if (address == null || typeof address === 'string') {
      throw new Error('expected the test server to listen on a TCP port')
    }
    process.stdout.write(`MULTER_TEST_READY ${address.port}\n`)
  })
}

void main()
