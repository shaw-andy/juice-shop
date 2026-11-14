/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { createTestApp } from '../../api/helpers/setup'
import { preconditionsReady } from '../../../lib/startup/validatePreconditions'

// Serves the real application so a browser test can request a coding-challenge
// snippet for a key that is not a challenge. Listens on the port the Angular
// client calls (config server.port, overridable with PORT).
async function main () {
  const { app } = await createTestApp()
  // Startup checks whether this port is free. Wait until that check has
  // finished before binding, so the check and the listener do not race.
  await preconditionsReady
  const server = http.createServer(app)
  const port = Number(process.env.PORT ?? 3000)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, () => {
      resolve()
    })
  })
  process.stdout.write('READY\n')
}

void main()
