/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { MissingSigningSecretsError } from './lib/hardenedProfile'

async function app () {
  const { default: validateDependencies } = await import('./lib/startup/validateDependenciesBasic')
  await validateDependencies()

  const server = await import('./server')
  await server.start()
}

app()
  .catch(err => {
    if (err instanceof MissingSigningSecretsError) {
      console.error(err.message)
      process.exit(1)
    }
    throw err
  })
