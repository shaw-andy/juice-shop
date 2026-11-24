/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { createApp } from '../../../server'
import type { Product as ProductConfig } from '../../../lib/config.schema'

async function main () {
  const { app, sequelize } = await createApp({ inMemoryDb: true })
  if (process.env.NULL_TAMPER_PRODUCT === '1') {
    const tamperUrl = config.get<ProductConfig[]>('products').find((product) => product.urlForProductTamperingChallenge != null)?.urlForProductTamperingChallenge
    if (tamperUrl == null) {
      throw new Error('Tampering product URL is not configured')
    }
    await sequelize.query(
      'UPDATE Products SET description = NULL WHERE description LIKE :pattern',
      { replacements: { pattern: `%${tamperUrl}%` } }
    )
  }
  const server = app.listen(0, '127.0.0.1', () => {
    const address = server.address()
    if (address == null || typeof address === 'string') {
      throw new Error('Test server did not bind to a port')
    }
    process.stdout.write(`READY ${address.port}\n`)
  })
}

void main()
