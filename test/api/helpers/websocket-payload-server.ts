/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import express from 'express'
import http from 'node:http'
import { createSequelize, initModels, setSequelize } from '../../../models'
import datacreator from '../../../data/datacreator'
import registerWebsocketEvents from '../../../lib/startup/registerWebsocketEvents'

async function main () {
  const sequelize = createSequelize({ inMemory: true })
  initModels(sequelize)
  setSequelize(sequelize)
  await sequelize.sync({ force: true })
  await datacreator()

  const app = express()
  app.get('/health', (_req, res) => {
    res.status(200).end('ok')
  })
  const server = http.createServer(app)
  registerWebsocketEvents(server)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    if (address == null || typeof address === 'string') {
      throw new Error('socket payload server did not bind a port')
    }
    process.stdout.write(`READY ${address.port}\n`)
  })
}

void main()
