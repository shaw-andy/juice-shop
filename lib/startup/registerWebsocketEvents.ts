/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { Server } from 'socket.io'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'
import * as utils from '../utils'
import logger from '../logger'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: Server
}

// socket.io does not catch exceptions thrown by event listeners, so an uncaught one would terminate the process
const on = (socket: any, event: string, listener: (data: any) => void) => {
  socket.on(event, (data: any) => {
    try {
      listener(data)
    } catch (error: unknown) {
      logger.warn(`Error handling websocket event ${event}: ${utils.getErrorMessage(error)}`)
    }
  })
}

const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    on(socket, 'notification received', (data: any) => {
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    on(socket, 'verifyLocalXssChallenge', (data: any) => {
      if (typeof data !== 'string') return
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return data.includes('<iframe src="javascript:alert(`xss`)">') })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return data.includes(config.get('challenges.xssBonusPayload')) })
    })

    on(socket, 'verifySvgInjectionChallenge', (data: any) => {
      if (typeof data !== 'string') return
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/cataas.com\/cat.*/) && security.isRedirectAllowed(data) })
    })

    on(socket, 'verifyCloseNotificationsChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
