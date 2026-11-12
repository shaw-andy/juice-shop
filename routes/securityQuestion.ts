/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { isIPv6 } from 'node:net'
import { type Request, type Response } from 'express'
import { rateLimit } from 'express-rate-limit'

export function securityQuestion () {
  return (_req: Request, res: Response) => {
    res.json({})
  }
}

// 'trust proxy' is enabled globally, so req.ip is taken from X-Forwarded-For and must not be used as the key
export function securityQuestionRateLimit () {
  return rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    validate: false,
    keyGenerator: ({ socket }: Request) => clientNetwork(socket.remoteAddress)
  })
}

export function clientNetwork (address = '') {
  const ipv4Mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address)
  if (ipv4Mapped) return ipv4Mapped[1]
  if (!isIPv6(address)) return address
  const [head, tail = ''] = address.split('::')
  const headGroups = head ? head.split(':') : []
  const tailGroups = tail ? tail.split(':') : []
  const groups = [...headGroups, ...Array(Math.max(0, 8 - headGroups.length - tailGroups.length)).fill('0'), ...tailGroups]
  return groups.slice(0, 4).map((group) => parseInt(group, 16).toString(16)).join(':') + '::/64'
}
