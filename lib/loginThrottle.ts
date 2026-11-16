/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { isIPv6 } from 'node:net'
import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

const message = 'Too many failed login attempts. Please try again later.'

export function loginAccountKey (email: unknown) {
  return String(email || '').trim().toLowerCase()
}

function ipv6Prefix64 (address: string) {
  const [head, tail] = address.split('%')[0].split('::')
  const groups = (part: string | undefined) => part ? part.split(':').flatMap(group => group.includes('.') ? ['0', '0'] : [group]) : []
  const headGroups = groups(head)
  const tailGroups = groups(tail)
  const expanded = [...headGroups, ...new Array(Math.max(8 - headGroups.length - tailGroups.length, 0)).fill('0'), ...tailGroups]
  return expanded.slice(0, 4).map(group => parseInt(group, 16).toString(16)).join(':') + '::/64'
}

// The global 'trust proxy' setting lets clients choose req.ip via X-Forwarded-For, so only the TCP peer address is used here
export function loginClientKey (req: Request) {
  const address = req.socket.remoteAddress ?? ''
  if (address.toLowerCase().startsWith('::ffff:') && address.includes('.')) {
    return address.substring(7)
  }
  return isIPv6(address) ? ipv6Prefix64(address) : address
}

const options = {
  skipSuccessfulRequests: true,
  standardHeaders: false,
  legacyHeaders: false,
  message,
  validate: { trustProxy: false, xForwardedForHeader: false }
}

const accountKeyGenerator = (req: Request) => loginAccountKey(req.body?.email)

const failedLoginsPerAccountShortTerm = rateLimit({ ...options, windowMs: 15 * 60 * 1000, limit: 5, keyGenerator: accountKeyGenerator })
const failedLoginsPerAccountLongTerm = rateLimit({ ...options, windowMs: 24 * 60 * 60 * 1000, limit: 100, keyGenerator: accountKeyGenerator })
const failedLoginsPerClient = rateLimit({ ...options, windowMs: 15 * 60 * 1000, limit: 100, keyGenerator: loginClientKey })

export const loginThrottle = [failedLoginsPerClient, failedLoginsPerAccountShortTerm, failedLoginsPerAccountLongTerm]

export async function resetFailedLogins (email: string) {
  const key = loginAccountKey(email)
  await Promise.all([failedLoginsPerAccountShortTerm.resetKey(key), failedLoginsPerAccountLongTerm.resetKey(key)])
}
