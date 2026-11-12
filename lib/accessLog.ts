/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type IncomingMessage } from 'node:http'
import morgan from 'morgan'

// Repeated slashes are tolerated because server.ts collapses them before routing, while morgan logs the original URL
const changePasswordPath = /\/+rest\/+user\/+change-password\/*$/i

const percentDecoded = (path: string) => path.replace(/%([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))

export const withoutChangePasswordQuery = (url?: string) => {
  if (!url) {
    return url
  }
  const queryStart = url.search(/[?#]/)
  if (queryStart === -1) {
    return url
  }
  const path = url.substring(0, queryStart)
  return changePasswordPath.test(percentDecoded(path).replace(/\\/g, '/')) ? path : url
}

morgan.token('url-without-passwords', (req: IncomingMessage & { originalUrl?: string }) => withoutChangePasswordQuery(req.originalUrl ?? req.url))
morgan.token('referrer-without-passwords', (req: IncomingMessage) => withoutChangePasswordQuery(req.headers.referer ?? (req.headers.referrer as string | undefined)))

export const combinedFormatWithoutPasswords = ':remote-addr - :remote-user [:date[clf]] ":method :url-without-passwords HTTP/:http-version" :status :res[content-length] ":referrer-without-passwords" ":user-agent"'
