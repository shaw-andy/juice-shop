/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { STATUS_CODES } from 'node:http'
import { inspect } from 'node:util'
import { type NextFunction, type Request, type Response } from 'express'
import logger from '../lib/logger'

const statusFor = (err: any, currentStatus: number) => {
  const status = Number(err?.status ?? err?.statusCode)
  if (Number.isInteger(status) && status >= 400 && status < 600) {
    return status
  }
  return currentStatus >= 400 ? currentStatus : 500
}

export function errorHandler () {
  return (err: unknown, req: Request, res: Response, next: NextFunction) => {
    logger.warn(`Unhandled error: ${inspect(err)}`)
    if (res.headersSent) {
      next(err)
      return
    }
    const status = statusFor(err, res.statusCode)
    const message = STATUS_CODES[status] ?? 'Error'
    res.status(status)
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.format({
      html: () => res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${status} ${message}</title></head><body><h1>${status} ${message}</h1></body></html>`),
      json: () => res.json({ error: { status, message } }),
      default: () => res.type('txt').send(`${status} ${message}`)
    })
  }
}
