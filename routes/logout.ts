/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function logout () {
  return (req: Request, res: Response) => {
    security.revokeSession(utils.jwtFrom(req))
    security.revokeSession(req.cookies.token)
    res.clearCookie('token')
    res.json({ status: 'success' })
  }
}
