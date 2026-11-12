/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function getComplaints () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)?.data
    if (user?.id == null) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const where = user.role === security.roles.admin ? {} : { UserId: user.id }
    const complaints = await ComplaintModel.findAll({ where })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
