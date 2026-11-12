/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'

type AuthorizedRequest = Request & { user?: { data?: { id?: unknown } } }

// Must run after security.isAuthorized(), which puts the verified token payload on req.user
export function getComplaints () {
  return async (req: AuthorizedRequest, res: Response) => {
    const userId = req.user?.data?.id
    if (typeof userId !== 'number') {
      res.status(200).json({ status: 'success', data: [] })
      return
    }
    const complaints = await ComplaintModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
