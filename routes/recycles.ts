/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { RecycleModel } from '../models/recycle'
import { findAddressOfUser } from './address'

import * as utils from '../lib/utils'

export const verifyRecycleAddress = () => async (req: Request, res: Response, next: NextFunction) => {
  const address = await findAddressOfUser(req.body.AddressId, req.body.UserId)
  if (address == null) {
    res.status(400).json({ status: 'error', data: 'Invalid pickup address.' })
    return
  }
  req.body.AddressId = address.id
  next()
}

export const getRecycleItem = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id)
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
