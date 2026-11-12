/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'
import { AddressModel } from '../models/address'

import * as utils from '../lib/utils'

export const createRecycleItem = () => async (req: Request, res: Response) => {
  const UserId: number = req.body.UserId
  const addressId = Number(req.body.AddressId)
  if (!Number.isInteger(addressId)) {
    return res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
  }
  // The ownership lookup and the insert share a transaction so the stored AddressId is the one that was verified.
  const recycle = await RecycleModel.sequelize!.transaction(async (transaction) => {
    const address = await AddressModel.findOne({ where: { id: addressId, UserId }, transaction })
    if (address == null) {
      return null
    }
    return await RecycleModel.create({
      UserId,
      AddressId: address.id,
      quantity: req.body.quantity,
      isPickup: req.body.isPickup,
      date: req.body.date
    }, { transaction })
  })
  if (recycle == null) {
    return res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
  }
  return res.status(201).json({ status: 'success', data: recycle })
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
