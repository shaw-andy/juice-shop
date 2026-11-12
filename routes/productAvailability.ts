/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import { QuantityModel } from '../models/quantity'

/* Matches the "Only {{quantity}} left" and "Sold out" ribbons of the product grid */
const LOW_STOCK_THRESHOLD = 5

export function getProductAvailability () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const lowStock = await QuantityModel.findAll({
      attributes: ['ProductId', 'quantity'],
      where: { quantity: { [Op.lte]: LOW_STOCK_THRESHOLD } }
    })
    res.status(200).json({
      status: 'success',
      data: lowStock.map(({ ProductId, quantity }) => ({ ProductId, quantity }))
    })
  }
}
