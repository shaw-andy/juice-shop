/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawBody = (req as RequestWithRawBody).rawBody
      if (typeof rawBody === 'string' && utils.hasDuplicateJsonKeys(rawBody)) {
        res.status(400).json({ error: 'Duplicate keys are not allowed' })
        return
      }

      const user = security.authenticatedUsers.from(req)
      const { ProductId, BasketId, quantity } = req.body
      if (!user?.bid || (BasketId !== undefined && BasketId !== null && Number(user.bid) !== Number(BasketId))) {
        res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
        return
      }

      const addedBasketItem = await BasketItemModel.create({ ProductId, BasketId: user.bid, quantity })
      res.json({ status: 'success', data: addedBasketItem })
    } catch (error) {
      next(error)
    }
  }
}

export function ensureBasketItemOwnership () {
  return (req: Request, res: Response, context: { instance: BasketItemModel, error: (status: number, message: string) => void, continue: unknown }) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.bid || context.instance.BasketId == null || Number(context.instance.BasketId) !== Number(user.bid)) {
      return context.error(401, 'Invalid BasketId')
    }
    return context.continue
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}
