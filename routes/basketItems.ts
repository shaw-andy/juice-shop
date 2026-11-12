/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
    const productIds = []
    const basketIds = []
    const quantities = []

    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'ProductId') {
        productIds.push(result[i].value)
      } else if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      } else if (result[i].key === 'quantity') {
        quantities.push(result[i].value)
      }
    }

    const user = security.authenticatedUsers.from(req)
    const isForeignBasket = (basketId: unknown) => Number(basketId) !== Number(user?.bid)
    if (user?.bid == null || (basketIds.length > 0 && isForeignBasket(basketIds[0]))) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else if (basketIds.some(isForeignBasket)) {
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => true)
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: user.bid,
        quantity: quantities[quantities.length - 1]
      }

      const basketItemInstance = BasketItemModel.build(basketItem)
      try {
        const addedBasketItem = await basketItemInstance.save()
        res.json({ status: 'success', data: addedBasketItem })
      } catch (error) {
        next(error)
      }
    }
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
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (user?.bid == null) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }
      const item = await BasketItemModel.findOne({ where: { id: req.params.id, BasketId: user.bid } })
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

interface FinaleContext {
  criteria: Record<string, unknown>
  instance: unknown
  continue: unknown
  skip: unknown
  error: (status: number, message: string) => void
}

export function listSessionBasketItems () {
  return async (req: Request, res: Response, context: FinaleContext) => {
    const bid = security.authenticatedUsers.from(req)?.bid
    if (bid == null) {
      context.error(401, 'Unauthorized')
      return
    }
    context.instance = await BasketItemModel.findAll({ where: { BasketId: bid } })
    return context.skip
  }
}

export function restrictFetchToSessionBasket () {
  return (req: Request, res: Response, context: FinaleContext) => {
    const bid = security.authenticatedUsers.from(req)?.bid
    if (bid == null) {
      context.error(401, 'Unauthorized')
      return
    }
    context.criteria = { BasketId: bid }
    return context.continue
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
