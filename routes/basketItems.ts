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
    const basketIds = []

    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      }
    }

    const user = security.authenticatedUsers.from(req)
    if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      // ProductId and quantity are taken from the already validated req.body (see
      // quantityCheckBeforeBasketItemAddition) rather than re-parsed from the raw
      // body, so the quantity that gets persisted always matches the one that was checked.
      const basketItem = {
        ProductId: req.body.ProductId,
        BasketId: basketIds[basketIds.length - 1],
        quantity: Number(req.body.quantity)
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

      try {
        const existingItem = await BasketItemModel.findOne({
          where: { ProductId: basketItem.ProductId, BasketId: basketItem.BasketId ?? null }
        })

        let savedItem
        if (existingItem) {
          existingItem.quantity += basketItem.quantity
          savedItem = await existingItem.save()
        } else {
          const basketItemInstance = BasketItemModel.build(basketItem)
          savedItem = await basketItemInstance.save()
        }
        res.json({ status: 'success', data: savedItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    const quantity = Number(req.body.quantity)
    if (!Number.isInteger(quantity) || quantity <= 0) {
      res.status(400).json({ error: res.__('Invalid quantity. Quantity must be a positive integer.') })
      return
    }
    void quantityCheck(req, res, next, req.body.ProductId, quantity, req.body.BasketId).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        await quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

// `basketId` is only passed in when checking an addition (as opposed to an update of an
// existing basket item), so that the existing quantity for that product in that basket can
// be combined with the newly requested quantity before validating stock/limitPerUser.
async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number, basketId?: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  let existingQuantity = 0
  if (basketId) {
    const existingItem = await BasketItemModel.findOne({ where: { ProductId: id, BasketId: basketId } })
    if (existingItem) {
      existingQuantity = existingItem.quantity
    }
  }
  const totalQuantity = existingQuantity + Number(quantity)

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= totalQuantity) || security.isDeluxe(req)) {
    if (product.quantity >= totalQuantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}
