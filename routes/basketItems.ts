/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
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

    // Only the first occurrence of a duplicated `BasketId` key is needed here, to check
    // it against the authenticated user's own basket id (see basketManipulateChallenge below).
    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      }
    }

    const user = security.authenticatedUsers.from(req)
    if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      // Use the already validated req.body values (set by quantityCheckBeforeBasketItemAddition)
      // instead of re-parsing the raw body, so the stored quantity always matches the checked one.
      const basketItem = {
        ProductId: req.body.ProductId,
        BasketId: req.body.BasketId,
        quantity: req.body.quantity
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

      try {
        const existingItem = await BasketItemModel.findOne({ where: basketItemLookupWhere(basketItem.ProductId, basketItem.BasketId) })
        let savedBasketItem
        if (existingItem != null) {
          existingItem.quantity += basketItem.quantity
          savedBasketItem = await existingItem.save()
        } else {
          savedBasketItem = await BasketItemModel.build(basketItem).save()
        }
        res.json({ status: 'success', data: savedBasketItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    const quantity = req.body.quantity
    if (!Number.isInteger(quantity) || quantity <= 0) {
      res.status(400).json({ error: res.__('Invalid quantity.') })
      return
    }

    void getExistingQuantity(req.body.ProductId, req.body.BasketId)
      .then((existingQuantity) => quantityCheck(req, res, next, req.body.ProductId, existingQuantity + quantity))
      .catch((error: Error) => {
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

function basketItemLookupWhere (productId: number, basketId: number | undefined) {
  return { ProductId: productId, BasketId: basketId === undefined ? { [Op.is]: null } : basketId }
}

async function getExistingQuantity (productId: number, basketId: number | undefined) {
  const existingItem = await BasketItemModel.findOne({ where: basketItemLookupWhere(productId, basketId) })
  return existingItem?.quantity ?? 0
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
