/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UniqueConstraintError } from 'sequelize'
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
    if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: basketIds[basketIds.length - 1],
        quantity: quantities[quantities.length - 1]
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

      try {
        const existingBasketItem = await findBasketItem(basketItem.BasketId, basketItem.ProductId)
        if (existingBasketItem != null) {
          res.json({ status: 'success', data: await incrementQuantity(existingBasketItem, basketItem.quantity) })
          return
        }
        try {
          const addedBasketItem = await BasketItemModel.build(basketItem).save()
          res.json({ status: 'success', data: addedBasketItem })
        } catch (error) {
          // A concurrent request for the same product may have inserted the row in the meantime
          const concurrentlyAddedItem = error instanceof UniqueConstraintError ? await findBasketItem(basketItem.BasketId, basketItem.ProductId) : null
          if (concurrentlyAddedItem == null) throw error
          res.json({ status: 'success', data: await incrementQuantity(concurrentlyAddedItem, basketItem.quantity) })
        }
      } catch (error) {
        next(error)
      }
    }
  }
}

async function findBasketItem (basketId: unknown, productId: unknown) {
  if (basketId == null || productId == null) return null
  return await BasketItemModel.findOne({ where: { BasketId: basketId as number, ProductId: productId as number } })
}

async function incrementQuantity (basketItem: BasketItemModel, quantity: unknown) {
  await basketItem.increment('quantity', { by: Number(quantity) })
  return await basketItem.reload()
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void (async () => {
      const existingBasketItem = await findBasketItem(req.body.BasketId, req.body.ProductId)
      const combinedQuantity = Number(req.body.quantity) + (existingBasketItem?.quantity ?? 0)
      await quantityCheck(req, res, next, req.body.ProductId, combinedQuantity)
    })().catch((error: Error) => {
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
