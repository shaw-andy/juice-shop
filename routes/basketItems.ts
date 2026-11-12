/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { QueryTypes } from 'sequelize'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as models from '../models/index'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

// Stock not yet held by other basket lines; writes must embed it in their own statement so concurrent requests cannot both pass it.
const availableUnits = `(SELECT quantity FROM Quantities WHERE ProductId = :ProductId)
  - (SELECT COALESCE(SUM(CASE WHEN quantity > 0 THEN quantity ELSE 0 END), 0) FROM BasketItems WHERE ProductId = :ProductId AND id IS NOT :id)`

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
        const addedBasketItem = await reserveNewBasketItem({ ...basketItem, quantity: Number(basketItem.quantity) })
        if (addedBasketItem == null) {
          outOfStock(res)
          return
        }
        res.json({ status: 'success', data: addedBasketItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (await quantityCheck(req, res, req.body.ProductId, req.body.quantity)) {
        next()
      }
    } catch (error) {
      next(error)
    }
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
        if (!await quantityCheck(req, res, item.ProductId, req.body.quantity)) {
          return
        }
        if (!await reserveBasketItemQuantity(item, Number(req.body.quantity))) {
          outOfStock(res)
          return
        }
        delete req.body.quantity
      }
      next()
    } catch (error) {
      next(error)
    }
  }
}

async function reserveNewBasketItem ({ ProductId, BasketId, quantity }: { ProductId: unknown, BasketId: unknown, quantity: number }) {
  if (!Number.isFinite(quantity)) {
    return null
  }
  const now = new Date()
  const [id, inserted] = await models.sequelize.query(
    `INSERT INTO BasketItems (ProductId, BasketId, quantity, createdAt, updatedAt)
     SELECT :ProductId, :BasketId, :quantity, :now, :now WHERE ${availableUnits} >= :quantity`,
    { replacements: { ProductId: ProductId ?? null, BasketId: BasketId ?? null, quantity, now, id: null }, type: QueryTypes.INSERT }
  )
  if (inserted !== 1) {
    return null
  }
  return { id, ProductId, BasketId, quantity, createdAt: now, updatedAt: now }
}

async function reserveBasketItemQuantity (item: BasketItemModel, quantity: number) {
  if (!Number.isFinite(quantity)) {
    return false
  }
  const updated = await models.sequelize.query(
    `UPDATE BasketItems SET quantity = :quantity, updatedAt = :now
     WHERE id = :id AND ProductId = :ProductId AND ${availableUnits} >= :quantity`,
    { replacements: { ProductId: item.ProductId, id: item.id, quantity, now: new Date() }, type: QueryTypes.BULKUPDATE }
  )
  return updated === 1
}

function outOfStock (res: Response) {
  res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
}

async function quantityCheck (req: Request, res: Response, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      return true
    } else {
      outOfStock(res)
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
  return false
}
