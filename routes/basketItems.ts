/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ValidationError } from 'sequelize'
import { type ValidationOptions } from 'sequelize/types/instance-validator'
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
export function updateBasketItem () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
    challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
    if (item == null) {
      throw new Error('No such item found!')
    }
    if (!belongsToSessionBasket(item, user?.bid)) {
      return res.status(401).json({ error: 'Invalid BasketId' })
    }
    const authorizedBasketId = item.BasketId

    for (const field of ['ProductId', 'BasketId', 'quantity'] as const) {
      if (req.body[field] !== undefined) {
        item.set(field, req.body[field])
      }
    }
    try {
      await item.validate({ validate: true } as ValidationOptions)
    } catch (error) {
      if (error instanceof ValidationError) {
        return res.status(400).json({ message: error.message, errors: error.errors.map(({ path, message }) => ({ field: path, message })) })
      }
      throw error
    }

    const quantity = req.body.quantity
    if (quantity !== undefined) {
      const quantityError = await quantityErrorFor(req, res, item.ProductId, quantity)
      if (quantityError) {
        return res.status(400).json({ error: quantityError })
      }
      // The row can change between the read above and this write, so only write it if it is still in the authorized basket
      const [updatedRows] = await BasketItemModel.update({ quantity }, { where: { id: item.id, BasketId: authorizedBasketId } })
      if (updatedRows === 0) {
        return res.status(401).json({ error: 'Invalid BasketId' })
      }
    }
    res.json({ status: 'success', data: item })
  }
}

export function deleteBasketItem () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
    if (item == null) {
      return res.status(404).json({ message: 'Not Found', errors: [] })
    }
    if (!belongsToSessionBasket(item, user?.bid)) {
      return res.status(401).json({ error: 'Invalid BasketId' })
    }
    const deletedRows = await BasketItemModel.destroy({ where: { id: item.id, BasketId: item.BasketId } })
    if (deletedRows === 0) {
      return res.status(401).json({ error: 'Invalid BasketId' })
    }
    res.json({ status: 'success', data: {} })
  }
}

function belongsToSessionBasket (item: BasketItemModel, sessionBasketId?: number) {
  return sessionBasketId != null && item.BasketId != null && Number(item.BasketId) === Number(sessionBasketId)
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const quantityError = await quantityErrorFor(req, res, id, quantity)
  if (quantityError) {
    res.status(400).json({ error: quantityError })
  } else {
    next()
  }
}

async function quantityErrorFor (req: Request, res: Response, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      return null
    }
    return res.__('We are out of stock! Sorry for the inconvenience.')
  }
  return res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() })
}
