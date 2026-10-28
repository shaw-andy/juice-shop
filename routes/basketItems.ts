/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UniqueConstraintError, Op, literal } from 'sequelize'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

class BasketQuantityError extends Error {
  constructor (readonly clientMessage: string) {
    super(clientMessage)
  }
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
        let existingBasketItem = await findExistingBasketItem(basketItem.ProductId, basketItem.BasketId)
        if (existingBasketItem == null) {
          try {
            const addedBasketItem = await BasketItemModel.build(basketItem).save()
            res.json({ status: 'success', data: addedBasketItem })
            return
          } catch (error) {
            // A concurrent add of the same product can insert the row between lookup and save
            if (!(error instanceof UniqueConstraintError)) throw error
            existingBasketItem = await findExistingBasketItem(basketItem.ProductId, basketItem.BasketId)
            if (existingBasketItem == null) throw error
          }
        }
        const data = await incrementBasketItemWithinLimits(req, res, existingBasketItem, basketItem.ProductId, Number(basketItem.quantity))
        res.json({ status: 'success', data })
      } catch (error) {
        if (error instanceof BasketQuantityError) {
          res.status(400).json({ error: error.clientMessage })
          return
        }
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void findExistingBasketItem(req.body.ProductId, req.body.BasketId).then(async (existingBasketItem) => {
      const quantity = existingBasketItem != null ? existingBasketItem.quantity + Number(req.body.quantity) : req.body.quantity
      await quantityCheck(req, res, next, req.body.ProductId, quantity)
    }).catch((error: Error) => {
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

async function findExistingBasketItem (productId: number, basketId: number | string | undefined) {
  if (productId == null || basketId == null || basketId === 'undefined') {
    return null
  }
  return await BasketItemModel.findOne({ where: { ProductId: productId, BasketId: basketId } })
}

async function incrementBasketItemWithinLimits (req: Request, res: Response, existingBasketItem: BasketItemModel, productId: number, addBy: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: productId } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  let maxAllowed = product.quantity
  if (product.limitPerUser && !security.isDeluxe(req)) {
    maxAllowed = Math.min(maxAllowed, product.limitPerUser)
  }

  // Atomic conditional increment so concurrent adds cannot push quantity past limit/stock
  for (let attempt = 0; attempt < 3; attempt++) {
    const [affectedCount] = await BasketItemModel.update(
      { quantity: literal(`quantity + ${addBy}`) },
      {
        where: {
          id: existingBasketItem.id,
          quantity: { [Op.lte]: maxAllowed - addBy }
        }
      }
    )
    if (affectedCount > 0) {
      return await existingBasketItem.reload()
    }
    await assertQuantityAllowed(req, res, productId, (await existingBasketItem.reload()).quantity + addBy)
  }
  throw new BasketQuantityError(res.__('We are out of stock! Sorry for the inconvenience.'))
}

async function assertQuantityAllowed (req: Request, res: Response, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      return
    }
    throw new BasketQuantityError(res.__('We are out of stock! Sorry for the inconvenience.'))
  }
  throw new BasketQuantityError(res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }))
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  try {
    await assertQuantityAllowed(req, res, id, quantity)
    next()
  } catch (error) {
    if (error instanceof BasketQuantityError) {
      res.status(400).json({ error: error.clientMessage })
      return
    }
    throw error
  }
}
