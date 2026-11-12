/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { type Sequelize, ValidationError } from 'sequelize'
import { ProductModel } from '../models/product'
import { QuantityModel } from '../models/quantity'

// SQLite allows a single writer, so overlapping transactions would exhaust Sequelize's SQLITE_BUSY retries
let previousCreation: Promise<unknown> = Promise.resolve()

export function createProduct (sequelize: Sequelize) {
  return async (req: Request, res: Response) => {
    const insertProductWithStock = async () => await sequelize.transaction(async (transaction) => {
      const created = await ProductModel.create(req.body, { transaction })
      await QuantityModel.create({ ProductId: created.id, quantity: 0 }, { transaction })
      return created
    })
    const creation = previousCreation.then(insertProductWithStock, insertProductWithStock)
    previousCreation = creation.catch(() => {})

    let product: ProductModel
    try {
      product = await creation
    } catch (error) {
      if (error instanceof ValidationError) {
        res.status(400).json({
          message: error.message,
          errors: error.errors.map(({ path, message }) => ({ field: path, message }))
        })
        return
      }
      throw error
    }
    await product.reload()
    res.location(`/api/Products/${product.id}`).status(201).json({ status: 'success', data: product })
  }
}
