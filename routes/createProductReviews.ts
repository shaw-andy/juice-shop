/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import { ProductModel } from '../models/product'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import {
  isBoundedString,
  MAX_REVIEW_AUTHOR_LENGTH,
  MAX_REVIEW_MESSAGE_LENGTH,
  MAX_REVIEWS_PER_PRODUCT,
  MAX_REVIEWS_TOTAL
} from '../lib/productReviewLimits'

let pendingInsert: Promise<unknown> = Promise.resolve()

// Counting and inserting must not interleave between requests, otherwise concurrent creates overshoot the caps
async function serialized<T> (task: () => Promise<T>): Promise<T> {
  const result = pendingInsert.then(task)
  pendingInsert = result.catch(() => {})
  return await result
}

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const message: unknown = req.body?.message
    const author: unknown = req.body?.author
    if (!isBoundedString(message, MAX_REVIEW_MESSAGE_LENGTH) || !isBoundedString(author, MAX_REVIEW_AUTHOR_LENGTH)) {
      return res.status(400).json({ error: 'Invalid review' })
    }

    const productId = Number(req.params.id)
    const product = Number.isSafeInteger(productId) ? await ProductModel.findByPk(productId) : null
    if (product === null) {
      return res.status(404).json({ error: 'Not found' })
    }

    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== author
    )

    try {
      const created = await serialized(async () => {
        const [reviewsForProduct, reviewsTotal] = await Promise.all([
          reviewsCollection.count({ product: product.id }),
          reviewsCollection.count({})
        ])
        if (reviewsForProduct >= MAX_REVIEWS_PER_PRODUCT || reviewsTotal >= MAX_REVIEWS_TOTAL) {
          return false
        }
        await reviewsCollection.insert({
          product: product.id,
          message,
          author,
          likesCount: 0,
          likedBy: []
        })
        return true
      })
      if (!created) {
        return res.status(400).json({ error: 'Review limit reached' })
      }
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
