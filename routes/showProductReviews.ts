/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { type Review } from '@juice-shop/data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = Number(req.params.id)

    // Reviews created via the API store the product id as the raw path string
    db.reviewsCollection.find({ $where: (review: { product: unknown }) => Number(review.product) === id }).then((reviews: Review[]) => {
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
