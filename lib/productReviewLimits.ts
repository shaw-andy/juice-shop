/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export const MAX_REVIEW_MESSAGE_LENGTH = 2000
export const MAX_REVIEW_AUTHOR_LENGTH = 320
export const MAX_REVIEWS_PER_PRODUCT = 20
// Users can add products, so the per-product cap alone does not bound the in-memory collection
export const MAX_REVIEWS_TOTAL = 1000
export const MAX_LIKES_PER_REVIEW = 100

export const isBoundedString = (value: unknown, maxLength: number): value is string =>
  typeof value === 'string' && value.length <= maxLength

export function checkReviewMessage () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isBoundedString(req.body?.message, MAX_REVIEW_MESSAGE_LENGTH)) {
      return res.status(400).json({ error: 'Invalid review' })
    }
    next()
  }
}
