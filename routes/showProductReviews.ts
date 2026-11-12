/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '@juice-shop/data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Truncate id to avoid unintentional RCE
    const id = !utils.isChallengeEnabled(challenges.noSqlCommandChallenge) ? Number(req.params.id) : utils.trunc(req.params.id, 40)

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    // MarsDB does not catch errors thrown by a $where clause, which leaves the query promise pending forever
    let matchesProduct: (this: Review, obj: Review) => boolean
    try {
      // eslint-disable-next-line no-new-func
      matchesProduct = Function('obj', 'return this.product == ' + id) as typeof matchesProduct
    } catch {
      return res.status(400).json({ error: 'Wrong Params' })
    }
    let whereFailed = false

    db.reviewsCollection.find({
      $where: function (this: Review, obj: Review) {
        try {
          return matchesProduct.call(this, obj)
        } catch {
          whereFailed = true
          return false
        }
      }
    }).then((reviews: Review[]) => {
      const t1 = new Date().getTime()
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })
      if (whereFailed) {
        return res.status(400).json({ error: 'Wrong Params' })
      }
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
