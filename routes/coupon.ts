/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

export function applyCoupon () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      if (user?.data?.id == null) {
        return res.status(401).json({ status: 'error', message: 'Unauthorized' })
      }

      const basket = await BasketModel.findOne({ where: { id: req.params.id, UserId: user.data.id } })
      if (!basket) {
        return res.status(403).json({ status: 'error', message: 'Coupons can only be applied to your own basket.' })
      }

      const coupon = req.params.coupon ? decodeURIComponent(req.params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      if (!discount) {
        return res.status(404).send('Invalid coupon.')
      }

      await basket.update({ coupon })
      return res.json({ discount })
    } catch (error) {
      next(error)
    }
  }
}
