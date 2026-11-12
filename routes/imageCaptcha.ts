/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import { ImageCaptchaModel } from '../models/imageCaptcha'
import * as security from '../lib/insecurity'

const CAPTCHA_VALIDITY_MS = 300000

export function imageCaptchas () {
  return async (req: Request, res: Response) => {
    try {
      const { default: svgCaptcha } = await import('svg-captcha')
      const captcha = svgCaptcha.create({ size: 5, noise: 2, color: true })

      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'))
        return
      }

      await ImageCaptchaModel.create({
        image: captcha.data,
        answer: captcha.text,
        UserId: user.data.id
      })
      res.json({ image: captcha.data })
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    const UserId = user?.data?.id
    if (UserId === undefined || UserId === null) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    const notExpired = { [Op.gt]: new Date(Date.now() - CAPTCHA_VALIDITY_MS) }
    const captcha = await ImageCaptchaModel.findOne({
      where: { UserId, createdAt: notExpired },
      order: [['createdAt', 'DESC'], ['id', 'DESC']]
    })
    // The conditional update claims the CAPTCHA for exactly one check, whether its answer is right or wrong
    const [claimed] = captcha
      ? await ImageCaptchaModel.update({ used: true }, { where: { id: captcha.id, UserId, used: false, createdAt: notExpired } })
      : [0]
    if (captcha && claimed === 1 && typeof req.body.answer === 'string' && req.body.answer === captcha.answer) {
      res.locals.imageCaptchaUserId = UserId
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
