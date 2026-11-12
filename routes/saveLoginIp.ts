/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { isIP } from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const toValidIpAddress = (value: string | undefined) => {
  const ip = utils.toSimpleIpAddress(value?.trim() ?? '')
  return isIP(ip) !== 0 ? ip : undefined
}

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      let trueClientIp = req.headers['true-client-ip']
      if (Array.isArray(trueClientIp)) {
        trueClientIp = trueClientIp[0]
      }
      if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
        challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return trueClientIp === '<iframe src="javascript:alert(`xss`)">' })
      }
      const lastLoginIp = toValidIpAddress(trueClientIp) ?? toValidIpAddress(req.socket.remoteAddress) ?? '0.0.0.0'
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp })
        res.json(updatedUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
