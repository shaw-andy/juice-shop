/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op, Sequelize } from 'sequelize'

import * as challengeUtils from '../lib/challengeUtils'
import { WalletModel } from '../models/wallet'
import { exclusiveTransaction } from '../models/index'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { CardModel } from '../models/card'
import * as utils from '../lib/utils'

const membershipCost = 49

class UpgradeRefused extends Error {}

export function upgradeToDeluxe () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await UserModel.findOne({ where: { id: req.body.UserId, role: security.roles.customer } })
      if (user == null) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
        return
      }
      if (req.body.paymentMode === 'card') {
        const card = await CardModel.findOne({ where: { id: req.body.paymentId, UserId: req.body.UserId } })
        if ((card == null) || card.expYear < new Date().getFullYear() || (card.expYear === new Date().getFullYear() && card.expMonth - 1 < new Date().getMonth())) {
          res.status(400).json({ status: 'error', error: 'Invalid Card' })
          return
        }
      }

      try {
        await exclusiveTransaction(async (transaction) => {
          const [upgradedUsers] = await UserModel.update(
            { role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) },
            { where: { id: user.id, role: security.roles.customer }, transaction }
          )
          if (upgradedUsers !== 1) {
            throw new UpgradeRefused('Something went wrong. Please try again!')
          }
          if (req.body.paymentMode === 'wallet') {
            const wallet = await WalletModel.findOne({ where: { UserId: user.id }, transaction })
            const [debitedWallets] = wallet != null
              ? await WalletModel.update(
                { balance: Sequelize.literal(`balance - ${membershipCost}`) },
                { where: { id: wallet.id, balance: { [Op.gte]: membershipCost } }, transaction }
              )
              : [0]
            if (debitedWallets !== 1) {
              throw new UpgradeRefused('Insuffienct funds in Wallet')
            }
          }
        })
      } catch (error) {
        if (error instanceof UpgradeRefused) {
          res.status(400).json({ status: 'error', error: error.message })
          return
        }
        throw error
      }

      try {
        const updatedUser = await user.reload()
        challengeUtils.solveIf(challenges.freeDeluxeChallenge, () => {
          return security.verify(utils.jwtFrom(req)) && req.body.paymentMode !== 'wallet' && req.body.paymentMode !== 'card'
        })
        const userWithStatus = utils.queryResultToJson(updatedUser)
        const updatedToken = security.authorize(userWithStatus)
        security.authenticatedUsers.put(updatedToken, userWithStatus)
        res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } })
      } catch (error) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
      }
    } catch (err: unknown) {
      res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) })
    }
  }
}

export function deluxeMembershipStatus () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (security.isCustomer(req)) {
      res.status(200).json({ status: 'success', data: { membershipCost } })
    } else if (security.isDeluxe(req)) {
      res.status(400).json({ status: 'error', error: 'You are already a deluxe member!' })
    } else {
      res.status(400).json({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    }
  }
}
