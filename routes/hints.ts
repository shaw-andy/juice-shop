/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { Op } from 'sequelize'

import { HintModel } from '../models/hint'

export function unlockHint () {
  return async (req: Request, res: Response) => {
    if (req.body?.unlocked !== true) {
      res.status(400).json({ status: 'error', message: 'Hints can only be unlocked' })
      return
    }
    const id = Number(req.params.id)
    const hint = Number.isInteger(id) ? await HintModel.findByPk(id) : null
    if (hint == null) {
      res.status(404).json({ status: 'error', message: 'Hint not found' })
      return
    }
    if (!hint.unlocked) {
      const lockedPredecessors = await HintModel.count({
        where: { ChallengeId: hint.ChallengeId, order: { [Op.lt]: hint.order }, unlocked: { [Op.not]: true } }
      })
      if (lockedPredecessors > 0) {
        res.status(403).json({ status: 'error', message: 'Previous hints must be unlocked first' })
        return
      }
      await hint.update({ unlocked: true })
    }
    res.json({ status: 'success', data: { ...hint.toJSON(), text: req.__(hint.text) } })
  }
}
