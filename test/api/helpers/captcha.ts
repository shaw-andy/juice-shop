/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import { Op } from 'sequelize'
import { ImageCaptchaModel } from '../../../models/imageCaptcha'
import * as security from '../../../lib/insecurity'

export function solveCaptcha (expression: string): string {
  return eval(expression).toString() // eslint-disable-line no-eval
}

export async function latestImageCaptchaAnswer (token: string): Promise<string | null> {
  const user = security.authenticatedUsers.get(token)
  assert.ok(user, 'token does not belong to a logged-in user')
  const captcha = await ImageCaptchaModel.findOne({
    where: { UserId: user.data.id, answer: { [Op.not]: null } },
    order: [['createdAt', 'DESC']]
  })
  return captcha?.answer ?? null
}
