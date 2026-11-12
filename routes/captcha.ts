/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'

const operators = ['*', '+', '-']
const captchaSecret = crypto.randomBytes(32)

// Challenges are derived from their id instead of being stored, so issuing one never writes to the database
function expressionFor (captchaId: number) {
  const digest = crypto.createHmac('sha256', captchaSecret).update(captchaId.toString()).digest()
  const term = (index: number) => ((digest[index] % 10) + 1).toString()
  const operator = (index: number) => operators[digest[index] % operators.length]
  return term(0) + operator(1) + term(2) + operator(3) + term(4)
}

function answerFor (expression: string) {
  return eval(expression).toString() // eslint-disable-line no-eval
}

function issuedCaptchaId (req: Request): number | undefined {
  const value = req.body?.captchaId
  const captchaId = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value
  if (Number.isSafeInteger(captchaId) && captchaId >= 0 && captchaId < req.app.locals.captchaId) {
    return captchaId
  }
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const expression = expressionFor(captchaId)

    res.json({
      captchaId,
      captcha: expression,
      answer: answerFor(expression)
    })
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  const captchaId = issuedCaptchaId(req)
  if (captchaId !== undefined && req.body.captcha === answerFor(expressionFor(captchaId))) {
    next()
  } else {
    res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
  }
}
