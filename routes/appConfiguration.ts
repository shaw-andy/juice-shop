/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

const securityAnswerKey = /securityanswer$/i

function removeSecurityAnswers (value: unknown) {
  if (Array.isArray(value)) {
    value.forEach(removeSecurityAnswers)
  } else if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      if (securityAnswerKey.test(key)) {
        delete (value as Record<string, unknown>)[key]
      } else {
        removeSecurityAnswers((value as Record<string, unknown>)[key])
      }
    }
  }
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = structuredClone(config.util.toObject(config))
    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    removeSecurityAnswers(safeConfig)
    res.json({ config: safeConfig })
  }
}
