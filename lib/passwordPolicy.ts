/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'

const privilegedPasswordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,30}$/

export function isPrivilegedAccount (email: string | null | undefined) {
  return typeof email === 'string' && email.toLowerCase() === `support@${config.get<string>('application.domain')}`.toLowerCase()
}

export function isAcceptablePassword (email: string | null | undefined, password: unknown) {
  if (!isPrivilegedAccount(email)) {
    return true
  }
  return typeof password === 'string' && privilegedPasswordPattern.test(password)
}
