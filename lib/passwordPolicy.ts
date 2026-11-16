/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export const minimumPasswordLength = 8

export const passwordTooShortMessage = `Password must be at least ${minimumPasswordLength} characters long.`

export function isPasswordTooShort (password: unknown) {
  return typeof password !== 'string' || password.length < minimumPasswordLength
}
