/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Imported before the application so node-config picks this up at load time.
// Safety mode turns off the persisted XSS challenges, which is when model
// setters and the login-IP route call the recursive cleaner.
const existing = process.env.NODE_CONFIG ? JSON.parse(process.env.NODE_CONFIG) as { challenges?: Record<string, unknown> } : {}
process.env.NODE_CONFIG = JSON.stringify({
  ...existing,
  challenges: {
    ...existing.challenges,
    safetyMode: 'enabled'
  }
})
