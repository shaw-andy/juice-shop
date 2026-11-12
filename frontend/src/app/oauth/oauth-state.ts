/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const oauthStateKey = 'oauth_state'

export function createOAuthState (): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const state = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
  sessionStorage.setItem(oauthStateKey, state)
  return state
}

// The stored state is removed on every callback so it can only complete one sign-in.
export function consumeOAuthState (receivedState: string | undefined): boolean {
  const expectedState = sessionStorage.getItem(oauthStateKey)
  sessionStorage.removeItem(oauthStateKey)
  return !!expectedState && receivedState === expectedState
}
