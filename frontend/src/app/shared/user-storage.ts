/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { CHAT_CONVERSATIONS_STORAGE_KEY } from '../Services/conversation-storage.service'

export const TOTP_TMP_TOKEN_KEY = 'totp_tmp_token'

// Must run wherever the session token is dropped, so the next user of this browser cannot read or reuse it.
export function clearUserScopedStorage (): void {
  localStorage.removeItem(CHAT_CONVERSATIONS_STORAGE_KEY)
  localStorage.removeItem(TOTP_TMP_TOKEN_KEY)
}
