/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export const HARDENED_PROFILE = 'hardened'

export const SIGNING_SECRET_ENV = Object.freeze({
  jwtPrivateKey: 'JUICESHOP_JWT_PRIVATE_KEY',
  jwtPublicKey: 'JUICESHOP_JWT_PUBLIC_KEY',
  cookieSecret: 'JUICESHOP_COOKIE_SECRET',
  hmacKey: 'JUICESHOP_HMAC_KEY'
})

const EXPOSED_FILE_MOUNTS = ['/ftp', '/encryptionkeys', '/support/logs', '/infrastructure', '/.well-known']

export function isHardenedProfile (): boolean {
  return process.env.JUICESHOP_PROFILE === HARDENED_PROFILE
}

export function missingSigningSecrets (): string[] {
  if (!isHardenedProfile()) {
    return []
  }
  return Object.values(SIGNING_SECRET_ENV).filter((name) => {
    const value = process.env[name]
    return value == null || value.trim() === ''
  })
}

export class MissingSigningSecretsError extends Error {
  readonly missing: readonly string[]

  constructor (missing: readonly string[]) {
    super(`Hardened profile refused to start. Missing signing secrets: ${missing.join(', ')}`)
    this.name = 'MissingSigningSecretsError'
    this.missing = missing
  }
}

export function blockExposedFileMounts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const pathname = req.path
    const blocked = EXPOSED_FILE_MOUNTS.some((mount) => pathname === mount || pathname.startsWith(`${mount}/`))
    if (!blocked) {
      next()
      return
    }
    res.status(404).type('text/plain').end()
  }
}
