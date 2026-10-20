/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export const PROFILE_ENV = 'JUICESHOP_PROFILE'
export const HARDENED_PROFILE = 'hardened'

export const SIGNING_SECRET_ENV = Object.freeze({
  jwtPrivateKey: 'JUICESHOP_JWT_PRIVATE_KEY',
  jwtPublicKey: 'JUICESHOP_JWT_PUBLIC_KEY',
  cookieSecret: 'JUICESHOP_COOKIE_SECRET',
  hmacKey: 'JUICESHOP_HMAC_KEY'
})

export type SigningSecrets = Record<keyof typeof SIGNING_SECRET_ENV, string>

export const EXPOSED_FILE_MOUNTS = Object.freeze(['/ftp', '/encryptionkeys', '/support/logs', '/infrastructure', '/.well-known'])

export class MissingSigningSecretsError extends Error {
  readonly missing: readonly string[]

  constructor (missing: readonly string[]) {
    super(`Refusing to start the ${HARDENED_PROFILE} profile without signing secrets. Set ${missing.join(', ')} in the environment.`)
    this.name = 'MissingSigningSecretsError'
    this.missing = missing
  }
}

export function isHardened (env: NodeJS.ProcessEnv = process.env): boolean {
  return env[PROFILE_ENV] === HARDENED_PROFILE
}

export function signingSecretsFromEnv (env: NodeJS.ProcessEnv = process.env): SigningSecrets {
  const missing = Object.values(SIGNING_SECRET_ENV).filter((name) => env[name] == null || env[name]?.trim() === '')
  if (missing.length > 0) {
    throw new MissingSigningSecretsError(missing)
  }
  const secrets: Partial<SigningSecrets> = {}
  for (const [key, name] of Object.entries(SIGNING_SECRET_ENV) as Array<[keyof SigningSecrets, string]>) {
    // PEM material is commonly passed through single-line env files with escaped line breaks
    secrets[key] = (env[name] as string).replace(/\\n/g, '\n')
  }
  return secrets as SigningSecrets
}
