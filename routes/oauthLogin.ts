/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

const googleTokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  email?: string
  email_verified?: string | boolean
  exp?: string | number
}

async function verifiedGoogleEmail (accessToken: string): Promise<string | undefined> {
  if (!config.has('application.googleOauth.clientId')) return undefined
  const clientId = config.get<string>('application.googleOauth.clientId')

  const response = await fetch(`${googleTokenInfoUrl}?${new URLSearchParams({ access_token: accessToken }).toString()}`, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) return undefined
  const tokenInfo = await response.json() as GoogleTokenInfo

  const issuedForThisApp = clientId !== '' && tokenInfo.aud === clientId
  const emailVerified = tokenInfo.email_verified === true || tokenInfo.email_verified === 'true'
  const notExpired = Number(tokenInfo.exp) * 1000 > Date.now()
  if (!issuedForThisApp || !emailVerified || !notExpired || typeof tokenInfo.email !== 'string' || tokenInfo.email === '') return undefined
  return tokenInfo.email
}

export function oauthLogin () {
  return async (req: Request, res: Response) => {
    const accessToken = req.body?.accessToken
    let email: string | undefined
    try {
      email = typeof accessToken === 'string' && accessToken !== '' ? await verifiedGoogleEmail(accessToken) : undefined
    } catch {
      email = undefined
    }
    if (email === undefined) {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    let user: UserModel
    try {
      [user] = await UserModel.findOrCreate({ where: { email }, defaults: { email, password: security.randomPassword() } })
    } catch {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    if (user.totpSecret !== '') {
      res.status(401).json({
        status: 'totp_token_required',
        data: {
          tmpToken: security.authorize({
            userId: user.id,
            type: 'password_valid_needs_second_factor_token'
          })
        }
      })
      return
    }

    const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
    const authenticatedUser = { data: user, bid: basket.id }
    const token = security.authorize(authenticatedUser)
    security.authenticatedUsers.put(token, authenticatedUser)
    res.json({ authentication: { token, bid: basket.id, umail: user.email } })
  }
}
