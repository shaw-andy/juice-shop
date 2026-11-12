/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

async function callerFrom (req: Request) {
  const id = security.verifiedPayload(utils.jwtFrom(req))?.data?.id
  return Number.isInteger(id) ? await UserModel.findByPk(id) : null
}

function isAdministrator (user: UserModel) {
  return user.role === security.roles.admin
}

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const caller = await callerFrom(req)
    if (caller === null) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const users = isAdministrator(caller) ? await UserModel.findAll() : [caller]

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          const parsedToken = decode(userToken, { json: true })
          lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null
        }

        return {
          ...user.dataValues,
          password: user.password?.replace(/./g, '*'),
          totpSecret: user.totpSecret?.replace(/./g, '*'),
          lastLoginTime
        }
      })
    })
  } catch (error) {
    next(error)
  }
}

function authorizeCaller (isPermitted: (caller: UserModel, req: Request) => boolean) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const caller = await callerFrom(req)
      if (caller === null) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
      } else if (isAdministrator(caller) || isPermitted(caller, req)) {
        next()
      } else {
        res.status(403).json({ status: 'error', message: 'Forbidden' })
      }
    } catch (error) {
      next(error)
    }
  }
}

export const restrictToAdministrator = () => authorizeCaller(() => false)

export const restrictToAdministratorOrSelf = () => authorizeCaller((caller, req) => req.params.id === String(caller.id))

export default () => retrieveUserList
