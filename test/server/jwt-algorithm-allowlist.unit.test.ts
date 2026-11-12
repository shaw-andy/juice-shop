/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import jws from 'jws'
import type { NextFunction, Request, Response } from 'express'
import * as security from '../../lib/insecurity'

type ForgedAlgorithm = 'none' | 'None' | 'HS256' | 'HS384' | 'HS512'

function forgedToken (algorithm: ForgedAlgorithm, data: Record<string, unknown>): string {
  return jws.sign({
    header: { alg: algorithm, typ: 'JWT' },
    payload: { data },
    secret: algorithm.toLowerCase() === 'none' ? 'placeholder' : security.publicKey
  })
}

function bearer (token: string): Request {
  return {
    cookies: {},
    headers: { authorization: 'Bearer ' + token },
    body: {}
  } as unknown as Request
}

const algorithms: ForgedAlgorithm[] = ['none', 'None', 'HS256', 'HS384', 'HS512']

void describe('JWT verification allow-list', { concurrency: false }, () => {
  void it('still accepts an RS256 token from authorize', () => {
    const token = security.authorize({ data: { role: security.roles.admin } })
    assert.equal(security.verify(token), true)
  })

  for (const algorithm of algorithms) {
    void it('verify rejects a ' + algorithm + ' token signed without the private key', () => {
      const token = forgedToken(algorithm, { role: security.roles.admin, email: 'admin@juice-sh.op', id: 1 })
      assert.equal(security.verify(token), false)
    })

    void it('isAuthorized rejects a ' + algorithm + ' bearer and does not attach req.user', () => {
      const token = forgedToken(algorithm, { role: security.roles.admin, email: 'admin@juice-sh.op', id: 1 })
      const req = bearer(token) as Request & { user?: unknown }
      let status = 0
      let forwarded: unknown = 'not-called'
      const res = {
        status (code: number) { status = code; return res },
        json () { return res }
      } as unknown as Response
      const next: NextFunction = (err?: unknown) => { forwarded = err }
      security.isAuthorized()(req, res, next)
      assert.equal(req.user, undefined)
      assert.equal(status === 401 || (forwarded !== 'not-called' && forwarded !== undefined), true)
    })

    void it('updateAuthenticatedUsers does not store a ' + algorithm + ' token or set a cookie', () => {
      const token = forgedToken(algorithm, { role: security.roles.admin, email: 'admin@juice-sh.op', id: 1 })
      const req = bearer(token)
      let cookieSet = false
      let nextCalled = false
      const res = {
        cookie () { cookieSet = true },
        status () { return res },
        json () { return res }
      } as unknown as Response
      security.updateAuthenticatedUsers()(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, true)
      assert.equal(cookieSet, false)
      assert.equal(security.authenticatedUsers.get(token), undefined)
      assert.notEqual(security.authenticatedUsers.idMap[1], token)
    })

    void it('updateAuthenticatedUsers does not store a ' + algorithm + ' cookie when the bearer is different', () => {
      const cookieToken = forgedToken(algorithm, { role: security.roles.admin, email: 'cookie-admin@juice-sh.op', id: 1 })
      const headerToken = forgedToken(algorithm, { role: security.roles.customer, email: 'header-user@juice-sh.op', id: 2 })
      const req = bearer(headerToken)
      req.cookies = { token: cookieToken }
      let cookieSet = false
      const res = {
        cookie () { cookieSet = true }
      } as unknown as Response
      security.updateAuthenticatedUsers()(req, res, () => {})
      assert.equal(cookieSet, false)
      assert.equal(security.authenticatedUsers.get(cookieToken), undefined)
      assert.equal(security.authenticatedUsers.get(headerToken), undefined)
      const storedEmails = Object.values(security.authenticatedUsers.tokenMap).map((entry) => entry?.data?.email)
      assert.equal(storedEmails.includes('cookie-admin@juice-sh.op'), false)
      assert.equal(storedEmails.includes('header-user@juice-sh.op'), false)
    })

    void it('isAccounting rejects a ' + algorithm + ' accounting token', () => {
      const token = forgedToken(algorithm, { role: security.roles.accounting, email: 'accountant@juice-sh.op', id: 1 })
      const req = bearer(token)
      let status = 0
      let nextCalled = false
      const res = {
        status (code: number) { status = code; return res },
        json () { return res }
      } as unknown as Response
      security.isAccounting()(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, false)
      assert.equal(status, 403)
    })

    void it('isCustomer rejects a ' + algorithm + ' customer token', () => {
      const token = forgedToken(algorithm, { role: security.roles.customer, email: 'customer@juice-sh.op', id: 2 })
      assert.equal(security.isCustomer(bearer(token)), false)
    })

    void it('isDeluxe rejects a ' + algorithm + ' token even when deluxeToken matches the server helper', () => {
      const email = 'deluxe@juice-sh.op'
      const token = forgedToken(algorithm, {
        role: security.roles.deluxe,
        email,
        id: 1,
        deluxeToken: security.deluxeToken(email)
      })
      assert.equal(security.isDeluxe(bearer(token)), false)
    })
  }
})
