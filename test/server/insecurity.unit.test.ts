/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import type { UserModel } from '@juice-shop/models/user'
import type { Request } from 'express'

void describe('insecurity', () => {
  void describe('cutOffPoisonNullByte', () => {
    void it('returns string unchanged if it contains no null byte', () => {
      assert.equal(security.cutOffPoisonNullByte('file.exe.pdf'), 'file.exe.pdf')
    })

    void it('returns string up to null byte', () => {
      assert.equal(security.cutOffPoisonNullByte('file.exe%00.pdf'), 'file.exe')
    })
  })

  void describe('userEmailFrom', () => {
    void it('returns content of "x-user-email" header if present', () => {
      assert.equal(security.userEmailFrom({ headers: { 'x-user-email': 'test@bla.blubb' } }), 'test@bla.blubb')
    })

    void it('returns undefined if header "x-user-email" is not present', () => {
      assert.equal(security.userEmailFrom({ headers: {} }), undefined)
      assert.equal(security.userEmailFrom({}), undefined)
    })
  })

  void describe('generateCoupon', () => {
    void it('returns a random 10 character alphanumeric coupon code', () => {
      const coupon = security.generateCoupon(10)
      assert.match(coupon, /^[A-Za-z0-9]{10}$/)
      assert.notEqual(coupon, security.generateCoupon(10))
    })

    void it('does not encode month, year or discount into coupon code', () => {
      const coupon = security.generateCoupon(10, new Date('1980-01-02'))
      assert.doesNotMatch(z85.decode(coupon)?.toString() ?? '', /JAN80/)
    })

    void it('refuses discounts outside the allowed range', () => {
      assert.throws(() => security.generateCoupon(0))
      assert.throws(() => security.generateCoupon(security.maxCouponDiscount + 1))
      assert.throws(() => security.generateCoupon(99))
      assert.throws(() => security.generateCoupon(5.5))
    })
  })

  void describe('discountFromCoupon', () => {
    void it('returns undefined when not passing in a coupon code', () => {
      assert.equal(security.discountFromCoupon(undefined), undefined)
    })

    void it('returns undefined for malformed coupon code', () => {
      assert.equal(security.discountFromCoupon(''), undefined)
      assert.equal(security.discountFromCoupon('x'), undefined)
      assert.equal(security.discountFromCoupon('___'), undefined)
    })

    void it('returns undefined for coupon code that was not issued by the server', () => {
      assert.equal(security.discountFromCoupon(z85.encode('Test')), undefined)
      assert.equal(security.discountFromCoupon(z85.encode('SEP14-50')), undefined)
      assert.equal(security.discountFromCoupon(z85.encode(utils.toMMMYY(new Date()) + '-99')), undefined)
      assert.equal(security.discountFromCoupon(z85.encode(utils.toMMMYY(new Date()) + '-10')), undefined)
      assert.equal(security.discountFromCoupon('constructor'), undefined)
    })

    void it('returns undefined for expired coupon code', () => {
      assert.equal(security.discountFromCoupon(security.generateCoupon(10, new Date('September 14, 2014'))), undefined)
    })

    void it('returns discount from issued coupon code', () => {
      assert.equal(security.discountFromCoupon(security.generateCoupon(10)), 10)
      assert.equal(security.discountFromCoupon(security.generateCoupon(security.maxCouponDiscount)), security.maxCouponDiscount)
    })
  })

  void describe('authenticatedUsers', () => {
    void it('returns user by associated token', () => {
      security.authenticatedUsers.put('11111', { data: { id: 1 } as unknown as UserModel })

      assert.deepEqual(security.authenticatedUsers.get('11111'), { data: { id: 1 } })
    })

    void it('returns undefined if no token is passed in', () => {
      assert.equal(security.authenticatedUsers.get(undefined), undefined)
    })

    void it('returns token by associated user', () => {
      security.authenticatedUsers.put('11111', { data: { id: 1 } as unknown as UserModel })

      assert.equal(security.authenticatedUsers.tokenOf({ id: 1 } as unknown as UserModel), '11111')
    })

    void it('returns user by associated token from request', () => {
      security.authenticatedUsers.put('11111', { data: { id: 1 } as unknown as UserModel })

      assert.deepEqual(security.authenticatedUsers.from({ headers: { authorization: 'Bearer 11111' } } as unknown as Request), { data: { id: 1 } })
    })

    void it('returns undefined if no token is present in request', () => {
      assert.equal(security.authenticatedUsers.from({ headers: {} } as unknown as Request), undefined)
      assert.equal(security.authenticatedUsers.from({} as unknown as Request), undefined)
    })
  })

  void describe('sanitizeHtml', () => {
    void it('handles empty inputs by returning their string representation', () => {
      assert.equal(security.sanitizeHtml(''), '')
    })

    void it('returns input unchanged for plain text input', () => {
      assert.equal(security.sanitizeHtml('This application is horrible!'), 'This application is horrible!')
    })

    void it('returns input unchanged for HTML input with only harmless text formatting', () => {
      assert.equal(security.sanitizeHtml('<strong>This</strong> application <em>is horrible</em>!'), '<strong>This</strong> application <em>is horrible</em>!')
    })

    void it('returns input unchanged for HTML input with only harmless links', () => {
      assert.equal(security.sanitizeHtml('<a href="bla.blubb">Please see here for details!</a>'), '<a href="bla.blubb">Please see here for details!</a>')
    })

    void it('removes all Javascript from HTML input', () => {
      assert.equal(security.sanitizeHtml('Sani<script>alert("ScriptXSS")</script>tizedScript'), 'SanitizedScript')
      assert.equal(security.sanitizeHtml('Sani<img src="alert("ImageXSS")"/>tizedImage'), 'SanitizedImage')
      assert.equal(security.sanitizeHtml('Sani<iframe src="alert("IFrameXSS")"></iframe>tizedIFrame'), 'SanitizedIFrame')
    })

    void it('can be bypassed by exploiting lack of recursive sanitization', () => {
      assert.equal(security.sanitizeHtml('<<script>Foo</script>iframe src="javascript:alert(`xss`)">'), '<iframe src="javascript:alert(`xss`)">')
    })
  })

  void describe('sanitizeLegacy', () => {
    void it('returns empty string for undefined input', () => {
      assert.equal(security.sanitizeLegacy(), '')
      assert.equal(security.sanitizeLegacy(undefined), '')
    })

    void it('returns input unchanged for plain text input', () => {
      assert.equal(security.sanitizeLegacy('bkimminich'), 'bkimminich')
      assert.equal(security.sanitizeLegacy('Kosh III.'), 'Kosh III.')
    })

    void it('removes all opening tags and subsequent character from HTML input', () => {
      assert.equal(security.sanitizeLegacy('<h1>Hello</h1>'), 'ello</h1>')
      assert.equal(security.sanitizeLegacy('<img src="test">'), 'rc="test">')
    })

    void it('can be bypassed to allow working HTML payload to be returned', () => {
      assert.equal(security.sanitizeLegacy('<<a|ascript>alert(`xss`)</script>'), '<script>alert(`xss`)</script>')
    })
  })

  void describe('sanitizeSecure', () => {
    void it('handles empty inputs by returning their string representation', () => {
      assert.equal(security.sanitizeSecure(''), '')
    })

    void it('returns input unchanged for plain text input', () => {
      assert.equal(security.sanitizeSecure('This application is horrible!'), 'This application is horrible!')
    })

    void it('returns input unchanged for HTML input with only harmless text formatting', () => {
      assert.equal(security.sanitizeSecure('<strong>This</strong> application <em>is horrible</em>!'), '<strong>This</strong> application <em>is horrible</em>!')
    })

    void it('returns input unchanged for HTML input with only harmless links', () => {
      assert.equal(security.sanitizeSecure('<a href="bla.blubb">Please see here for details!</a>'), '<a href="bla.blubb">Please see here for details!</a>')
    })

    void it('removes all Javascript from HTML input', () => {
      assert.equal(security.sanitizeSecure('Sani<script>alert("ScriptXSS")</script>tizedScript'), 'SanitizedScript')
      assert.equal(security.sanitizeSecure('Sani<img src="alert("ImageXSS")"/>tizedImage'), 'SanitizedImage')
      assert.equal(security.sanitizeSecure('Sani<iframe src="alert("IFrameXSS")"></iframe>tizedIFrame'), 'SanitizedIFrame')
    })

    void it('cannot be bypassed by exploiting lack of recursive sanitization', () => {
      assert.equal(security.sanitizeSecure('Bla<<script>Foo</script>iframe src="javascript:alert(`xss`)">Blubb'), 'BlaBlubb')
    })
  })

  void describe('hash', () => {
    void it('returns MD5 hash for any input string', () => {
      assert.equal(security.hash('admin123'), '0192023a7bbd73250516f069df18b500')
      assert.equal(security.hash('password'), '5f4dcc3b5aa765d61d8327deb882cf99')
      assert.equal(security.hash(''), 'd41d8cd98f00b204e9800998ecf8427e')
    })
  })

  void describe('hmac', () => {
    void it('returns SHA-256 HMAC with "pa4qacea4VK9t9nGv7yZtwmj" as salt any input string', () => {
      assert.equal(security.hmac('admin123'), '6be13e2feeada221f29134db71c0ab0be0e27eccfc0fb436ba4096ba73aafb20')
      assert.equal(security.hmac('password'), 'da28fc4354f4a458508a461fbae364720c4249c27f10fccf68317fc4bf6531ed')
      assert.equal(security.hmac(''), 'f052179ec5894a2e79befa8060cfcb517f1e14f7f6222af854377b6481ae953e')
    })
  })

  void describe('deluxeToken', () => {
    void it('returns SHA-256 HMAC with private key as salt for email and deluxe role', () => {
      assert.equal(security.deluxeToken('test@juice-sh.op'), '91e2b6493fda679d95ae05ac0d1cdce82c2ad4f7b518202a3ed54732531bc7e1')
    })
  })

  void describe('isCustomer', () => {
    void it('returns true if decoded token has customer role', () => {
      const user = { data: { role: 'customer' } }
      const token = security.authorize(user)
      assert.equal(security.isCustomer({ headers: { authorization: `Bearer ${token}` } } as unknown as Request), true)
    })

    void it('returns false if decoded token has other role', () => {
      const user = { data: { role: 'admin' } }
      const token = security.authorize(user)
      assert.equal(security.isCustomer({ headers: { authorization: `Bearer ${token}` } } as unknown as Request), false)
    })

    void it('returns false if no token is present', () => {
      assert.equal(security.isCustomer({ headers: {} } as unknown as Request), false)
    })
  })

  void describe('isDeluxe', () => {
    void it('returns true if decoded token has deluxe role and valid deluxe token', () => {
      const user = { data: { email: 'deluxe@juice-sh.op', role: 'deluxe', deluxeToken: security.deluxeToken('deluxe@juice-sh.op') } }
      const token = security.authorize(user)
      assert.equal(security.isDeluxe({ headers: { authorization: `Bearer ${token}` } } as unknown as Request), true)
    })

    void it('returns false if decoded token has deluxe role but invalid deluxe token', () => {
      const user = { data: { email: 'deluxe@juice-sh.op', role: 'deluxe', deluxeToken: 'invalid' } }
      const token = security.authorize(user)
      assert.equal(security.isDeluxe({ headers: { authorization: `Bearer ${token}` } } as unknown as Request), false)
    })

    void it('returns false if decoded token has other role', () => {
      const user = { data: { email: 'admin@juice-sh.op', role: 'admin' } }
      const token = security.authorize(user)
      assert.equal(security.isDeluxe({ headers: { authorization: `Bearer ${token}` } } as unknown as Request), false)
    })
  })

  void describe('isRedirectAllowed', () => {
    void it('returns true for allowed URLs', () => {
      for (const url of security.redirectAllowlist) {
        assert.equal(security.isRedirectAllowed(url), true)
      }
    })

    void it('returns true for URLs containing allowed URLs', () => {
      assert.equal(security.isRedirectAllowed('https://github.com/juice-shop/juice-shop/issues'), true)
    })

    void it('returns false for disallowed URLs', () => {
      assert.equal(security.isRedirectAllowed('https://google.com'), false)
      assert.equal(security.isRedirectAllowed('https://owasp.org'), false)
    })
  })

  void describe('sanitizeFilename', () => {
    void it('returns sanitized filename', () => {
      assert.equal(security.sanitizeFilename('file/name.txt'), 'filename.txt')
      assert.equal(security.sanitizeFilename('../../etc/passwd'), '....etcpasswd')
    })
  })

  void describe('authenticatedUsers.updateFrom', () => {
    void it('updates user in token map', () => {
      const token = '22222'
      const user = { data: { id: 2 } } as any
      security.authenticatedUsers.updateFrom({ headers: { authorization: `Bearer ${token}` } } as Request, user)
      assert.deepEqual(security.authenticatedUsers.get(token), user)
    })
  })

  void describe('middlewares', () => {
    void it('isAccounting should allow next() for accounting role', () => {
      const user = { data: { role: 'accounting' } }
      const token = security.authorize(user)
      const req = { headers: { authorization: `Bearer ${token}` } } as any
      let nextCalled = false
      const next = () => { nextCalled = true }
      security.isAccounting()(req, {} as any, next)
      assert.ok(nextCalled)
    })

    void it('isAccounting should return 403 for other roles', () => {
      const user = { data: { role: 'admin' } }
      const token = security.authorize(user)
      const req = { headers: { authorization: `Bearer ${token}` } } as any
      let statusSet = 0
      const res = {
        status: (s: number) => { statusSet = s; return res },
        json: () => {}
      } as any
      security.isAccounting()(req, res, () => {})
      assert.equal(statusSet, 403)
    })

    void it('appendUserId should append user id to req.body', () => {
      const token = '33333'
      const user = { data: { id: 3 } } as any
      security.authenticatedUsers.put(token, user)
      const req = { headers: { authorization: `Bearer ${token}` }, body: {} } as any
      let nextCalled = false
      const next = () => { nextCalled = true }
      security.appendUserId()(req, {} as any, next)
      assert.equal(req.body.UserId, 3)
      assert.ok(nextCalled)
    })

    void it('appendUserId should return 401 if token is invalid or missing', () => {
      const req = { headers: {}, body: {} } as any
      let statusSet = 0
      const res = {
        status: (s: number) => { statusSet = s; return res },
        json: () => {}
      } as any
      security.appendUserId()(req, res, () => {})
      assert.equal(statusSet, 401)
    })

    void it('updateAuthenticatedUsers should call next()', () => {
      const req = { cookies: {}, headers: {} } as any
      let nextCalled = false
      const next = () => { nextCalled = true }
      security.updateAuthenticatedUsers()(req, {} as any, next)
      assert.ok(nextCalled)
    })

    void it('isAuthorized returns a middleware', () => {
      assert.equal(typeof security.isAuthorized(), 'function')
    })

    void it('denyAll returns a middleware', () => {
      assert.equal(typeof security.denyAll(), 'function')
    })
  })
})
