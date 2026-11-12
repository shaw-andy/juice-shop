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

function encodedCoupon (discountField: string) {
  const plain = utils.toMMMYY(new Date()) + '-' + discountField
  const encoded = z85.encode(plain)
  assert.equal(typeof encoded, 'string', `coupon text ${plain} is not a length the codec accepts`)
  assert.equal(z85.decode(encoded).toString(), plain)
  return encoded
}

function assertDiscountAtMost100 (coupon: string) {
  const discount = security.discountFromCoupon(coupon)
  assert.ok(
    discount === undefined || (typeof discount === 'number' && discount >= 0 && discount <= 100),
    `discount must be omitted or within 0..100, got ${String(discount)}`
  )
}

void describe('discountFromCoupon percentage cap', () => {
  void it('keeps a two-digit coupon at that percentage', () => {
    assert.equal(security.discountFromCoupon(security.generateCoupon(99)), 99)
  })

  void it('does not accept a current month-year coupon whose discount field is six digits', () => {
    assertDiscountAtMost100(encodedCoupon('999999'))
    assertDiscountAtMost100(encodedCoupon('100001'))
  })

  void it('does not accept a current month-year coupon whose discount field is ten digits', () => {
    assertDiscountAtMost100(encodedCoupon('1000000001'))
  })

  void it('does not accept a coupon minted by generateCoupon with a percentage above 100', () => {
    assertDiscountAtMost100(security.generateCoupon(999999))
    assertDiscountAtMost100(security.generateCoupon(100001))
    assertDiscountAtMost100(security.generateCoupon(1000000001))
  })
})
