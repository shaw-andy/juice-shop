/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

const reviewMarker = '__reviewIdRan'
const orderMarker = '__orderIdRan'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function pathSegment (value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (ch) =>
    `%${ch.charCodeAt(0).toString(16).toUpperCase()}`)
}

function markerValue (name: string): unknown {
  return (globalThis as Record<string, unknown>)[name]
}

function clearMarker (name: string) {
  delete (globalThis as Record<string, unknown>)[name]
}

async function assertLookupDoesNotBlock (path: string) {
  let ticks = 0
  const interval = setInterval(() => { ticks += 1 }, 500)
  const started = Date.now()
  try {
    await request(app).get(path)
  } finally {
    clearInterval(interval)
  }
  const elapsed = Date.now() - started
  const expectedTicks = Math.floor(elapsed / 500)
  assert.ok(
    elapsed < 1000 && ticks + 1 >= expectedTicks,
    `lookup took ${elapsed}ms and the event loop ran ${ticks} times`
  )
}

void describe('GET /rest/products/:id/reviews', () => {
  void it('returns reviews for a numeric product id', async () => {
    const res = await request(app).get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length > 0)
    for (const review of res.body.data) {
      assert.equal(review.product, 1)
    }
  })

  void it('does not evaluate JavaScript supplied as the product id', async () => {
    clearMarker(reviewMarker)
    const id = pathSegment(`(globalThis.${reviewMarker}=1)`)
    try {
      await request(app).get(`/rest/products/${id}/reviews`)
      assert.equal(markerValue(reviewMarker), undefined)
    } finally {
      clearMarker(reviewMarker)
    }
  })

  void it('does not block the event loop when the product id calls sleep(2000)', async () => {
    const id = pathSegment('sleep(2000)')
    await assertLookupDoesNotBlock(`/rest/products/${id}/reviews`)
  }, { timeout: 180000 })
})

void describe('GET /rest/track-order/:id', () => {
  void it('does not evaluate JavaScript supplied as the order id', async () => {
    clearMarker(orderMarker)
    const id = pathSegment(`'||(globalThis.${orderMarker}=1)||'`)
    try {
      await request(app).get(`/rest/track-order/${id}`)
      assert.equal(markerValue(orderMarker), undefined)
    } finally {
      clearMarker(orderMarker)
    }
  })

  void it('does not block the event loop when the order id calls sleep(2000)', async () => {
    const id = pathSegment('\'||sleep(2000)||\'')
    await assertLookupDoesNotBlock(`/rest/track-order/${id}`)
  }, { timeout: 60000 })
})
