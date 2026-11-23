/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { seededProductTexts } from '../data/datacache'

// Locale catalogs also hold HTML for non-product keys, so only text that is still exactly what the product was seeded with may be looked up
export function translateProductName (req: Request, product: { id?: number, name: string }) {
  const seeded = product.id !== undefined ? seededProductTexts[product.id] : undefined
  return seeded !== undefined && product.name === seeded.name ? req.__(product.name) : product.name
}

export function translateProductDescription (req: Request, product: { id?: number, description: string }) {
  const seeded = product.id !== undefined ? seededProductTexts[product.id] : undefined
  return seeded !== undefined && product.description === seeded.description ? req.__(product.description) : product.description
}
