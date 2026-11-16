/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// "." and ".." survive percent-encoding and are still resolved as dot segments by the URL parser
export function pathSegment (value: string | number | null | undefined): string {
  const segment = encodeURIComponent(String(value))
  if (segment === '.' || segment === '..') {
    throw new Error(`Illegal path segment: ${segment}`)
  }
  return segment
}
