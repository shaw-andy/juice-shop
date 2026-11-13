/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const PRODUCT_IMAGE_DIR = 'assets/public/images/products/'
const FALLBACK_IMAGE = 'undefined.png'
// eslint-disable-next-line no-control-regex
const SINGLE_FILE_NAME = /^[^./\\?#%\u0000-\u001f\u007f][^/\\?#%\u0000-\u001f\u007f]*$/

export function productImageUrl (image: unknown): string {
  return PRODUCT_IMAGE_DIR + (encodeFileName(image) ?? FALLBACK_IMAGE)
}

function encodeFileName (image: unknown): string | undefined {
  if (typeof image !== 'string' || !SINGLE_FILE_NAME.test(image)) {
    return undefined
  }
  try {
    // The result is also embedded in a quoted CSS url(), so encode the characters encodeURIComponent leaves alone
    return encodeURIComponent(image).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
  } catch {
    return undefined
  }
}
