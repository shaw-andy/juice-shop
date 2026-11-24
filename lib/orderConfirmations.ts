/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'

// Kept outside of the publicly listed /ftp folder and pruned at startup by cleanupFtpFolder
export const orderConfirmationsDir = path.resolve('data/orders')
const maxStoredOrderConfirmations = 1000
const storedOrderConfirmations: string[] = []

export function orderConfirmationFile (orderId: string) {
  return path.join(orderConfirmationsDir, `order_${orderId}.pdf`)
}

export async function prepareOrderConfirmationsDir () {
  await fs.promises.mkdir(orderConfirmationsDir, { recursive: true })
}

export function retainOrderConfirmation (file: string) {
  storedOrderConfirmations.push(file)
  while (storedOrderConfirmations.length > maxStoredOrderConfirmations) {
    const oldest = storedOrderConfirmations.shift()
    if (oldest !== undefined) {
      fs.rm(oldest, { force: true }, () => {})
    }
  }
}
