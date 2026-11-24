/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { glob } from 'glob'
import logger from '../logger'
import fs from 'fs-extra'
import * as utils from '../utils'
import { orderConfirmationsDir } from '../orderConfirmations'

const cleanupFtpFolder = async () => {
  try {
    const files = [
      ...await glob('ftp/*.pdf', { windowsPathsNoEscape: true }),
      ...await glob('order_*.pdf', { cwd: orderConfirmationsDir, absolute: true, windowsPathsNoEscape: true })
    ]
    for (const filename of files) {
      await fs.remove(filename)
    }
  } catch (err) {
    logger.warn('Error listing PDF files in /ftp folder: ' + utils.getErrorMessage(err))
  }
}
export default cleanupFtpFolder
