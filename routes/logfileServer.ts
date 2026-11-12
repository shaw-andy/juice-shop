/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { resolveFileInDirectory } from '../lib/utils'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }
    const filePath = resolveFileInDirectory('logs/', file)
    if (filePath) {
      res.sendFile(filePath)
    } else {
      res.status(403)
      next(new Error('File names must not leave the logs directory!'))
    }
  }
}
