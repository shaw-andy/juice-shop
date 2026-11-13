/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Same limit as direct profile image uploads via multer in server.ts
const MAX_IMAGE_BYTES = 200000
const DOWNLOAD_TIMEOUT_MS = 5000

async function downloadImage (url: string): Promise<Buffer> {
  const controller = new AbortController()
  const timer = setTimeout(() => { controller.abort(new Error(`download timed out after ${DOWNLOAD_TIMEOUT_MS}ms`)) }, DOWNLOAD_TIMEOUT_MS)
  try {
    const response = await fetch(url, { signal: controller.signal })
    if (!response.ok || !response.body) {
      throw new Error('url returned a non-OK status code or an empty body')
    }
    if (Number(response.headers.get('content-length')) > MAX_IMAGE_BYTES) {
      throw new Error(`image exceeds ${MAX_IMAGE_BYTES} bytes`)
    }
    const reader = response.body.getReader()
    const chunks: Uint8Array[] = []
    let size = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_IMAGE_BYTES) {
        throw new Error(`image exceeds ${MAX_IMAGE_BYTES} bytes`)
      }
      chunks.push(value)
    }
    return Buffer.concat(chunks)
  } finally {
    clearTimeout(timer)
    controller.abort()
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const image = await downloadImage(url)
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          await fs.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, image)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
