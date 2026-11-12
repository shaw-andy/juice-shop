/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads/')
const extensionsByMimeType = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg'],
  ['image/jpg', 'jpg']
])

export function memoryImageExtension (mimeType: string) {
  return extensionsByMimeType.get(mimeType)
}

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const ext = file !== undefined ? memoryImageExtension(file.mimetype) : undefined
    if (file?.buffer === undefined || ext === undefined) {
      res.status(400).json({ error: 'File is not passed' })
      return
    }
    const name = security.sanitizeFilename(file.originalname)
      .toLowerCase()
      .split(' ')
      .join('-')
    const filename = name + '-' + Date.now() + '.' + ext
    const filePath = path.join(uploadDir, filename)
    await fs.writeFile(filePath, file.buffer, { flag: 'wx' })
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + filename,
      UserId: res.locals.authenticatedUserId
    }
    let memory
    try {
      memory = await MemoryModel.create(record)
    } catch (error) {
      await fs.rm(filePath, { force: true })
      throw error
    }
    res.status(200).json({ status: 'success', data: memory })
  }
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const memories = await MemoryModel.findAll({ include: [UserModel] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
