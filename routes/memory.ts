/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import multer from 'multer'
import { type Request, type Response, type NextFunction } from 'express'
import { MEMORY_CAPTION_MAX_LENGTH, MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export const MEMORY_PAGE_SIZE = 10

const uploadDirectory = path.resolve('frontend/dist/frontend/assets/public/images/uploads/')
const mimeTypeMap: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
}

export const uploadMemoryImage = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1,
    fields: 5,
    // a caption of MEMORY_CAPTION_MAX_LENGTH characters can take up to 4 bytes per character in UTF-8
    fieldSize: MEMORY_CAPTION_MAX_LENGTH * 4
  },
  fileFilter: (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    if (mimeTypeMap[file.mimetype]) {
      cb(null, true)
    } else {
      cb(new Error('Invalid mime type'))
    }
  }
})

export function handleMemoryUploadLimits () {
  return (err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (err instanceof multer.MulterError) {
      const tooLarge = err.code === 'LIMIT_FILE_SIZE' || err.code === 'LIMIT_FIELD_VALUE'
      res.status(tooLarge ? 413 : 400).json({ status: 'error', error: err.message })
      return
    }
    next(err)
  }
}

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const caption = req.body.caption
    if (caption !== undefined && (typeof caption !== 'string' || caption.length > MEMORY_CAPTION_MAX_LENGTH)) {
      res.status(400).json({ status: 'error', error: `Caption must be text of at most ${MEMORY_CAPTION_MAX_LENGTH} characters` })
      return
    }
    const file = req.file as Express.Multer.File
    const name = security.sanitizeFilename(file.originalname)
      .toLowerCase()
      .split(' ')
      .join('-')
    const filename = name + '-' + Date.now() + '.' + mimeTypeMap[file.mimetype]
    await fs.writeFile(path.join(uploadDirectory, filename), file.buffer)
    const record = {
      caption,
      imagePath: 'assets/public/images/uploads/' + filename,
      UserId: req.body.UserId
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

function parsePagingParameter (value: unknown, fallback: number) {
  const parsed = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : NaN
  return Number.isSafeInteger(parsed) ? parsed : fallback
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const limit = Math.min(Math.max(parsePagingParameter(req.query.limit, MEMORY_PAGE_SIZE), 1), MEMORY_PAGE_SIZE)
    const offset = parsePagingParameter(req.query.offset, 0)
    const [memories, total] = await Promise.all([
      MemoryModel.findAll({
        include: [{ model: UserModel, attributes: ['id', 'username'] }],
        order: [['id', 'ASC']],
        limit,
        offset
      }),
      MemoryModel.count()
    ])
    res.status(200).json({ status: 'success', data: memories, total })
  }
}
