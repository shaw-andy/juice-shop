/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import yaml from 'js-yaml'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { SNIPPET_PATHS } from '../lib/codingChallenges'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import { parseXmlString } from '../lib/xml'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

const isWithin = (directory: string, target: string) => target === directory || target.startsWith(directory + path.sep)

async function realpathOrNull (target: string) {
  try {
    return await fs.promises.realpath(target)
  } catch {
    return null
  }
}

// Entries may still traverse out of uploads/complaints (Arbitrary File Write and Video XSS challenges),
// but never out of the application or into the sources the coding challenge loader parses.
async function resolveZipEntryTarget (absolutePath: string) {
  const appRoot = await fs.promises.realpath('.')
  const parent = await realpathOrNull(path.dirname(absolutePath))
  if (parent === null) return null
  const target = path.join(parent, path.basename(absolutePath))
  if (!isWithin(appRoot, target)) return null
  for (const snippetPath of SNIPPET_PATHS) {
    if (isWithin((await realpathOrNull(snippetPath)) ?? path.resolve(snippetPath), target)) return null
  }
  return target
}

const zipEntryWriteFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | (fs.constants.O_NOFOLLOW ?? 0)

async function extractZipBuffer (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  for (const entry of directory.files) {
    const fileName = entry.path
    const absolutePath = path.resolve('uploads/complaints/' + fileName)
    challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
    if (entry.type === 'Directory') continue
    const target = await resolveZipEntryTarget(absolutePath)
    if (target !== null) {
      const file = await fs.promises.open(target, zipEntryWriteFlags)
      await pipeline(entry.stream(), file.createWriteStream())
    }
  }
}

async function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!(file?.originalname?.toLowerCase().endsWith('.zip') ?? false)) {
    next()
    return
  }
  if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
    try {
      await extractZipBuffer(file.buffer)
    } catch (err) {
      next(err)
      return
    }
  }
  res.status(204).end()
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

async function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (file?.originalname?.toLowerCase().endsWith('.xml') ?? false) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      try {
        const xmlString = await parseXmlString(data)
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (errorMessage.includes('Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if ((file?.originalname?.toLowerCase().endsWith('.yml') ?? false) || (file?.originalname?.toLowerCase().endsWith('.yaml') ?? false)) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (errorMessage.includes('Invalid string length') || errorMessage.includes('Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
