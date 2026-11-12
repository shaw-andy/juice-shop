/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids from 'hashids/cjs'
import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { decrypt } from '../lib/continueCodes'
import { challenges } from '../data/datacache'

const hashidsAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const hashidRegexp = /^[a-zA-Z0-9]+$/
const invalidContinueCode = 'Invalid continue code.'

export function restoreProgress () {
  const hashids = new Hashids('this is my salt', 60, hashidsAlphabet)
  return ({ params }: Request, res: Response) => {
    const continueCode = params.continueCode
    if (!hashidRegexp.test(continueCode)) {
      return res.status(404).send(invalidContinueCode)
    }
    const ids = decrypt('hacking', hashids.decodeHex(continueCode))
    if (ids.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (ids.includes(challenge.id)) {
          challengeUtils.solve(challenge, true)
        }
      }
      res.json({ data: ids.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}

export function restoreProgressFindIt () {
  const hashids = new Hashids('this is the salt for findIt challenges', 60, hashidsAlphabet)
  return async ({ params }: Request, res: Response) => {
    const continueCodeFindIt = params.continueCode
    if (!hashidRegexp.test(continueCodeFindIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    const idsFindIt = decrypt('findIt', hashids.decodeHex(continueCodeFindIt))
    if (idsFindIt.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (idsFindIt.includes(challenge.id)) {
          await challengeUtils.solveFindIt(challenge.key, true)
        }
      }
      res.json({ data: idsFindIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}

export function restoreProgressFixIt () {
  const hashids = new Hashids('yet another salt for the fixIt challenges', 60, hashidsAlphabet)
  return async ({ params }: Request, res: Response) => {
    const continueCodeFixIt = params.continueCode
    if (!hashidRegexp.test(continueCodeFixIt)) {
      return res.status(404).send(invalidContinueCode)
    }
    const idsFixIt = decrypt('fixIt', hashids.decodeHex(continueCodeFixIt))
    if (idsFixIt.length > 0) {
      for (const challenge of Object.values(challenges)) {
        if (idsFixIt.includes(challenge.id)) {
          await challengeUtils.solveFixIt(challenge.key, true)
        }
      }
      res.json({ data: idsFixIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}
