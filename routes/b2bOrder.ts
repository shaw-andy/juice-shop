/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const packageRoot = (name: string, fromDir?: string) =>
  path.dirname(require.resolve(`${name}/package.json`, fromDir ? { paths: [fromDir] } : undefined))

const notevilRoot = packageRoot('notevil')
const notevilEntry = require.resolve('notevil')
const readablePaths = [notevilRoot, packageRoot('esprima', notevilRoot), packageRoot('hoister', notevilRoot)]
const permissionFlag = process.allowedNodeEnvironmentFlags.has('--permission') ? '--permission' : '--experimental-permission'

// notevil runs in the realm of whoever loads it, so it must live in its own process to keep
// prototype changes made by evaluated code away from the shop's heap.
const evaluatorSource = `
const { eval: safeEval } = require(process.argv[1])
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'))
let result
try {
  safeEval(input)
  result = { ok: true }
} catch (err) {
  result = { ok: false, message: String(err && err.message) }
}
process.stdout.write(JSON.stringify(result))
`

function evaluateInSandbox (orderLinesData: unknown) {
  let output: string
  try {
    output = execFileSync(process.execPath, [
      permissionFlag,
      ...readablePaths.map(dir => `--allow-fs-read=${dir}`),
      '--disallow-code-generation-from-strings',
      '--max-old-space-size=64',
      '-e', evaluatorSource,
      notevilEntry
    ], {
      input: JSON.stringify(orderLinesData),
      timeout: 2000,
      killSignal: 'SIGKILL',
      env: process.platform === 'win32' && process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {},
      stdio: ['pipe', 'pipe', 'ignore'],
      encoding: 'utf8',
      windowsHide: true
    })
  } catch (err: any) {
    if (err?.code === 'ETIMEDOUT') {
      throw new Error('Script execution timed out after 2000ms')
    }
    throw new Error('Order lines could not be evaluated')
  }
  let result: { ok?: unknown, message?: unknown }
  try {
    result = JSON.parse(output)
  } catch {
    throw new Error('Order lines could not be evaluated')
  }
  if (result?.ok !== true) {
    throw new Error(typeof result?.message === 'string' ? result.message : 'Order lines could not be evaluated')
  }
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        evaluateInSandbox(orderLinesData)
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
