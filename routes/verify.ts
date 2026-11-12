/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { Op } from 'sequelize'
import jwt from 'jsonwebtoken'
import config from 'config'
import jws from 'jws'

import { challenges, products, retrieveBlueprintChallengeFile } from '../data/datacache'
import type { Product as ProductConfig } from '../lib/config.schema'
import { type Challenge, type Product } from '../data/types'
import * as challengeUtils from '../lib/challengeUtils'
import * as antiCheat from '../lib/antiCheat'
import { ComplaintModel } from '../models/complaint'
import { FeedbackModel } from '../models/feedback'
import { ProductModel } from '../models/product'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import { buildSystemPrompt } from './chat'

export const emptyUserRegistration = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.emptyUserRegistration, () => {
    return req.body && req.body.email === '' && req.body.password === ''
  })
  next()
}

export const forgedFeedbackChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.forgedFeedbackChallenge, () => {
    const user = security.authenticatedUsers.from(req)
    const userId = user?.data ? user.data.id : undefined
    return req.body?.UserId && req.body.UserId != userId // eslint-disable-line eqeqeq
  })
  next()
}

export const captchaBypassChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.captchaBypassChallenge)) {
    if (req.app.locals.captchaReqId >= 10) {
      if ((new Date().getTime() - req.app.locals.captchaBypassReqTimes[req.app.locals.captchaReqId - 10]) <= 20000) {
        challengeUtils.solve(challenges.captchaBypassChallenge)
      }
    }
    req.app.locals.captchaBypassReqTimes[req.app.locals.captchaReqId - 1] = new Date().getTime()
    req.app.locals.captchaReqId++
  }
  next()
}

export const registerAdminChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
    return req.body && req.body.role === security.roles.admin
  })
  next()
}

export const passwordRepeatChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.passwordRepeatChallenge, () => { return req.body && req.body.passwordRepeat !== req.body.password })
  next()
}

export const accessControlChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  const { url } = req
  const uiBypassed = req.header('sec-fetch-dest') === 'document' || !req.header('referer')
  challengeUtils.solveIf(challenges.scoreBoardChallenge, () => { return url.endsWith('/1px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.web3SandboxChallenge, () => { return url.endsWith('/11px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.adminSectionChallenge, () => { return url.endsWith('/19px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.tokenSaleChallenge, () => { return url.endsWith('/56px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.privacyPolicyChallenge, () => { return url.endsWith('/81px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.extraLanguageChallenge, () => { return url.endsWith('/tlh_AA.json') })
  challengeUtils.solveIf(challenges.retrieveBlueprintChallenge, () => { return url.endsWith(retrieveBlueprintChallengeFile ?? '') })
  challengeUtils.solveIf(challenges.securityPolicyChallenge, () => { return url.endsWith('/security.txt') })
  challengeUtils.solveIf(challenges.missingEncodingChallenge, () => { return url.toLowerCase().endsWith('%e1%93%9a%e1%98%8f%e1%97%a2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg') })
  challengeUtils.solveIf(challenges.accessLogDisclosureChallenge, () => { return url.match(/access\.log(0-9-)*/) })
  challengeUtils.solveIf(challenges.misplacedIacFiles, () => { return (url.endsWith('.tf') || url.endsWith('Dockerfile') || url.endsWith('docker-compose.yml')) })
  next()
}

export const errorHandlingChallenge = () => (err: unknown, req: Request, { statusCode }: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.errorHandlingChallenge, () => { return err && (statusCode === 200 || statusCode > 401) })
  next(err)
}

export const jwtChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.jwtUnsignedChallenge)) {
    jwtChallenge(challenges.jwtUnsignedChallenge, req, 'none', /jwtn3d@/)
  }
  if (utils.isChallengeEnabled(challenges.jwtForgedChallenge) && challengeUtils.notSolved(challenges.jwtForgedChallenge)) {
    jwtChallenge(challenges.jwtForgedChallenge, req, 'HS256', /rsa_lord@/)
  }
  if (challengeUtils.notSolved(challenges.iacLeakedKeyChallenge)) {
    jwtChallenge(challenges.iacLeakedKeyChallenge, req, 'RS256', /cloud-admin@/)
  }
  next()
}

export const serverSideChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (req.query.key === 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3') {
    if (challengeUtils.notSolved(challenges.sstiChallenge) && req.app.locals.abused_ssti_bug === true) {
      challengeUtils.solve(challenges.sstiChallenge)
      res.status(204).send()
      return
    }

    if (challengeUtils.notSolved(challenges.ssrfChallenge) && req.app.locals.abused_ssrf_bug === true) {
      challengeUtils.solve(challenges.ssrfChallenge)
      res.status(204).send()
      return
    }
  }
  next()
}

function jwtChallenge (challenge: Challenge, req: Request, algorithm: string, email: string | RegExp) {
  const token = utils.jwtFrom(req)
  if (token) {
    const decoded = jws.decode(token) ? jwt.decode(token) : null

    if (decoded === null || typeof decoded === 'string') {
      return
    }

    jwt.verify(token, security.publicKey, (err: jwt.VerifyErrors | null) => {
      if (err === null) {
        challengeUtils.solveIf(challenge, () => {
          return hasAlgorithm(token, algorithm) && hasEmail(decoded as { data: { email: string } }, email)
        })
      }
    })
  }
}

function hasAlgorithm (token: string, algorithm: string) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
  return token && header && header.alg === algorithm
}

function hasEmail (token: { data: { email: string } }, email: string | RegExp) {
  return token?.data?.email?.match(email)
}

interface RowScope {
  feedbackId?: number
  complaintId?: number
}

async function checkPatternInFeedbackAndComplaints (
  challenge: Challenge,
  fieldCriteria: any,
  scope: RowScope = {}
): Promise<void> {
  const checks: Array<Promise<void>> = []

  if (scope.complaintId === undefined) {
    const where: Record<string, unknown> = { comment: fieldCriteria }
    if (scope.feedbackId !== undefined) where.id = scope.feedbackId
    checks.push(FeedbackModel.findAndCountAll({ where }).then(({ count, rows }: { count: number, rows: any[] }) => {
      if (count > 0) {
        const isCheating = rows.some((row: any) => antiCheat.checkForSourceFileOverlap(challenge.key, row.comment ?? ''))
        challengeUtils.solve(challenge, false, isCheating)
      }
    }).catch(() => {
      throw new Error('Unable to retrieve feedback details. Please try again')
    }))
  }

  if (scope.feedbackId === undefined) {
    const where: Record<string, unknown> = { message: fieldCriteria }
    if (scope.complaintId !== undefined) where.id = scope.complaintId
    checks.push(ComplaintModel.findAndCountAll({ where }).then(({ count, rows }: { count: number, rows: any[] }) => {
      if (count > 0) {
        const isCheating = rows.some((row: any) => antiCheat.checkForSourceFileOverlap(challenge.key, row.message ?? ''))
        challengeUtils.solve(challenge, false, isCheating)
      }
    }).catch(() => {
      throw new Error('Unable to retrieve complaint details. Please try again')
    }))
  }

  await Promise.all(checks)
}

function patternChallengeChecks (scope?: RowScope): Array<Promise<void>> {
  const checks: Array<Promise<void>> = []
  if (challengeUtils.notSolved(challenges.knownVulnerableComponentChallenge)) {
    checks.push(knownVulnerableComponentChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.weirdCryptoChallenge)) {
    checks.push(weirdCryptoChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.typosquattingNpmChallenge)) {
    checks.push(typosquattingNpmChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.typosquattingAngularChallenge)) {
    checks.push(typosquattingAngularChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.hiddenImageChallenge)) {
    checks.push(hiddenImageChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.supplyChainAttackChallenge)) {
    checks.push(supplyChainAttackChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.dlpPastebinDataLeakChallenge)) {
    checks.push(dlpPastebinDataLeakChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.csafChallenge)) {
    checks.push(csafChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.leakedApiKeyChallenge)) {
    checks.push(leakedApiKeyChallenge(scope))
  }
  if (challengeUtils.notSolved(challenges.vulnerableDockerImageChallenge)) {
    checks.push(vulnerableDockerImageChallenge(scope))
  }
  return checks
}

export async function verifyDatabaseRelatedChallenges (): Promise<void> {
  const checks: Array<Promise<void>> = []
  if (challengeUtils.notSolved(challenges.changeProductChallenge) && products.osaft) {
    checks.push(changeProductChallenge(products.osaft))
  }
  if (challengeUtils.notSolved(challenges.feedbackChallenge)) {
    checks.push(feedbackChallenge())
  }
  checks.push(...patternChallengeChecks())
  if (challengeUtils.notSolved(challenges.systemPromptExtractionChallenge)) {
    checks.push(systemPromptExtractionChallenge())
  }
  await Promise.allSettled(checks)
}

async function verifyFeedback (feedback: FeedbackModel) {
  await Promise.allSettled(patternChallengeChecks({ feedbackId: feedback.id }))
}

async function verifyComplaint (complaint: ComplaintModel) {
  const checks = patternChallengeChecks({ complaintId: complaint.id })
  if (challengeUtils.notSolved(challenges.systemPromptExtractionChallenge)) {
    solveSystemPromptExtractionIfLeaked([complaint.message])
  }
  await Promise.allSettled(checks)
}

async function verifyFiveStarFeedbackRemoval () {
  if (challengeUtils.notSolved(challenges.feedbackChallenge)) {
    await feedbackChallenge().catch(() => {})
  }
}

async function verifyProductTampering (productId?: number) {
  const osaft = products.osaft
  if (osaft && challengeUtils.notSolved(challenges.changeProductChallenge) && (productId === undefined || productId === osaft.id)) {
    await changeProductChallenge(osaft).catch(() => {})
  }
}

const hookName = 'databaseRelatedChallenges'

/* Challenge checks follow writes to the inspected tables instead of running on every incoming request */
export function registerDatabaseRelatedChallengeHooks () {
  FeedbackModel.removeHook('afterCreate', hookName)
  FeedbackModel.addHook('afterCreate', hookName, verifyFeedback)
  FeedbackModel.removeHook('afterBulkCreate', hookName)
  FeedbackModel.addHook('afterBulkCreate', hookName, async (feedbacks: FeedbackModel[]) => { await Promise.all(feedbacks.map(verifyFeedback)) })
  FeedbackModel.removeHook('afterUpdate', hookName)
  FeedbackModel.addHook('afterUpdate', hookName, async (feedback: FeedbackModel) => { await Promise.all([verifyFeedback(feedback), verifyFiveStarFeedbackRemoval()]) })
  FeedbackModel.removeHook('afterDestroy', hookName)
  FeedbackModel.addHook('afterDestroy', hookName, async (feedback: FeedbackModel) => {
    if (feedback.rating === 5) await verifyFiveStarFeedbackRemoval()
  })
  FeedbackModel.removeHook('afterBulkUpdate', hookName)
  FeedbackModel.addHook('afterBulkUpdate', hookName, verifyDatabaseRelatedChallenges)
  FeedbackModel.removeHook('afterBulkDestroy', hookName)
  FeedbackModel.addHook('afterBulkDestroy', hookName, verifyFiveStarFeedbackRemoval)

  ComplaintModel.removeHook('afterCreate', hookName)
  ComplaintModel.addHook('afterCreate', hookName, verifyComplaint)
  ComplaintModel.removeHook('afterBulkCreate', hookName)
  ComplaintModel.addHook('afterBulkCreate', hookName, async (complaints: ComplaintModel[]) => { await Promise.all(complaints.map(verifyComplaint)) })
  ComplaintModel.removeHook('afterUpdate', hookName)
  ComplaintModel.addHook('afterUpdate', hookName, verifyComplaint)
  ComplaintModel.removeHook('afterBulkUpdate', hookName)
  ComplaintModel.addHook('afterBulkUpdate', hookName, verifyDatabaseRelatedChallenges)

  ProductModel.removeHook('afterUpdate', hookName)
  ProductModel.addHook('afterUpdate', hookName, async (product: ProductModel) => { await verifyProductTampering(product.id) })
  ProductModel.removeHook('afterBulkUpdate', hookName)
  ProductModel.addHook('afterBulkUpdate', hookName, async () => { await verifyProductTampering() })
}

function changeProductChallenge (osaft: Product): Promise<void> {
  let urlForProductTamperingChallenge: string | null = null
  return osaft.reload().then(() => {
    for (const product of config.get<ProductConfig[]>('products')) {
      if (product.urlForProductTamperingChallenge !== undefined) {
        urlForProductTamperingChallenge = product.urlForProductTamperingChallenge
        break
      }
    }
    if (urlForProductTamperingChallenge) {
      if (!osaft.description.includes(`${urlForProductTamperingChallenge}`)) {
        if (osaft.description.includes(`<a href="${config.get<string>('challenges.overwriteUrlForProductTamperingChallenge')}" target="_blank">`)) {
          challengeUtils.solve(challenges.changeProductChallenge)
        }
      }
    }
  })
}

function feedbackChallenge (): Promise<void> {
  return FeedbackModel.findAndCountAll({ where: { rating: 5 } }).then(({ count }: { count: number }) => {
    if (count === 0) {
      challengeUtils.solve(challenges.feedbackChallenge)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve feedback details. Please try again')
  })
}

function knownVulnerableComponentChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.knownVulnerableComponentChallenge,
    { [Op.or]: knownVulnerableComponents() },
    scope
  )
}

function knownVulnerableComponents () {
  return [
    {
      [Op.and]: [
        { [Op.like]: '%sanitize-html%' },
        { [Op.like]: '%1.4.2%' }
      ]
    },
    {
      [Op.and]: [
        { [Op.like]: '%express-jwt%' },
        { [Op.like]: '%0.1.3%' }
      ]
    }
  ]
}

function weirdCryptoChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.weirdCryptoChallenge,
    { [Op.or]: weirdCryptos() },
    scope
  )
}

function weirdCryptos () {
  return [
    { [Op.like]: '%z85%' },
    { [Op.like]: '%base85%' },
    { [Op.like]: '%hashids%' },
    { [Op.like]: '%md5%' },
    { [Op.like]: '%base64%' }
  ]
}

function typosquattingNpmChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.typosquattingNpmChallenge,
    { [Op.like]: '%epilogue-js%' },
    scope
  )
}

function typosquattingAngularChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.typosquattingAngularChallenge,
    { [Op.like]: '%ngy-cookie%' },
    scope
  )
}

function hiddenImageChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.hiddenImageChallenge,
    { [Op.like]: '%pickle rick%' },
    scope
  )
}

function supplyChainAttackChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.supplyChainAttackChallenge,
    { [Op.or]: eslintScopeVulnIds() },
    scope
  )
}

function eslintScopeVulnIds () {
  return [
    { [Op.like]: '%eslint-scope/issues/39%' },
    { [Op.like]: '%npm:eslint-scope:20180712%' }
  ]
}

function dlpPastebinDataLeakChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.dlpPastebinDataLeakChallenge,
    { [Op.and]: dangerousIngredients() },
    scope
  )
}

function csafChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.csafChallenge,
    { [Op.like]: '%' + config.get<string>('challenges.csafHashValue') + '%' },
    scope
  )
}

function leakedApiKeyChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.leakedApiKeyChallenge,
    { [Op.like]: '%6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie%' },
    scope
  )
}

function vulnerableDockerImageChallenge (scope?: RowScope) {
  return checkPatternInFeedbackAndComplaints(
    challenges.vulnerableDockerImageChallenge,
    {
      [Op.and]: [
        { [Op.like]: '%mongo%' },
        { [Op.like]: '%4.4.29%' }
      ]
    },
    scope
  )
}

function dangerousIngredients () {
  return config.get<ProductConfig[]>('products')
    .flatMap((product) => product.keywordsForPastebinDataLeakChallenge)
    .filter(Boolean)
    .map((keyword) => {
      return { [Op.like]: `%${keyword}%` }
    })
}

export function checkSystemPromptSimilarity (submission: string, reference: string, threshold = 0.25): boolean {
  const score = utils.diceCoefficient((submission ?? '').toLowerCase().trim(), reference.toLowerCase().trim(), 3)
  return score >= threshold
}

async function systemPromptExtractionChallenge (): Promise<void> {
  const complaints = await ComplaintModel.findAll().catch(() => [])
  solveSystemPromptExtractionIfLeaked(complaints.map(complaint => complaint.message))
}

function solveSystemPromptExtractionIfLeaked (messages: Array<string | undefined>) {
  const reference = buildSystemPrompt().toLowerCase().trim()
  if (messages.some(message => checkSystemPromptSimilarity(message ?? '', reference))) {
    challengeUtils.solveIf(challenges.systemPromptExtractionChallenge, () => true)
  }
}
