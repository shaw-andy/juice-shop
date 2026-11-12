/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { type AddressInfo } from 'node:net'

const CHALLENGE_TEXTS = ['Admin Section', 'Password Hash Leak']
const PLACEHOLDER_KEY = 'placeholder-ctf-key'

type Status = 'REFUSED' | 'FORGED' | 'PUBLISHED' | 'MINTED' | 'WRONG_ERROR' | 'OK' | 'ENV_NOT_USED'

function finish (status: Status): never {
  process.stdout.write(status + '\n')
  process.exit(status === 'REFUSED' || status === 'OK' ? 0 : 1)
}

function matchesRepositoryKey (text: string, minted: string): boolean {
  const key = fs.readFileSync('ctf.key', 'utf8')
  const forged = crypto.createHmac('sha1', key).update(text).digest('hex')
  return minted === forged
}

function classifyMint (produce: () => string, text: string): 'refused' | 'forged' | 'minted' {
  try {
    const minted = produce()
    let forged = false
    try {
      forged = matchesRepositoryKey(text, minted)
    } catch {
      forged = false
    }
    return forged ? 'forged' : 'minted'
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (message.includes('CTF_KEY')) return 'refused'
    const code = error instanceof Error && 'code' in error ? String((error as NodeJS.ErrnoException).code) : ''
    const name = error instanceof Error ? error.name : 'Error'
    process.stdout.write(`WRONG_ERROR ${name} ${code}\n`)
    process.exit(1)
  }
}

function finishMintResults (results: Array<'refused' | 'forged' | 'minted'>): never {
  if (results.every((result) => result === 'refused')) finish('REFUSED')
  if (results.length > 0 && results.every((result) => result === 'forged')) finish('FORGED')
  finish('MINTED')
}

async function flagWhenKeyMissing (setEmpty: boolean): Promise<void> {
  if (setEmpty) process.env.CTF_KEY = ''
  else delete process.env.CTF_KEY
  const { ctfFlag } = await import('../../../lib/utils.ts')
  finishMintResults(CHALLENGE_TEXTS.map((text) => classifyMint(() => ctfFlag(text), text)))
}

async function flagTwice (): Promise<void> {
  delete process.env.CTF_KEY
  const { ctfFlag } = await import('../../../lib/utils.ts')
  finishMintResults([
    classifyMint(() => ctfFlag(CHALLENGE_TEXTS[0]), CHALLENGE_TEXTS[0]),
    classifyMint(() => ctfFlag(CHALLENGE_TEXTS[1]), CHALLENGE_TEXTS[1])
  ])
}

async function flagFromEnvironment (): Promise<void> {
  process.env.CTF_KEY = PLACEHOLDER_KEY
  const { ctfFlag } = await import('../../../lib/utils.ts')
  const text = CHALLENGE_TEXTS[0]
  const minted = ctfFlag(text)
  const fromEnv = crypto.createHmac('sha1', PLACEHOLDER_KEY).update(text).digest('hex')
  if (minted !== fromEnv || matchesRepositoryKey(text, minted)) finish('ENV_NOT_USED')
  finish('OK')
}

async function sendNotificationUnset (): Promise<void> {
  delete process.env.CTF_KEY
  const datacache = await import('../../../data/datacache.ts')
  const challengeUtils = await import('../../../lib/challengeUtils.ts')
  let emitted = false
  ;(global as { io?: { emit: () => void } }).io = {
    emit () { emitted = true }
  }
  const challenge = {
    solved: true,
    key: 'adminSectionChallenge',
    name: CHALLENGE_TEXTS[0],
    description: 'test',
    difficulty: 1,
    id: 1
  }
  try {
    challengeUtils.sendNotification(challenge, false)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (!message.includes('CTF_KEY')) {
      const code = error instanceof Error && 'code' in error ? String((error as NodeJS.ErrnoException).code) : ''
      process.stdout.write(`WRONG_ERROR ${error instanceof Error ? error.name : 'Error'} ${code}\n`)
      process.exit(1)
    }
  }
  const forged = datacache.notifications.some((notification) => {
    return matchesRepositoryKey(challenge.name, notification.flag)
  })
  if (forged) finish('FORGED')
  if (emitted || datacache.notifications.length !== 0) finish('PUBLISHED')
  finish('REFUSED')
}

async function postedTo (text: string, run: () => Promise<void>): Promise<{ posted: boolean, forged: boolean }> {
  let posted = false
  let forged = false
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
    req.on('end', () => {
      posted = true
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ctfFlag?: unknown }
        forged = typeof body.ctfFlag === 'string' && matchesRepositoryKey(text, body.ctfFlag)
      } catch {
        forged = false
      }
      res.statusCode = 204
      res.end()
    })
  })
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const port = (server.address() as AddressInfo).port
  process.env.SOLUTIONS_WEBHOOK = `http://127.0.0.1:${port}/`
  try {
    await run()
  } finally {
    await new Promise<void>((resolve) => { server.close(() => resolve()) })
  }
  return { posted, forged }
}

async function webhookUnset (): Promise<void> {
  delete process.env.CTF_KEY
  const webhook = await import('../../../lib/webhook.ts')
  let refused = false
  const { posted, forged } = await postedTo(CHALLENGE_TEXTS[0], async () => {
    try {
      await webhook.notify({ key: 'adminSectionChallenge', name: CHALLENGE_TEXTS[0] }, 0, 0, 0, process.env.SOLUTIONS_WEBHOOK)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (!message.includes('CTF_KEY')) throw error
      refused = true
    }
  })
  if (forged) finish('FORGED')
  if (posted) finish('PUBLISHED')
  if (!refused) finish('MINTED')
  finish('REFUSED')
}

async function solveUnset (): Promise<void> {
  delete process.env.CTF_KEY
  const datacache = await import('../../../data/datacache.ts')
  const challengeUtils = await import('../../../lib/challengeUtils.ts')
  let emitted = false
  ;(global as { io?: { emit: () => void } }).io = {
    emit () { emitted = true }
  }
  const challenge = {
    solved: false,
    key: 'adminSectionChallenge',
    name: CHALLENGE_TEXTS[1],
    description: 'test',
    difficulty: 1,
    id: 1,
    save: async function (this: { solved: boolean }) { return this }
  }
  datacache.challenges.adminSectionChallenge = challenge as never
  let refused = false
  let laterFailure = ''
  const receipt = await postedTo(challenge.name, async () => {
    try {
      await challengeUtils.solve(challenge as never, false)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (message.includes('CTF_KEY')) refused = true
      else {
        const code = error instanceof Error && 'code' in error ? String((error as NodeJS.ErrnoException).code) : ''
        laterFailure = `${error instanceof Error ? error.name : 'Error'} ${code}`
      }
    }
    await new Promise((resolve) => { setTimeout(resolve, 50) })
  })
  const forgedNotification = datacache.notifications.some((notification) => {
    return matchesRepositoryKey(challenge.name, notification.flag)
  })
  if (receipt.forged || forgedNotification) finish('FORGED')
  if (receipt.posted || emitted || datacache.notifications.length !== 0) finish('PUBLISHED')
  if (refused) finish('REFUSED')
  if (laterFailure !== '') {
    process.stdout.write(`WRONG_ERROR ${laterFailure}\n`)
    process.exit(1)
  }
  finish('MINTED')
}

const scenarios: Record<string, () => Promise<void>> = {
  'flag-unset': async () => { await flagWhenKeyMissing(false) },
  'flag-empty': async () => { await flagWhenKeyMissing(true) },
  'flag-twice': flagTwice,
  'flag-env': flagFromEnvironment,
  'notification-unset': sendNotificationUnset,
  'webhook-unset': webhookUnset,
  'solve-unset': solveUnset
}

const scenario = scenarios[process.argv[2]]
if (!scenario) {
  process.stdout.write('WRONG_ERROR Error \n')
  process.exit(1)
}

scenario().catch((error: unknown) => {
  const code = error instanceof Error && 'code' in error ? String((error as NodeJS.ErrnoException).code) : ''
  const name = error instanceof Error ? error.name : 'Error'
  process.stdout.write(`WRONG_ERROR ${name} ${code}\n`)
  process.exit(1)
})
