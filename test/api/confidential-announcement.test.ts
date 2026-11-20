/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { runInNewContext } from 'node:vm'
import compression from 'compression'
import express, { type NextFunction, type Request, type Response } from 'express'
import request from 'supertest'
import serveIndex from 'serve-index'
// @ts-expect-error FIXME due to non-existing type definitions for express-robots-txt
import robots from 'express-robots-txt'
import * as antiCheat from '../../lib/antiCheat'
import { servePublicFiles } from '../../routes/fileServer'

const ANNOUNCEMENT_FILE = 'announcement_encrypted.md'
const PUBLIC_EXPONENT = 65537n
const PUBLIC_MODULUS = BigInt('145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053')

function createFtpApp () {
  const app = express()
  app.use(compression())
  app.use((req: Request, _res: Response, next: NextFunction) => {
    req.url = req.url.replace(/[/]+/g, '/')
    next()
  })
  app.use(robots({ UserAgent: '*', Disallow: '/ftp' }))
  app.use(antiCheat.checkForPreSolveInteractions())
  app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))
  app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  return app
}

const serveIndexMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const origEnd = res.end
  // @ts-expect-error FIXME assignment broken due to seemingly void return value
  res.end = function () {
    if (arguments.length && typeof arguments[0] === 'string') {
      const reqPath = req.originalUrl.replace(/\?.*$/, '')
      const currentFolder = reqPath.split('/').pop()!
      arguments[0] = arguments[0].replace(/a href="([^"]+?)"/gi, function (_match: string, matchedUrl: string) {
        let relativePath = path.relative(reqPath, matchedUrl)
        if (relativePath === '') {
          relativePath = currentFolder
        } else if (!relativePath.startsWith('.') && currentFolder !== '') {
          relativePath = currentFolder + '/' + relativePath
        } else {
          relativePath = relativePath.replace('..', '.')
        }
        return 'a href="' + relativePath + '"'
      })
    }
    // @ts-expect-error FIXME passed argument has wrong type
    origEnd.apply(this, arguments)
  }
  next()
}

function modPow (base: bigint, exponent: bigint, modulus: bigint) {
  let result = 1n
  let value = base % modulus
  let exp = exponent
  while (exp > 0n) {
    if ((exp & 1n) === 1n) result = (result * value) % modulus
    value = (value * value) % modulus
    exp >>= 1n
  }
  return result
}

function publicParameters () {
  const parameters = [{ modulus: PUBLIC_MODULUS, exponent: PUBLIC_EXPONENT }]
  const scriptPath = path.resolve('test/files/encrypt.py')
  if (!existsSync(scriptPath)) return parameters
  const script = readFileSync(scriptPath, 'utf8')
  const modulus = script.match(/^N = (\d+)/m)
  const exponent = script.match(/^e = (\d+)/m)
  if (modulus != null && exponent != null) {
    parameters.push({ modulus: BigInt(modulus[1]), exponent: BigInt(exponent[1]) })
  }
  return parameters
}

function dictionary () {
  const alphabet = [
    ...Array.from({ length: 126 - 33 }, (_value, index) => String.fromCharCode(index + 33)),
    ' ',
    '\n',
    '\t'
  ]
  return publicParameters().map((parameters) => {
    const encoded = new Map<string, string>()
    for (const character of alphabet) {
      encoded.set(modPow(BigInt(character.charCodeAt(0)), parameters.exponent, parameters.modulus).toString(), character)
    }
    return encoded
  })
}

function recoverPerCharacterRsa (body: string) {
  const lines = body.replace(/\n$/, '').split('\n')
  if (lines.length === 0 || lines.some(line => !/^\d+$/.test(line))) return null
  for (const encoded of dictionary()) {
    let recovered = ''
    let unknown = false
    for (const line of lines) {
      const character = encoded.get(line)
      if (character === undefined) {
        unknown = true
        break
      }
      recovered += character
    }
    if (!unknown) return recovered
  }
  return null
}

function saleRouteAccepted (text: string) {
  const routingPath = path.resolve('frontend/src/app/app.routing.ts')
  if (!existsSync(routingPath)) return false
  const routing = readFileSync(routingPath, 'utf8')
  const start = routing.indexOf('export function token1')
  const end = routing.indexOf('// vuln-code-snippet end tokenSaleChallenge')
  if (start < 0 || end < start) return false
  const snippet = routing.slice(start, end)
    .replace(/export function /g, 'function ')
    .replace(/: UrlSegment\[\]/g, '')
    .replace(/: UrlMatchResult/g, '')
    .replace(/: number\[\]/g, '')
    .replace(/ as unknown as UrlMatchResult/g, '')
    .replace(/\/\/.*$/gm, '')
  const segments = new Set<string>()
  for (const match of text.matchAll(/#\/([A-Za-z0-9_-]+)/g)) {
    segments.add(match[1])
  }
  if (segments.size === 0) return false
  const accepted = runInNewContext(
    `${snippet}\n[...segments].some((segment) => Boolean(tokenMatcher([{ toString () { return segment } }])))`,
    { segments }
  )
  return accepted === true
}

function responseText (res: request.Response) {
  return res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf8') : '')
}

function recoversConfidentialAnnouncement (body: string) {
  const recovered = recoverPerCharacterRsa(body)
  if (recovered == null) return false
  const announcementPath = path.resolve('test/files/announcement.md')
  if (existsSync(announcementPath) && readFileSync(announcementPath, 'utf8') === recovered) return true
  return saleRouteAccepted(recovered)
}

void describe('confidential announcement', { concurrency: 1 }, () => {
  const app = createFtpApp()

  void it('is not recoverable from an anonymous download of the public file route', async () => {
    const res = await request(app).get('/ftp/' + ANNOUNCEMENT_FILE)
    const recovered = res.status === 200 && recoversConfidentialAnnouncement(responseText(res))
    assert.equal(recovered, false)
  })

  void it('is not recoverable by following the public file listing', async () => {
    const listing = await request(app).get('/ftp')
    if (listing.status !== 200 || !listing.text.includes(ANNOUNCEMENT_FILE)) return
    const res = await request(app).get('/ftp/' + ANNOUNCEMENT_FILE)
    const recovered = res.status === 200 && recoversConfidentialAnnouncement(responseText(res))
    assert.equal(recovered, false)
  })
})
