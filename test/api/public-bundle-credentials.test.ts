/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { parse, type Node } from 'acorn'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const emailPattern = /^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
const anchorWindow = 800

interface FoundString {
  value: string
  start: number
}

interface PublicScript {
  path: string
  literals: FoundString[]
}

void describe('public frontend bundle', () => {
  void it('does not ship string literals that authenticate seeded accounts', { timeout: 180000 }, async () => {
    const index = await request(app).get('/')
    assert.equal(index.status, 200)
    const scripts = await loadPublicScripts(index.text)
    assert.ok(scripts.length > 0, 'the public index did not reference any JavaScript')

    const configuration = await request(app).get('/rest/admin/application-configuration')
    assert.equal(configuration.status, 200)
    const domain = configuration.body?.config?.application?.domain
    assert.equal(typeof domain, 'string')

    const emails = new Set<string>()
    const passwords = new Set<string>()
    for (const script of scripts) {
      for (const literal of script.literals) {
        if (emailPattern.test(literal.value)) {
          emails.add(literal.value)
          const at = literal.value.lastIndexOf('@')
          emails.add(literal.value.slice(0, at + 1) + domain)
        }
      }
      for (const candidate of passwordsNearAnchors(script.literals)) {
        passwords.add(candidate)
      }
    }

    const breaches = []
    const seenEmails = new Set<string>()
    for (const email of emails) {
      for (const password of passwords) {
        const loginResponse = await request(app)
          .post('/rest/user/login')
          .set({ 'content-type': 'application/json' })
          .send({ email, password })
        const token = loginResponse.body?.authentication?.token
        if (loginResponse.status !== 200 || typeof token !== 'string') continue
        if (seenEmails.has(email)) continue
        seenEmails.add(email)
        breaches.push(await describeAuthenticatedSession(token, email))
      }
    }

    assert.deepEqual(breaches, [])
  })
})

async function loadPublicScripts (indexHtml: string): Promise<PublicScript[]> {
  const queue = scriptPathsFromHtml(indexHtml)
  const seen = new Set<string>()
  const scripts: PublicScript[] = []
  while (queue.length > 0) {
    const path = queue.shift()
    if (path == null || seen.has(path)) continue
    seen.add(path)
    const response = await request(app).get(path)
    if (response.status !== 200 || typeof response.text !== 'string') continue
    const sourceType = response.headers['content-type']
    if (typeof sourceType === 'string' && !sourceType.includes('javascript') && !sourceType.includes('text/plain') && !path.endsWith('.js')) continue
    let literals: FoundString[] = []
    try {
      literals = collectStringLiterals(response.text)
    } catch {
      continue
    }
    scripts.push({ path, literals })
    for (const literal of literals) {
      const next = scriptPathFromLiteral(literal.value)
      if (next != null && !seen.has(next)) queue.push(next)
    }
  }
  return scripts
}

function scriptPathsFromHtml (html: string): string[] {
  const paths: string[] = []
  const attributes = /(?:src|href)\s*=\s*["']([^"']+)["']/gi
  for (const match of html.matchAll(attributes)) {
    const normalized = normalizeScriptPath(match[1])
    if (normalized != null) paths.push(normalized)
  }
  return paths
}

function scriptPathFromLiteral (value: string): string | null {
  return normalizeScriptPath(value)
}

function normalizeScriptPath (value: string): string | null {
  if (!value.endsWith('.js')) return null
  if (value.includes('://') || value.startsWith('data:') || value.includes('..')) return null
  const withoutDot = value.replace(/^\.\//, '')
  if (withoutDot.startsWith('/')) return withoutDot
  if (withoutDot.includes('/')) return '/' + withoutDot
  if (/^[A-Za-z0-9._-]+\.js$/.test(withoutDot)) return '/' + withoutDot
  return null
}

function collectStringLiterals (code: string): FoundString[] {
  const ast = parseJavaScript(code)
  const literals: FoundString[] = []
  const seen = new Set<Node>()
  const walk = (node: Node | null | undefined): void => {
    if (node == null || typeof node !== 'object' || seen.has(node)) return
    seen.add(node)
    if (node.type === 'Literal') {
      const value = (node as Node & { value?: unknown }).value
      if (typeof value === 'string') literals.push({ value, start: node.start })
    }
    if (node.type === 'TemplateLiteral') {
      const template = node as Node & {
        expressions: unknown[]
        quasis: Array<{ start: number, value?: { cooked?: string | null } }>
      }
      if (template.expressions.length === 0 && template.quasis.length === 1) {
        const cooked = template.quasis[0].value?.cooked
        if (typeof cooked === 'string') literals.push({ value: cooked, start: template.quasis[0].start })
      }
    }
    for (const child of Object.values(node)) {
      if (Array.isArray(child)) {
        for (const entry of child) {
          if (isAstNode(entry)) walk(entry)
        }
      } else if (isAstNode(child)) {
        walk(child)
      }
    }
  }
  walk(ast)
  return literals
}

function parseJavaScript (code: string): Node {
  try {
    return parse(code, { ecmaVersion: 'latest', sourceType: 'module' })
  } catch {
    return parse(code, { ecmaVersion: 'latest', sourceType: 'script' })
  }
}

function isAstNode (value: unknown): value is Node {
  return value != null && typeof value === 'object' && 'type' in value && typeof (value as { type?: unknown }).type === 'string'
}

function passwordsNearAnchors (literals: FoundString[]): string[] {
  const anchors = literals.filter(literal => literal.value === '#password' || emailPattern.test(literal.value))
  const candidates: string[] = []
  for (const literal of literals) {
    if (!isPasswordCandidate(literal.value)) continue
    const nearAnchor = anchors.some(anchor => Math.abs(anchor.start - literal.start) <= anchorWindow)
    if (nearAnchor) candidates.push(literal.value)
  }
  return candidates
}

function isPasswordCandidate (value: string): boolean {
  if (value.length < 1 || value.length > 200) return false
  if (emailPattern.test(value)) return false
  if (/\s/.test(value)) return false
  if (value.startsWith('#') || value.startsWith('.') || value.startsWith('/') || value.startsWith('http')) return false
  if (/\.(?:js|css|png|svg|html|json)$/.test(value)) return false
  return true
}

async function describeAuthenticatedSession (token: string, email: string) {
  const payload = security.decode(token) as { data?: { role?: string } } | undefined
  const headers = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  const users = await request(app).get('/rest/user/authentication-details').set(headers)
  const feedbacks = await request(app).get('/api/Feedbacks').set(headers)
  const cards = await request(app).get('/api/Cards').set(headers)
  const addresses = await request(app).get('/api/Addresss').set(headers)
  const wallet = await request(app).get('/rest/wallet/balance').set(headers)
  return {
    email,
    role: payload?.data?.role ?? null,
    administrationUserCount: Array.isArray(users.body?.data) ? users.body.data.length : 0,
    feedbackCount: Array.isArray(feedbacks.body?.data) ? feedbacks.body.data.length : 0,
    cardCount: Array.isArray(cards.body?.data) ? cards.body.data.length : 0,
    addressCount: Array.isArray(addresses.body?.data) ? addresses.body.data.length : 0,
    walletStatus: wallet.status,
    walletBalance: wallet.status === 200 ? wallet.body?.data : null
  }
}
