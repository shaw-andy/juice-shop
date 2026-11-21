/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import http from 'node:http'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import locales from '../../data/static/locales.json'

interface RenderedDescription {
  locale: string
  name: string
  iframeSrcs: string[]
  dialogs: string[]
}

let app: Express
let chrome: ChildProcess | undefined
let pageSocket: WebSocket | undefined
let cdpId = 0
const cdpPending = new Map<number, (message: any) => void>()
const dialogs: string[] = []

const EMPTY_PAGE = '<!DOCTYPE html><html><body><div id="host"></div></body></html>'

before(async () => {
  const result = await createTestApp()
  app = result.app
  await startChrome()
}, { timeout: 120000 })

after(() => {
  pageSocket?.close()
  chrome?.kill()
})

void describe('scoreboard challenge description translations', () => {
  void it('does not execute script when a listed language is rendered as HTML', async () => {
    const rendered: RenderedDescription[] = []
    for (const locale of locales) {
      const res = await request(app)
        .get('/api/Challenges')
        .set('Cookie', 'language=' + locale.key)
      assert.equal(res.status, 200)
      assert.ok(Array.isArray(res.body.data))
      for (const challenge of res.body.data) {
        const description = String(challenge.description ?? '')
        if (!/<iframe|<script|onerror\s*=/i.test(description)) {
          continue
        }
        const outcome = await renderDescription(description)
        if (outcome.iframeSrcs.some(src => /^\s*javascript:/i.test(src)) || outcome.dialogs.length > 0) {
          rendered.push({
            locale: locale.key,
            name: String(challenge.name),
            iframeSrcs: outcome.iframeSrcs,
            dialogs: outcome.dialogs
          })
        }
      }
    }
    assert.deepEqual(rendered, [])
  })
})

async function startChrome (): Promise<void> {
  const pageServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(EMPTY_PAGE)
  })
  await new Promise<void>(resolve => { pageServer.listen(0, '127.0.0.1', resolve) })
  const address = pageServer.address()
  if (address == null || typeof address === 'string') {
    throw new Error('Could not bind the description page')
  }
  const debuggingPort = 9300 + (process.pid % 1000)
  chrome = spawn('google-chrome', [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    `--remote-debugging-port=${debuggingPort}`,
    'about:blank'
  ], { stdio: ['ignore', 'ignore', 'pipe'] })
  const version = await waitForJson(`http://127.0.0.1:${debuggingPort}/json/version`)
  assert.match(String(version.Browser), /Chrome\//)
  const targets = await waitForJson(`http://127.0.0.1:${debuggingPort}/json/list`)
  const page = targets.find((target: { type: string }) => target.type === 'page')
  pageSocket = new WebSocket(page.webSocketDebuggerUrl)
  await new Promise<void>((resolve, reject) => {
    pageSocket?.addEventListener('open', () => { resolve() })
    pageSocket?.addEventListener('error', () => { reject(new Error('Chrome DevTools socket failed')) })
  })
  pageSocket.addEventListener('message', event => {
    const message = JSON.parse(String(event.data))
    if (message.id && cdpPending.has(message.id)) {
      const resolve = cdpPending.get(message.id)
      cdpPending.delete(message.id)
      resolve?.(message)
      return
    }
    if (message.method === 'Page.javascriptDialogOpening') {
      dialogs.push(String(message.params?.message ?? ''))
      const id = ++cdpId
      pageSocket?.send(JSON.stringify({
        id,
        method: 'Page.handleJavaScriptDialog',
        params: { accept: true }
      }))
    }
  })
  await cdp('Page.enable')
  await cdp('Runtime.enable')
  await cdp('Page.navigate', { url: `http://127.0.0.1:${address.port}/` })
  await new Promise(resolve => { setTimeout(resolve, 200) })
}

async function renderDescription (description: string): Promise<{ iframeSrcs: string[], dialogs: string[] }> {
  dialogs.length = 0
  const evaluated = await cdp('Runtime.evaluate', {
    expression: `(() => {
      const host = document.getElementById('host')
      host.innerHTML = ${JSON.stringify(description)}
      return JSON.stringify([...host.querySelectorAll('iframe')].map(frame => frame.getAttribute('src')))
    })()`,
    returnByValue: true
  })
  await new Promise(resolve => { setTimeout(resolve, 300) })
  const value = evaluated.result?.result?.value
  const iframeSrcs = typeof value === 'string' ? JSON.parse(value) as string[] : []
  return { iframeSrcs, dialogs: dialogs.slice() }
}

function cdp (method: string, params: Record<string, unknown> = {}): Promise<any> {
  const id = ++cdpId
  return new Promise((resolve, reject) => {
    cdpPending.set(id, resolve)
    pageSocket?.send(JSON.stringify({ id, method, params }))
    setTimeout(() => {
      if (cdpPending.has(id)) {
        cdpPending.delete(id)
        reject(new Error('Chrome DevTools timed out calling ' + method))
      }
    }, 8000)
  })
}

async function waitForJson (url: string): Promise<any> {
  let lastError: unknown
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const response = await fetch(url)
      return await response.json()
    } catch (error) {
      lastError = error
      await new Promise(resolve => { setTimeout(resolve, 200) })
    }
  }
  throw lastError
}
