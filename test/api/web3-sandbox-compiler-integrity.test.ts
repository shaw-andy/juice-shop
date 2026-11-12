/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import express, { type Express, type Request, type Response } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { UserModel } from '../../models/user'
import { PrivacyRequestModel } from '../../models/privacyRequests'

const componentPath = path.resolve('frontend/src/app/web3-sandbox/web3-sandbox.component.ts')
const frontendRequire = createRequire(path.resolve('frontend/package.json'))

function loadEsbuild (): { build: (options: Record<string, unknown>) => Promise<{ outputFiles: Array<{ text: string }> }> } {
  for (const spec of ['esbuild', '@angular/build/node_modules/esbuild']) {
    try {
      return frontendRequire(spec)
    } catch {
      // The Angular build pulls esbuild in; it may be hoisted or nested.
    }
  }
  return frontendRequire('esbuild')
}

interface CompilerEffect {
  which: string
  passwordFieldReturned: boolean
  hadSessionCookie: boolean
  hadAuthorization: boolean
}

function compilerVersions (): string[] {
  const source = fs.readFileSync(componentPath, 'utf8')
  const block = source.match(/const compilerReleases = \{([\s\S]*?)\n\}/)
  assert.ok(block, 'compilerReleases is missing from the web3 sandbox')
  return [...block[1].matchAll(/'([^']+)':\s*'[^']+'/g)].map((match) => match[1])
}

function sessionCookie (token: string): string {
  const expires = new Date(Date.now() + 8 * 60 * 60 * 1000)
  return 'token=' + encodeURIComponent(token) + ';path=/;expires=' + expires.toUTCString()
}

function substitutedCompiler (which: string, origin: string): string {
  return `
    var base = (self.location && self.location.origin && self.location.origin !== 'null')
      ? self.location.origin
      : ${JSON.stringify(origin)}
    function syncSend (method, url, body, contentType) {
      var xhr = new XMLHttpRequest()
      xhr.open(method, url, false)
      if (contentType) xhr.setRequestHeader('content-type', contentType)
      xhr.send(body == null ? null : body)
      return { status: xhr.status, body: xhr.responseText }
    }
    var whoami = syncSend('GET', base + '/rest/user/whoami?fields=id,email,password,username')
    syncSend('POST', base + '/profile', JSON.stringify({ username: 'compiler-taken-over' }), 'application/json')
    syncSend('POST', base + '/profile/image/url', 'imageUrl=' + encodeURIComponent(base + '/compiler-ssrf-target.jpg'), 'application/x-www-form-urlencoded')
    syncSend('POST', base + '/compiler-integrity-probe', JSON.stringify({ which: ${JSON.stringify(which)}, whoami: whoami }), 'application/json')
    syncSend('POST', base + '/dataerasure', JSON.stringify({}), 'application/json')
    self.Module = { _solidity_compile: true, cwrap: function () { return function () { return '{}' } } }
  `
}

async function bundleHarness (versions: string[]): Promise<string> {
  const esbuild = loadEsbuild() as {
    build: (options: Record<string, unknown>) => Promise<{ outputFiles: Array<{ text: string }> }>
  }
  const entry = path.join(os.tmpdir(), `compiler-integrity-entry-${process.pid}.ts`)
  fs.writeFileSync(entry, `
    import { Web3SandboxComponent } from ${JSON.stringify(componentPath)}
    const versions = ${JSON.stringify(versions)}
    const results = []
    for (const version of versions) {
      const component = Object.create(Web3SandboxComponent.prototype)
      component.selectedCompilerVersion = version
      component.compilerErrors = []
      try {
        await component.compileAndFetchContracts('contract C {}')
        results.push({ version, settled: true })
      } catch {
        results.push({ version, settled: true })
      }
    }
    globalThis.__compileResults = results
  `)
  try {
    const bundled = await esbuild.build({
      entryPoints: [entry],
      bundle: true,
      format: 'esm',
      platform: 'browser',
      write: false,
      absWorkingDir: path.resolve('frontend'),
      nodePaths: [path.resolve('frontend/node_modules')],
      tsconfigRaw: {
        compilerOptions: {
          experimentalDecorators: true,
          useDefineForClassFields: false,
          target: 'ES2022'
        }
      },
      plugins: [{
        name: 'stub-unrelated',
        setup (build: { onResolve: Function, onLoad: Function }) {
          build.onResolve({ filter: /.*/ }, (args: { kind?: string, path: string, importer?: string }) => {
            if (args.kind === 'entry-point') return null
            if (args.path === componentPath || args.path.includes('web3-sandbox.component')) return null
            if (args.path === 'solidity-browser-compiler') return null
            if (args.importer?.includes('solidity-browser-compiler') || args.importer?.includes(`${path.sep}node_modules${path.sep}`)) return null
            return { path: args.path, namespace: 'stub' }
          })
          build.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({
            contents: `
              export const Component = () => (cls) => cls
              export const ViewChild = () => () => {}
              export const ChangeDetectionStrategy = { Eager: 0 }
              export class ChangeDetectorRef {}
              export class ElementRef {}
              export const inject = () => ({})
              export const getDefaultProvider = () => ({})
              export const ethers = {}
              export const createClient = () => ({})
              export const connect = async () => ({})
              export const disconnect = async () => {}
              export const getAccount = () => ({})
              export class InjectedConnector {}
              export const MatInputModule = {}
              export const MatFormFieldModule = {}
              export const MatLabel = {}
              export const TranslateModule = {}
              export const MatButtonModule = {}
              export const FormsModule = {}
              export const MatIconModule = {}
              export class EditorView {}
              export const basicSetup = {}
              export const EditorState = { create () { return {} } }
              export const getLanguageExtension = () => ({})
              export const juiceShopTheme = () => []
              export class KeysService {}
              export class SnackBarHelperService {}
            `,
            loader: 'js'
          }))
        }
      }]
    })
    return bundled.outputFiles[0].text
  } finally {
    fs.rmSync(entry, { force: true })
  }
}

interface BrowserSession {
  evaluate: (expression: string) => Promise<unknown>
  close: () => Promise<void>
}

async function openHarness (url: string): Promise<BrowserSession> {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-compiler-'))
  const chrome = spawn(process.env.CHROME_PATH ?? 'google-chrome', [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    `--user-data-dir=${profile}`,
    '--remote-debugging-port=0',
    '--no-first-run',
    '--no-default-browser-check'
  ], { stdio: ['ignore', 'pipe', 'pipe'] })
  const browserWsUrl = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Chrome did not open a debugging port')), 20000)
    chrome.stderr.on('data', (chunk: Buffer) => {
      const match = String(chunk).match(/DevTools listening on (ws:\/\/\S+)/)
      if (match) {
        clearTimeout(timer)
        resolve(match[1])
      }
    })
    chrome.once('exit', (code) => {
      clearTimeout(timer)
      reject(new Error('Chrome exited before the debugging port was ready: ' + String(code)))
    })
  })
  const versionUrl = browserWsUrl.replace('ws://', 'http://').replace(/\/devtools\/browser\/.*/, '/json/version')
  const version = await (await fetch(versionUrl)).json() as { webSocketDebuggerUrl: string }
  const ws = new WebSocket(version.webSocketDebuggerUrl)
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener('open', () => resolve())
    ws.addEventListener('error', () => reject(new Error('Chrome debugging socket failed')))
  })

  let nextId = 0
  const pending = new Map<number, { resolve: (value: any) => void, reject: (error: Error) => void }>()
  function send (method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<any> {
    const id = ++nextId
    const payload: Record<string, unknown> = { id, method, params }
    if (sessionId) payload.sessionId = sessionId
    ws.send(JSON.stringify(payload))
    return new Promise((resolve, reject) => pending.set(id, { resolve, reject }))
  }

  const counts = new Map<string, number>()
  ws.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data))
    if (message.id && pending.has(message.id)) {
      const waiter = pending.get(message.id)!
      pending.delete(message.id)
      if (message.error) waiter.reject(new Error(JSON.stringify(message.error)))
      else waiter.resolve(message.result)
      return
    }
    if (message.method === 'Target.attachedToTarget') {
      const sessionId = message.params.sessionId as string
      void send('Fetch.enable', {
        patterns: [{ urlPattern: '*binaries.soliditylang.org*', requestStage: 'Request' }]
      }, sessionId).then(async () => {
        if (message.params.waitingForDebugger) await send('Runtime.runIfWaitingForDebugger', {}, sessionId)
      }).catch(() => {})
    }
    if (message.method === 'Fetch.requestPaused') {
      const requestUrl = message.params.request.url as string
      const count = (counts.get(requestUrl) ?? 0) + 1
      counts.set(requestUrl, count)
      const body = substitutedCompiler(count === 1 ? 'first' : 'second', new URL(url).origin)
      void send('Fetch.fulfillRequest', {
        requestId: message.params.requestId,
        responseCode: 200,
        responseHeaders: [{ name: 'Content-Type', value: 'application/javascript; charset=utf-8' }],
        body: Buffer.from(body).toString('base64')
      }, message.sessionId).catch(() => {})
    }
  })

  await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true })
  const created = await send('Target.createTarget', { url: 'about:blank' })
  const attached = await send('Target.attachToTarget', { targetId: created.targetId, flatten: true })
  const sessionId = attached.sessionId as string
  await send('Fetch.enable', {
    patterns: [{ urlPattern: '*binaries.soliditylang.org*', requestStage: 'Request' }]
  }, sessionId)
  await send('Page.enable', {}, sessionId)
  await send('Runtime.enable', {}, sessionId)
  await send('Page.navigate', { url }, sessionId)

  return {
    async evaluate (expression: string) {
      const evaluated = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId)
      if (evaluated.exceptionDetails) {
        throw new Error(evaluated.exceptionDetails.text ?? 'Page evaluation failed')
      }
      return evaluated.result?.value
    },
    async close () {
      ws.close()
      if (chrome.exitCode == null && !chrome.killed) {
        chrome.kill()
        await new Promise<void>((resolve) => chrome.once('exit', () => resolve()))
      }
      try {
        fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
      } catch {
        // Chrome can still be flushing the profile after exit.
      }
    }
  }
}

void describe('web3 sandbox compiler integrity', () => {
  void it('does not run a substituted Solidity compiler in the shop origin', async () => {
    const versions = compilerVersions()
    assert.ok(versions.length > 0)
    const bundle = await bundleHarness(versions)
    const { app, sequelize } = await createTestApp()
    const email = 'compiler-integrity@example.test'
    const password = 'placeholder-password'
    await register(app, { email, password })
    const authentication = await login(app, { email, password })
    const beforeUser = await UserModel.findOne({ where: { email } })
    assert.ok(beforeUser)
    const before = beforeUser
    const deletionsBefore = await PrivacyRequestModel.count({ where: { UserId: before.id } })
    const executed: CompilerEffect[] = []
    const imageFetches: string[] = []
    let passwordFieldReturned = false

    const router = express.Router()
    router.get('/compiler-integrity-harness', (_req: Request, res: Response) => {
      res.set('Cache-Control', 'no-store')
      res.type('html').send(
        '<!doctype html><meta charset="utf-8"><script>document.cookie = ' +
        JSON.stringify(sessionCookie(authentication.token)) +
        '</script><script type="module" src="/compiler-integrity-bundle.js"></script>'
      )
    })
    router.get('/compiler-integrity-bundle.js', (_req: Request, res: Response) => {
      res.type('js').send(bundle)
    })
    router.post('/compiler-integrity-probe', (req: Request, res: Response) => {
      const whoamiBody = req.body?.whoami?.body
      let disclosed = false
      if (typeof whoamiBody === 'string') {
        try {
          const parsed = JSON.parse(whoamiBody) as { user?: object }
          disclosed = Object.prototype.hasOwnProperty.call(parsed.user ?? {}, 'password')
        } catch {
          disclosed = false
        }
      }
      passwordFieldReturned = passwordFieldReturned || disclosed
      const cookie = req.headers.cookie ?? ''
      executed.push({
        which: String(req.body?.which ?? ''),
        passwordFieldReturned: disclosed,
        hadSessionCookie: cookie.split(';').some((part) => part.trim().startsWith('token=')),
        hadAuthorization: req.headers.authorization != null
      })
      res.json({ ok: true })
    })
    router.get('/compiler-ssrf-target.jpg', (req: Request, res: Response) => {
      imageFetches.push(req.originalUrl)
      res.type('jpg').end('x')
    })
    app.use(router)
    const stack = (app as Express & { _router: { stack: any[] } })._router.stack
    const layer = stack.pop()
    const errorIndex = stack.findIndex((entry) => entry.handle?.length === 4)
    stack.splice(errorIndex > 0 ? errorIndex - 1 : stack.length, 0, layer)

    const server = http.createServer(app)
    let browser: BrowserSession | undefined
    try {
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
      const address = server.address()
      assert.ok(address && typeof address !== 'string')
      const origin = `http://127.0.0.1:${address.port}`
      browser = await openHarness(origin + '/compiler-integrity-harness')
      let results: Array<{ version: string }> = []
      const deadline = Date.now() + 30000
      while (Date.now() < deadline) {
        const value = await browser.evaluate('globalThis.__compileResults || null')
        if (Array.isArray(value) && value.length === versions.length) {
          results = value as Array<{ version: string }>
          break
        }
        await new Promise((resolve) => setTimeout(resolve, 200))
      }
      const after = await UserModel.findOne({ where: { email } })
      assert.ok(after)
      const deletionsAfter = await PrivacyRequestModel.count({ where: { UserId: before.id } })
      assert.deepEqual({
        versionsCompiled: results.map((result) => result.version),
        substitutedScriptsExecuted: executed.length,
        passwordFieldReturned,
        sessionCookieAttached: executed.some((effect) => effect.hadSessionCookie),
        authorizationHeaderSent: executed.some((effect) => effect.hadAuthorization),
        usernameUnchanged: after.username === before.username,
        profileImageUnchanged: after.profileImage === before.profileImage,
        profileImageFetches: imageFetches.length,
        deletionRequests: deletionsAfter - deletionsBefore
      }, {
        versionsCompiled: versions,
        substitutedScriptsExecuted: 0,
        passwordFieldReturned: false,
        sessionCookieAttached: false,
        authorizationHeaderSent: false,
        usernameUnchanged: true,
        profileImageUnchanged: true,
        profileImageFetches: 0,
        deletionRequests: 0
      })
    } finally {
      await browser?.close()
      await new Promise<void>((resolve) => server.close(() => resolve()))
      const upload = path.resolve(`frontend/dist/frontend/assets/public/images/uploads/${before.id}.jpg`)
      fs.rmSync(upload, { force: true })
      await sequelize.close()
    }
  }, { timeout: 180000 })
})
