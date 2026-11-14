/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ChildProcess, spawn } from 'node:child_process'
import path from 'node:path'
import { ErrorHandler } from '@angular/core'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { provideHttpClient, withInterceptorsFromDi, HTTP_INTERCEPTORS } from '@angular/common/http'
import { ActivatedRoute, provideRouter } from '@angular/router'
import { TranslateModule } from '@ngx-translate/core'
import { CookieModule, CookieService } from 'ngy-cookie'
import { of } from 'rxjs'

import { CodingChallengePageComponent } from './coding-challenge-page.component'
import { CodingChallengeFindItComponent } from './components/coding-challenge-find-it/coding-challenge-find-it.component'
import { CodingChallengeFixItComponent } from './components/coding-challenge-fix-it/coding-challenge-fix-it.component'
import { ChallengeService } from '../Services/challenge.service'
import { CodeFixesService } from '../Services/code-fixes.service'
import { RequestInterceptor } from '../Services/request.interceptor'
import { type CodeSnippet } from '../Services/code-snippet.service'

const UNKNOWN_KEY = 'notARealKey'
const MISSING_SNIPPET_MESSAGE = 'No code challenge for challenge key: notARealKey'

// The shape serveCodeSnippet sends for an unknown key: a JSON object, not source text.
const SNIPPET_FROM_404 = {
  snippet: { status: 'error', error: MISSING_SNIPPET_MESSAGE }
} as unknown as CodeSnippet

describe('unknown coding-challenge key', () => {
  let server: ChildProcess | null = null
  let serverLog = ''

  async function startShop () {
    const repoRoot = path.resolve(process.cwd(), '..')
    server = spawn(process.execPath, [
      '--import', 'tsx',
      'test/server/helpers/unknown-coding-challenge-server.ts'
    ], {
      cwd: repoRoot,
      env: { ...process.env, NODE_ENV: 'test', PORT: '3000' },
      stdio: ['ignore', 'pipe', 'pipe']
    })
    server.stdout?.on('data', (chunk: Buffer) => {
      serverLog += chunk.toString()
    })
    server.stderr?.on('data', (chunk: Buffer) => {
      serverLog += chunk.toString()
    })
    const deadline = Date.now() + 60000
    while (Date.now() < deadline) {
      if (server.exitCode !== null) {
        throw new Error('coding-challenge server exited early:\n' + serverLog)
      }
      try {
        const res = await fetch('http://127.0.0.1:3000/snippets/' + UNKNOWN_KEY)
        if (res.status === 404) return
      } catch {
        // Process is still booting.
      }
      await new Promise(resolve => setTimeout(resolve, 200))
    }
    throw new Error('coding-challenge server did not accept requests:\n' + serverLog)
  }

  function stopShop () {
    if (server && server.exitCode === null) {
      server.kill('SIGTERM')
    }
    server = null
  }

  describe('coding-challenge page', () => {
    const errors: unknown[] = []

    beforeAll(async () => {
      await startShop()
    }, 70000)

    afterAll(() => {
      stopShop()
    })

    beforeEach(async () => {
      errors.length = 0
      localStorage.removeItem('token')
      localStorage.removeItem('email')
      TestBed.resetTestingModule()
      await TestBed.configureTestingModule({
        imports: [
          TranslateModule.forRoot(),
          CookieModule.forRoot(),
          CodingChallengePageComponent
        ],
        providers: [
          provideRouter([]),
          provideHttpClient(withInterceptorsFromDi()),
          { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true },
          {
            provide: ActivatedRoute,
            useValue: { params: of({ challengeKey: UNKNOWN_KEY }) }
          },
          {
            provide: ErrorHandler,
            useValue: { handleError: (error: unknown) => { errors.push(error) } }
          }
        ]
      }).compileComponents()
    })

    async function renderPage (): Promise<ComponentFixture<CodingChallengePageComponent>> {
      const fixture = TestBed.createComponent(CodingChallengePageComponent)
      fixture.detectChanges()
      await fixture.whenStable()
      fixture.detectChanges()
      return fixture
    }

    it('leaves the snippet unset, shows the error text, and does not build an editor', async () => {
      let failure: unknown = null
      let fixture: ComponentFixture<CodingChallengePageComponent> | null = null
      try {
        fixture = await renderPage()
      } catch (err) {
        failure = err
      }
      expect(failure).toBeNull()
      expect(errors).toEqual([])
      expect(fixture).not.toBeNull()
      const page = fixture!.componentInstance
      expect(page.challengeKey).toBe(UNKNOWN_KEY)
      expect(page.isLoaded).toBe(true)
      expect(page.snippet).toBeNull()
      const view: HTMLElement = fixture!.nativeElement
      expect(view.textContent).toContain(MISSING_SNIPPET_MESSAGE)
      expect(view.querySelector('mat-spinner')).toBeNull()
      expect(view.querySelector('coding-challenge-find-it')).toBeNull()
      expect(view.querySelector('coding-challenge-fix-it')).toBeNull()
      expect(view.querySelector('.cm-editor')).toBeNull()
    })
  })

  describe('editors given a non-string snippet', () => {
    beforeEach(() => {
      localStorage.removeItem('token')
      localStorage.removeItem('email')
    })

    async function findItWith (snippet: CodeSnippet): Promise<ComponentFixture<CodingChallengeFindItComponent>> {
      TestBed.resetTestingModule()
      await TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot(), CookieModule.forRoot(), CodingChallengeFindItComponent],
        providers: [
          provideHttpClient(withInterceptorsFromDi()),
          {
            provide: ChallengeService,
            useValue: { continueCodeFindIt: () => of('continue') }
          },
          { provide: CookieService, useValue: { put: () => undefined, get: () => undefined, hasKey: () => false } }
        ]
      }).compileComponents()
      const fixture = TestBed.createComponent(CodingChallengeFindItComponent)
      fixture.componentRef.setInput('challengeKey', UNKNOWN_KEY)
      fixture.componentRef.setInput('snippet', snippet)
      fixture.componentRef.setInput('alreadySolved', false)
      return fixture
    }

    async function fixItWith (snippet: CodeSnippet): Promise<ComponentFixture<CodingChallengeFixItComponent>> {
      TestBed.resetTestingModule()
      await TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot(), CookieModule.forRoot(), CodingChallengeFixItComponent],
        providers: [
          provideHttpClient(withInterceptorsFromDi()),
          {
            provide: ChallengeService,
            useValue: { continueCodeFixIt: () => of('continue') }
          },
          {
            provide: CodeFixesService,
            useValue: { check: () => of({ verdict: false }) }
          },
          { provide: CookieService, useValue: { put: () => undefined, get: () => undefined, hasKey: () => false } }
        ]
      }).compileComponents()
      const fixture = TestBed.createComponent(CodingChallengeFixItComponent)
      fixture.componentRef.setInput('challengeKey', UNKNOWN_KEY)
      fixture.componentRef.setInput('snippet', snippet)
      fixture.componentRef.setInput('fixes', ['fixed line'])
      fixture.componentRef.setInput('alreadySolved', false)
      return fixture
    }

    function expectNoEditor (fixture: ComponentFixture<unknown>) {
      let failure: unknown = null
      try {
        fixture.detectChanges()
      } catch (err) {
        failure = err
      }
      expect(failure).toBeNull()
      expect((fixture.nativeElement as HTMLElement).querySelector('.cm-editor')).toBeNull()
    }

    it('find-it does not detect a language or create an editor for the 404 body', async () => {
      expectNoEditor(await findItWith(SNIPPET_FROM_404))
    })

    it('find-it does not detect a language or create an editor when snippet text is missing', async () => {
      expectNoEditor(await findItWith({ snippet: undefined } as unknown as CodeSnippet))
    })

    it('fix-it does not detect a language or create an editor for the 404 body', async () => {
      expectNoEditor(await fixItWith(SNIPPET_FROM_404))
    })

    it('fix-it does not detect a language or create an editor when snippet text is missing', async () => {
      expectNoEditor(await fixItWith({ snippet: undefined } as unknown as CodeSnippet))
    })
  })
})
