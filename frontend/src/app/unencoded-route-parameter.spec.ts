/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { TestBed } from '@angular/core/testing'
import { provideRouter, Router } from '@angular/router'
import { RouterTestingHarness } from '@angular/router/testing'
import { TranslateModule } from '@ngx-translate/core'
import { MatSnackBarModule } from '@angular/material/snack-bar'

import { LoginGuard } from './app.guard'
import { AddressCreateComponent } from './address-create/address-create.component'
import { CodingChallengePageComponent } from './coding-challenge-page/coding-challenge-page.component'
import { AddressService } from './Services/address.service'
import { CodeSnippetService } from './Services/code-snippet.service'
import { CodeFixesService } from './Services/code-fixes.service'
import { RequestInterceptor } from './Services/request.interceptor'

const SHOP_ORIGIN = 'https://shop.example/'
const PLACEHOLDER_TOKEN = 'placeholder-token'
const PASSWORD_PATH = '/rest/user/change-password'

// Hash path Chrome keeps percent-encoded. Angular's parser decodes the segment once.
const TWO_LEVEL = '..%2F..%2Frest%2Fuser%2Fchange-password%3Fnew%3Dplaceholder-next%26repeat%3Dplaceholder-next'
const ONE_LEVEL = '..%2Frest%2Fuser%2Fchange-password%3Fnew%3Dplaceholder-next%26repeat%3Dplaceholder-next'
const DECODED_TWO_LEVEL = '../../rest/user/change-password?new=placeholder-next&repeat=placeholder-next'
const DECODED_ONE_LEVEL = '../rest/user/change-password?new=placeholder-next&repeat=placeholder-next'

describe('unencoded route parameters', () => {
  beforeEach(() => {
    localStorage.setItem('token', PLACEHOLDER_TOKEN)
  })

  afterEach(() => {
    localStorage.removeItem('token')
  })

  describe('address edit route', () => {
    it('keeps the signed-in address lookup on the address API when the id contains encoded dot segments', async () => {
      await TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot(), MatSnackBarModule],
        providers: [
          provideRouter([
            {
              path: 'address/edit/:addressId',
              component: AddressCreateComponent,
              canActivate: [LoginGuard]
            }
          ]),
          LoginGuard,
          provideHttpClient(withInterceptorsFromDi()),
          provideHttpClientTesting(),
          { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true }
        ]
      }).compileComponents()

      const harness = await RouterTestingHarness.create('/address/edit/' + TWO_LEVEL)
      const component = harness.routeDebugElement?.componentInstance as AddressCreateComponent
      expect(component instanceof AddressCreateComponent).toBe(true)
      expect(TestBed.inject(Router).url.startsWith('/address/edit/')).toBe(true)
      expect(component.mode).toBe('edit')
      component.save()

      const httpMock = TestBed.inject(HttpTestingController)
      const urls = drain(httpMock)
      expect(urls.length).toBeGreaterThan(0)

      for (const url of urls) {
        expect(addressRequestStaysPut(url)).toBe(true)
        expect(resolvedPath(url)).not.toBe(PASSWORD_PATH)
      }
    })
  })

  describe('coding-challenge route', () => {
    async function openChallenge (encodedKey: string) {
      await TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot()],
        providers: [
          provideRouter([
            {
              path: 'coding-challenge/:challengeKey',
              component: CodingChallengePageComponent
            }
          ]),
          provideHttpClient(withInterceptorsFromDi()),
          provideHttpClientTesting(),
          { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true }
        ]
      }).compileComponents()

      const harness = await RouterTestingHarness.create('/coding-challenge/' + encodedKey)
      const component = harness.routeDebugElement?.componentInstance as CodingChallengePageComponent
      expect(component instanceof CodingChallengePageComponent).toBe(true)
      expect(TestBed.inject(Router).url.startsWith('/coding-challenge/')).toBe(true)
      expect(typeof component.challengeKey).toBe('string')
      const httpMock = TestBed.inject(HttpTestingController)
      return drain(httpMock)
    }

    it('keeps snippet and fix lookups on their APIs for a one-level encoded key', async () => {
      const urls = await openChallenge(ONE_LEVEL)
      for (const url of urls) {
        expect(resolvedPath(url)).not.toBe(PASSWORD_PATH)
        expect(challengeRequestStaysPut(url)).toBe(true)
      }
    })

    it('keeps snippet and fix lookups on their APIs for a two-level encoded key', async () => {
      const urls = await openChallenge(TWO_LEVEL)
      for (const url of urls) {
        expect(resolvedPath(url)).not.toBe(PASSWORD_PATH)
        expect(challengeRequestStaysPut(url)).toBe(true)
      }
    })
  })

  describe('services that interpolate ids', () => {
    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(withInterceptorsFromDi()),
          provideHttpClientTesting(),
          { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true }
        ]
      })
    })

    it('AddressService get, put, and delete keep a hostile id inside the address API', () => {
      const service = TestBed.inject(AddressService)
      const httpMock = TestBed.inject(HttpTestingController)
      service.getById(DECODED_TWO_LEVEL).subscribe({ error: () => undefined })
      service.put(DECODED_TWO_LEVEL, {}).subscribe({ error: () => undefined })
      service.del(DECODED_TWO_LEVEL as unknown as number).subscribe({ error: () => undefined })
      expectConfined(httpMock, '/api/Addresss/')
    })

    it('CodeSnippetService keeps a hostile key inside the snippets API', () => {
      const service = TestBed.inject(CodeSnippetService)
      const httpMock = TestBed.inject(HttpTestingController)
      service.get(DECODED_ONE_LEVEL).subscribe({ error: () => undefined })
      service.get(DECODED_TWO_LEVEL).subscribe({ error: () => undefined })
      expectConfined(httpMock, '/snippets/')
    })

    it('CodeFixesService keeps a hostile key inside the fixes API', () => {
      const service = TestBed.inject(CodeFixesService)
      const httpMock = TestBed.inject(HttpTestingController)
      service.get(DECODED_ONE_LEVEL).subscribe({ error: () => undefined })
      service.get(DECODED_TWO_LEVEL).subscribe({ error: () => undefined })
      expectConfined(httpMock, '/snippets/fixes/')
    })
  })
})

function drain (httpMock: HttpTestingController): string[] {
  const urls: string[] = []
  let pending = httpMock.match(() => true)
  let rounds = 0
  while (pending.length > 0 && rounds < 5) {
    rounds++
    const batch = pending
    pending = []
    for (const req of batch) {
      expect(req.request.headers.get('Authorization')).toBe('Bearer ' + PLACEHOLDER_TOKEN)
      urls.push(req.request.url)
      if (req.request.url.includes('/api/Challenges')) {
        req.flush({ data: [] })
      } else if (req.request.url.includes('/snippets/fixes/')) {
        req.flush({ fixes: [] })
      } else if (req.request.url.includes('/snippets/')) {
        req.flush({ snippet: '' })
      } else {
        req.flush({ data: {} })
      }
    }
    pending = httpMock.match(() => true)
  }
  httpMock.verify()
  return urls
}

function expectConfined (httpMock: HttpTestingController, prefix: string) {
  const urls = drain(httpMock)
  expect(urls.length).toBeGreaterThan(0)
  for (const url of urls) {
    expect(confinedToSingleId(url, prefix)).toBe(true)
    expect(resolvedPath(url)).not.toBe(PASSWORD_PATH)
  }
}

function challengeRequestStaysPut (url: string): boolean {
  const pathOnly = url.split('?')[0]
  if (pathOnly.includes('/api/Challenges')) {
    const path = resolvedPath(url)
    return path === '/api/Challenges' || path === '/api/Challenges/'
  }
  if (pathOnly.includes('/snippets/fixes/')) {
    return confinedToSingleId(url, '/snippets/fixes/')
  }
  if (pathOnly.includes('/snippets/')) {
    return confinedToSingleId(url, '/snippets/')
  }
  return false
}

function addressRequestStaysPut (url: string): boolean {
  const path = resolvedPath(url)
  if (path === '/api/Addresss' || path === '/api/Addresss/') {
    return true
  }
  return confinedToSingleId(url, '/api/Addresss/')
}

function confinedToSingleId (url: string, prefix: string): boolean {
  const path = resolvedPath(url)
  if (!path.startsWith(prefix)) {
    return false
  }
  const idSegment = path.slice(prefix.length)
  return idSegment.length > 0 && !idSegment.includes('/')
}

function resolvedPath (url: string): string {
  return new URL(url, SHOP_ORIGIN).pathname
}
