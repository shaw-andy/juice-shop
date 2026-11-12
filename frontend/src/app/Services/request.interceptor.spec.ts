/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type IncomingHttpHeaders, type Server, createServer } from 'node:http'
import { HTTP_INTERCEPTORS, HttpClient, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { environment } from '../../environments/environment'
import { CtfSystemWideNotificationComponent } from '../ctf-system-wide-notification/ctf-system-wide-notification.component'
import { ConfigurationService } from './configuration.service'
import { CtfSystemWideNotificationService } from './ctf-system-wide-notification.service'
import { RequestInterceptor } from './request.interceptor'
import { UserService } from './user.service'

const SHOP_SESSION = 'placeholder-shop-session'
const SHOP_EMAIL = 'placeholder-email@example.test'
const NOTIFICATION_BODY = { message: 'maintenance window', enabled: true, updatedAt: '2026-01-01T00:00:00Z' }

interface CapturedRequest {
  method: string
  url: string
  headers: IncomingHttpHeaders
}

function rememberShopSession (includeEmail = true): void {
  localStorage.setItem('token', SHOP_SESSION)
  if (includeEmail) {
    localStorage.setItem('email', SHOP_EMAIL)
  } else {
    localStorage.removeItem('email')
  }
}

function forgetShopSession (): void {
  localStorage.removeItem('token')
  localStorage.removeItem('email')
}

function shopSessionHeaders (headers: { get (name: string): string | null } | IncomingHttpHeaders): { authorization: string | undefined, email: string | undefined } {
  if (typeof (headers as { get?: unknown }).get === 'function') {
    const httpHeaders = headers as { get (name: string): string | null }
    return {
      authorization: httpHeaders.get('Authorization') ?? undefined,
      email: httpHeaders.get('X-User-Email') ?? undefined
    }
  }
  const nodeHeaders = headers as IncomingHttpHeaders
  const authorization = nodeHeaders.authorization
  const email = nodeHeaders['x-user-email']
  return {
    authorization: Array.isArray(authorization) ? authorization[0] : authorization,
    email: Array.isArray(email) ? email[0] : email
  }
}

function expectNoShopSession (headers: { get (name: string): string | null } | IncomingHttpHeaders): void {
  expect(shopSessionHeaders(headers)).toEqual({ authorization: undefined, email: undefined })
}

async function waitForNotification (fixture: ComponentFixture<CtfSystemWideNotificationComponent>): Promise<void> {
  const started = Date.now()
  while (fixture.componentInstance.notification === null && Date.now() - started < 1000) {
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

function startProbe (): Promise<{
  origin: string
  requests: CapturedRequest[]
  nextGet: () => Promise<CapturedRequest>
  close: () => Promise<void>
}> {
  const requests: CapturedRequest[] = []
  let waitForGet: ((request: CapturedRequest) => void) | null = null
  const server: Server = createServer((req, res) => {
    const captured = { method: req.method ?? '', url: req.url ?? '', headers: req.headers }
    requests.push(captured)
    if (captured.method === 'GET' && waitForGet) {
      const resolve = waitForGet
      waitForGet = null
      resolve(captured)
    }
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'authorization, x-user-email, accept, content-type',
      'Content-Type': 'application/json'
    })
    res.end(captured.method === 'OPTIONS' ? '' : JSON.stringify(NOTIFICATION_BODY))
  })

  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('probe server did not bind a TCP port'))
        return
      }
      resolve({
        origin: `http://127.0.0.1:${address.port}`,
        requests,
        nextGet: () => new Promise((resolveGet) => {
          const existing = requests.find((request) => request.method === 'GET')
          if (existing) {
            resolveGet(existing)
            return
          }
          waitForGet = resolveGet
        }),
        close: () => new Promise((resolveClose, rejectClose) => {
          server.close((error) => error ? rejectClose(error) : resolveClose())
        })
      })
    })
  })
}

describe('RequestInterceptor shop session headers', () => {
  afterEach(() => {
    forgetShopSession()
  })

  describe('external notification poll', () => {
    let probe: Awaited<ReturnType<typeof startProbe>>
    let fixture: ComponentFixture<CtfSystemWideNotificationComponent>

    beforeEach(async () => {
      probe = await startProbe()
      const configurationService = {
        getApplicationConfiguration: vi.fn().mockReturnValue(of({
          ctf: {
            systemWideNotifications: {
              url: `${probe.origin}/notify`,
              pollFrequencySeconds: 3600
            }
          }
        }))
      }

      await TestBed.configureTestingModule({
        imports: [CtfSystemWideNotificationComponent],
        providers: [
          provideHttpClient(withInterceptorsFromDi()),
          { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true },
          { provide: ConfigurationService, useValue: configurationService },
          CtfSystemWideNotificationService
        ]
      }).compileComponents()
    })

    afterEach(async () => {
      fixture?.destroy()
      await probe.close()
    })

    it('does not send the shop session when the notification host allows those request headers', async () => {
      rememberShopSession()
      fixture = TestBed.createComponent(CtfSystemWideNotificationComponent)
      fixture.detectChanges()

      const get = await probe.nextGet()
      await waitForNotification(fixture)

      expect(get.url).toBe('/notify')
      expect(fixture.componentInstance.notification).toEqual(NOTIFICATION_BODY)
      expectNoShopSession(get.headers)
      expect(probe.requests.every((request) => shopSessionHeaders(request.headers).authorization === undefined)).toBe(true)
      expect(probe.requests.every((request) => shopSessionHeaders(request.headers).email === undefined)).toBe(true)
    })

    it('does not send a token-only session when no email was remembered', async () => {
      rememberShopSession(false)
      fixture = TestBed.createComponent(CtfSystemWideNotificationComponent)
      fixture.detectChanges()

      const get = await probe.nextGet()
      await waitForNotification(fixture)

      expect(fixture.componentInstance.notification).toEqual(NOTIFICATION_BODY)
      expectNoShopSession(get.headers)
    })

    it('does not send the shop session when the foreign url merely contains the shop origin', async () => {
      rememberShopSession()
      const http = TestBed.inject(HttpClient)
      const received = probe.nextGet()
      http.get(`${probe.origin}/notify?next=${encodeURIComponent(environment.hostServer)}`).subscribe({
        error: () => undefined
      })

      const get = await received

      expect(get.url).toContain('/notify?next=')
      expectNoShopSession(get.headers)
    })
  })

  describe('other HttpClient calls', () => {
    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(withInterceptorsFromDi()),
          provideHttpClientTesting(),
          { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true },
          UserService
        ]
      })
    })

    afterEach(() => {
      TestBed.inject(HttpTestingController).verify()
    })

    it('still attaches the shop session to a same-origin shop API call', () => {
      rememberShopSession()
      const http = TestBed.inject(HttpClient)
      const httpMock = TestBed.inject(HttpTestingController)

      http.post(`${environment.hostServer}/rest/basket/1/checkout`, {}).subscribe()

      const req = httpMock.expectOne(`${environment.hostServer}/rest/basket/1/checkout`)
      expect(shopSessionHeaders(req.request.headers)).toEqual({
        authorization: `Bearer ${SHOP_SESSION}`,
        email: SHOP_EMAIL
      })
      req.flush({})
    })

    it('does not attach the shop session to the Google userinfo request', () => {
      rememberShopSession()
      const users = TestBed.inject(UserService)
      const httpMock = TestBed.inject(HttpTestingController)

      users.oauthLogin('placeholder-access-token').subscribe()

      const req = httpMock.expectOne('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=placeholder-access-token')
      expectNoShopSession(req.request.headers)
      req.flush({ id: 'placeholder' })
    })

    it('does not attach the shop session to urls that only resemble the shop origin', () => {
      rememberShopSession()
      const http = TestBed.inject(HttpClient)
      const httpMock = TestBed.inject(HttpTestingController)
      const foreignUrls = [
        'https://notifications.example/status',
        'https://localhost:3000/notify',
        'http://localhost:3001/notify',
        'http://127.0.0.1/notify?next=http://localhost:3000',
        'http://localhost:3000@notifications.example/notify'
      ]

      for (const url of foreignUrls) {
        http.get(url).subscribe()
        const req = httpMock.expectOne(url)
        expectNoShopSession(req.request.headers)
        req.flush(NOTIFICATION_BODY)
      }
    })
  })
})
