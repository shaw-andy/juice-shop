/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { CookieModule } from 'ngy-cookie'
import { TranslateModule } from '@ngx-translate/core'
import { LoginComponent } from './login.component'
import { WindowRefService } from '../Services/window-ref.service'

interface AuthorizedRedirect {
  uri: string
  proxy?: string
}

interface ServedConfig {
  config: {
    application: {
      googleOauth: {
        authorizedRedirects: AuthorizedRedirect[]
      }
    }
  }
}

function repositoryRoot (): string {
  const candidates = [process.cwd(), path.resolve(process.cwd(), '..')]
  for (const candidate of candidates) {
    if (existsSync(path.join(candidate, 'config', 'default.yml')) && existsSync(path.join(candidate, 'routes', 'appConfiguration.ts'))) {
      return candidate
    }
  }
  throw new Error('Could not find the Juice Shop repository root')
}

function servedApplicationConfiguration (): ServedConfig {
  const root = repositoryRoot()
  const stdout = execFileSync(process.execPath, [
    '--import', 'tsx',
    '--input-type=module',
    '--eval', `
      process.env.NODE_ENV = 'test'
      const { retrieveAppConfiguration } = await import('./routes/appConfiguration.ts')
      let payload
      const res = { json (body) { payload = JSON.parse(JSON.stringify(body)) } }
      retrieveAppConfiguration()({}, res)
      process.stdout.write(JSON.stringify(payload))
    `
  ], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'test' }
  })
  return JSON.parse(stdout) as ServedConfig
}

// response_type=token asks the authorization server to add the access token to
// the fragment of redirect_uri. The fragment is available to script on that origin.
function implicitGrantFragmentOrigin (redirectUri: string): string {
  const landed = new URL(redirectUri)
  const fragment = new URLSearchParams(landed.hash.startsWith('#') ? landed.hash.slice(1) : '')
  fragment.append('access_token', 'PLACEHOLDER')
  fragment.append('token_type', 'Bearer')
  landed.hash = fragment.toString()
  return landed.origin
}

const served = servedApplicationConfiguration()
const configurationUrl = 'http://localhost:3000/rest/admin/application-configuration'

describe('Google sign-in redirect origin', () => {
  let fixture: ComponentFixture<LoginComponent>
  let replace: ReturnType<typeof vi.fn<(url: string) => void>>
  let httpMock: HttpTestingController
  const location: { protocol: string, host: string, replace: (url: string) => void } = {
    protocol: 'http:',
    host: 'localhost:3000',
    replace: () => undefined
  }

  beforeEach(async () => {
    replace = vi.fn<(url: string) => void>()
    location.replace = replace

    await TestBed.configureTestingModule({
      imports: [
        RouterTestingModule.withRoutes([]),
        CookieModule.forRoot(),
        TranslateModule.forRoot(),
        LoginComponent
      ],
      providers: [
        {
          provide: WindowRefService,
          useValue: { nativeWindow: { location } }
        },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    httpMock = TestBed.inject(HttpTestingController)
    fixture = TestBed.createComponent(LoginComponent)
  })

  afterEach(() => {
    httpMock.verify()
  })

  for (const entry of served.config.application.googleOauth.authorizedRedirects) {
    it(`keeps an implicit access token on ${entry.uri}`, () => {
      const shop = new URL(entry.uri)
      location.protocol = shop.protocol
      location.host = shop.host

      fixture.detectChanges()
      const request = httpMock.expectOne(configurationUrl)
      expect(request.request.method).toBe('GET')
      request.flush(served)
      fixture.detectChanges()

      const button = (fixture.nativeElement as HTMLElement).querySelector('#loginButtonGoogle') as HTMLButtonElement | null
      expect(button).toBeTruthy()
      button?.click()

      expect(replace).toHaveBeenCalledTimes(1)
      const navigation = new URL(replace.mock.calls[0][0] as string)
      const responseType = navigation.searchParams.get('response_type') ?? ''
      const redirectUri = navigation.searchParams.get('redirect_uri')
      expect(redirectUri).toBeTruthy()
      const redirect = new URL(redirectUri as string)
      // responseType is on both sides so a mismatch still prints the grant that was requested.
      expect({ responseType, redirectOrigin: redirect.origin }).toEqual({ responseType, redirectOrigin: shop.origin })
      if (responseType.split(' ').includes('token')) {
        expect(implicitGrantFragmentOrigin(redirectUri as string)).toBe(shop.origin)
      }
    })
  }
})
