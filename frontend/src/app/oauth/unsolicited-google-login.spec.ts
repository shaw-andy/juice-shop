/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { ActivatedRoute, Router } from '@angular/router'
import { RouterTestingModule } from '@angular/router/testing'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'
import { ReactiveFormsModule } from '@angular/forms'
import { MatIconModule } from '@angular/material/icon'
import { MatCheckboxModule } from '@angular/material/checkbox'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatInputModule } from '@angular/material/input'
import { MatTooltipModule } from '@angular/material/tooltip'
import { MatTableModule } from '@angular/material/table'
import { MatPaginatorModule } from '@angular/material/paginator'
import { MatDialogModule } from '@angular/material/dialog'
import { MatDividerModule } from '@angular/material/divider'
import { MatGridListModule } from '@angular/material/grid-list'
import { CookieModule, CookieService } from 'ngy-cookie'
import { of } from 'rxjs'

import { OAuthComponent } from './oauth.component'
import { LoginComponent } from '../login/login.component'
import { SearchResultComponent } from '../search-result/search-result.component'
import { UserService } from '../Services/user.service'
import { PaymentService } from '../Services/payment.service'
import { BasketService } from '../Services/basket.service'
import { RequestInterceptor } from '../Services/request.interceptor'
import { WindowRefService } from '../Services/window-ref.service'
import { ConfigurationService } from '../Services/configuration.service'

const profileEmail = 'oauth-csrf-profile@example.test'
const shopSessionToken = 'shop-session-placeholder'
const shopBasketId = 77
const checkedAccessToken = 'placeholder-checked-token'
const swappedAccessToken = 'placeholder-swapped-token'
const unsolicitedAccessToken = 'placeholder-access-token'

interface GoogleLoginStart {
  state: string | null
  storedBeforeNavigation: boolean
}

interface CallbackEffects {
  profileAccessTokens: (string | null)[]
  registeredEmails: string[]
  loginRequests: number
  shopToken: string | null
  basketId: string | null
  cookieToken: string | null
  loggedIn: boolean
  cardAuthorization: string | null
  orderAuthorization: string | null
}

const noShopSession: CallbackEffects = {
  profileAccessTokens: [],
  registeredEmails: [],
  loginRequests: 0,
  shopToken: null,
  basketId: null,
  cookieToken: null,
  loggedIn: false,
  cardAuthorization: null,
  orderAuthorization: null
}

function clearBrowser (): void {
  localStorage.clear()
  sessionStorage.clear()
  document.cookie.split(';').forEach((part) => {
    const name = part.split('=')[0]?.trim()
    if (name) {
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`
    }
  })
}

function browserHolds (value: string): boolean {
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i)
    if (key != null && sessionStorage.getItem(key) === value) {
      return true
    }
  }
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i)
    if (key != null && localStorage.getItem(key) === value) {
      return true
    }
  }
  return document.cookie.split(';').some((part) => {
    const stored = part.split('=').slice(1).join('=').trim()
    return stored === value
  })
}

function fragmentData (values: string[]): { params: string } {
  let index = 0
  const data = {} as { params: string }
  Object.defineProperty(data, 'params', {
    configurable: true,
    get () {
      const value = values[Math.min(index, values.length - 1)]
      index += 1
      return value
    }
  })
  return data
}

function startGoogleLogin (): GoogleLoginStart {
  clearBrowser()
  TestBed.resetTestingModule()
  const windowRef = {
    nativeWindow: {
      location: {
        protocol: 'http:',
        host: 'localhost:3000',
        replace: (url: string) => {
          captured.state = new URL(url).searchParams.get('state')
          captured.storedBeforeNavigation = captured.state != null && browserHolds(captured.state)
        }
      }
    }
  }
  const captured: GoogleLoginStart = { state: null, storedBeforeNavigation: false }
  const userService = {
    login: vi.fn().mockReturnValue(of({})),
    isLoggedIn: { next: vi.fn() }
  }
  const configurationService = {
    getApplicationConfiguration: vi.fn().mockReturnValue(of({}))
  }
  const basketService = {
    mergeGuestBasketIntoUserBasket: vi.fn().mockReturnValue(of(undefined)),
    updateNumberOfCartItems: vi.fn()
  }

  TestBed.configureTestingModule({
    imports: [
      RouterTestingModule.withRoutes([
        { path: 'search', component: SearchResultComponent }
      ]),
      ReactiveFormsModule,
      CookieModule.forRoot(),
      TranslateModule.forRoot(),
      MatCheckboxModule,
      MatFormFieldModule,
      MatCardModule,
      MatIconModule,
      MatInputModule,
      MatTableModule,
      MatPaginatorModule,
      MatDialogModule,
      MatDividerModule,
      MatGridListModule,
      MatTooltipModule,
      LoginComponent,
      SearchResultComponent
    ],
    providers: [
      { provide: UserService, useValue: userService },
      { provide: ConfigurationService, useValue: configurationService },
      { provide: BasketService, useValue: basketService },
      { provide: WindowRefService, useValue: windowRef },
      CookieService,
      provideHttpClient(withInterceptorsFromDi()),
      provideHttpClientTesting()
    ]
  })

  const fixture = TestBed.createComponent(LoginComponent)
  fixture.detectChanges()
  fixture.componentInstance.googleLogin()
  fixture.destroy()
  return captured
}

function runCallback (fragments: string[], saveStatus: number): CallbackEffects {
  TestBed.resetTestingModule()
  let loggedIn = false
  TestBed.configureTestingModule({
    imports: [
      CookieModule.forRoot(),
      TranslateModule.forRoot(),
      MatCardModule,
      OAuthComponent
    ],
    providers: [
      UserService,
      PaymentService,
      BasketService,
      RequestInterceptor,
      { provide: HTTP_INTERCEPTORS, useExisting: RequestInterceptor, multi: true },
      { provide: ActivatedRoute, useValue: { snapshot: { data: fragmentData(fragments) } } },
      { provide: Router, useValue: { navigate: vi.fn().mockResolvedValue(true) } },
      provideHttpClient(withInterceptorsFromDi()),
      provideHttpClientTesting()
    ]
  })

  const userService = TestBed.inject(UserService)
  userService.isLoggedIn.subscribe((value) => {
    if (value === true) {
      loggedIn = true
    }
  })
  const httpMock = TestBed.inject(HttpTestingController)
  const cookieService = TestBed.inject(CookieService)
  const paymentService = TestBed.inject(PaymentService)
  const basketService = TestBed.inject(BasketService)
  const fixture: ComponentFixture<OAuthComponent> = TestBed.createComponent(OAuthComponent)
  fixture.detectChanges()

  const google = httpMock.match((req) => req.url.startsWith('https://www.googleapis.com/oauth2/v1/userinfo'))
  const profileAccessTokens = google.map((req) => new URL(req.request.url).searchParams.get('access_token'))
  for (const req of google) {
    req.flush({
      email: profileEmail,
      verified_email: true,
      id: 'placeholder-google-profile'
    })
  }

  const saves = httpMock.match((req) => req.method === 'POST' && req.url.includes('/api/Users'))
  const registeredEmails = saves.map((req) => String(req.request.body?.email ?? ''))
  for (const req of saves) {
    if (saveStatus >= 400) {
      req.flush({ message: 'account already exists' }, { status: saveStatus, statusText: 'Bad Request' })
    } else {
      req.flush({ data: { id: 50, email: profileEmail } })
    }
  }

  const logins = httpMock.match((req) => req.method === 'POST' && req.url.includes('/rest/user/login'))
  for (const req of logins) {
    req.flush({ authentication: { token: shopSessionToken, bid: shopBasketId } })
  }

  let cardAuthorization: string | null = null
  paymentService.save({
    fullName: 'Victim Shopper',
    cardNum: 1000000000000000,
    expMonth: 1,
    expYear: 2090
  }).subscribe({ error: () => undefined })
  const cards = httpMock.match((req) => req.method === 'POST' && req.url.includes('/api/Cards'))
  if (cards.length > 0) {
    cardAuthorization = cards[0].request.headers.get('Authorization')
    cards.forEach((req) => req.flush({ data: { id: 1 } }))
  }

  let orderAuthorization: string | null = null
  basketService.checkout(shopBasketId, '', {
    paymentId: '1',
    addressId: '1',
    deliveryMethodId: '1'
  }).subscribe({ error: () => undefined })
  const orders = httpMock.match((req) => req.method === 'POST' && req.url.includes('/checkout'))
  if (orders.length > 0) {
    orderAuthorization = orders[0].request.headers.get('Authorization')
    orders.forEach((req) => req.flush({ orderConfirmation: 'placeholder-order' }))
  }

  httpMock.verify()
  fixture.destroy()

  return {
    profileAccessTokens,
    registeredEmails,
    loginRequests: logins.length,
    shopToken: localStorage.getItem('token'),
    basketId: sessionStorage.getItem('bid'),
    cookieToken: cookieService.get('token') || null,
    loggedIn,
    cardAuthorization,
    orderAuthorization
  }
}

describe('Google sign-in session binding', () => {
  beforeEach(() => {
    clearBrowser()
  })

  afterEach(() => {
    clearBrowser()
    TestBed.resetTestingModule()
  })

  it('does not open a shop session from an access token the browser did not request', () => {
    const effects = runCallback([
      `#access_token=${unsolicitedAccessToken}&token_type=Bearer&expires_in=3600`
    ], 201)

    expect(effects).toEqual(noShopSession)
  })

  it('does not open a shop session when the fragment carries an attacker-chosen state', () => {
    const effects = runCallback([
      `#access_token=${unsolicitedAccessToken}&state=attacker-supplied-state&token_type=Bearer&expires_in=3600`
    ], 201)

    expect(effects).toEqual(noShopSession)
  })

  it('does not open a shop session when account creation fails for an unsolicited token', () => {
    const effects = runCallback([
      `#access_token=${unsolicitedAccessToken}&token_type=Bearer&expires_in=3600`
    ], 400)

    expect(effects).toEqual(noShopSession)
  })

  it('sends a fresh state when Google login starts and ignores a callback with a different state', () => {
    const started = startGoogleLogin()
    const callbackState = started.state == null ? 'attacker-supplied-state' : `${started.state}x`
    const effects = runCallback([
      `#access_token=${unsolicitedAccessToken}&state=${callbackState}&token_type=Bearer&expires_in=3600`
    ], 201)

    expect({
      state: started.state,
      storedBeforeNavigation: started.storedBeforeNavigation,
      ...effects
    }).toEqual({
      state: expect.stringMatching(/^[A-Za-z0-9_-]{16,}$/),
      storedBeforeNavigation: true,
      ...noShopSession
    })
  })

  it('opens a shop session only for the access token paired with the state this browser stored', () => {
    const started = startGoogleLogin()
    expect(started.state ?? '').toMatch(/^[A-Za-z0-9_-]{16,}$/)
    expect(started.storedBeforeNavigation).toBe(true)

    const authorized = `#access_token=${checkedAccessToken}&state=${started.state}&token_type=Bearer&expires_in=3600`
    const swapped = `#access_token=${swappedAccessToken}&state=${started.state}&token_type=Bearer&expires_in=3600`
    const effects = runCallback([authorized, swapped], 201)

    expect(effects.profileAccessTokens).toEqual([checkedAccessToken])
    expect(effects.registeredEmails).toEqual([profileEmail])
    expect(effects.loginRequests).toBe(1)
    expect(effects.shopToken).toBe(shopSessionToken)
    expect(effects.basketId).toBe(String(shopBasketId))
    expect(effects.cookieToken).toBe(shopSessionToken)
    expect(effects.loggedIn).toBe(true)
    expect(effects.cardAuthorization).toBe(`Bearer ${shopSessionToken}`)
    expect(effects.orderAuthorization).toBe(`Bearer ${shopSessionToken}`)
  })

  it('uses a different state for each Google login', () => {
    const first = startGoogleLogin()
    const second = startGoogleLogin()

    expect(first.state ?? '').toMatch(/^[A-Za-z0-9_-]{16,}$/)
    expect(second.state ?? '').toMatch(/^[A-Za-z0-9_-]{16,}$/)
    expect(first.state).not.toBe(second.state)
    expect(first.storedBeforeNavigation).toBe(true)
    expect(second.storedBeforeNavigation).toBe(true)
  })
})
