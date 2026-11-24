/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { RouterTestingModule } from '@angular/router/testing'
import { CookieModule, CookieService } from 'ngy-cookie'
import { of } from 'rxjs'
import { MatSnackBar } from '@angular/material/snack-bar'
import { SidenavComponent } from './sidenav/sidenav.component'
import { NavbarComponent } from './navbar/navbar.component'
import { UserService } from './Services/user.service'
import { RequestInterceptor } from './Services/request.interceptor'
import { AdministrationService } from './Services/administration.service'
import { ChallengeService } from './Services/challenge.service'
import { ConfigurationService } from './Services/configuration.service'
import { SocketIoService } from './Services/socket-io.service'
import { LoginGuard } from './app.guard'
import { LanguagesService } from './Services/languages.service'
import { BasketService } from './Services/basket.service'
import { WindowRefService } from './Services/window-ref.service'
import { MatToolbarModule } from '@angular/material/toolbar'
import { MatIconModule } from '@angular/material/icon'
import { MatButtonModule } from '@angular/material/button'
import { MatMenuModule } from '@angular/material/menu'
import { MatListModule } from '@angular/material/list'
import { MatTooltipModule } from '@angular/material/tooltip'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatInputModule } from '@angular/material/input'
import { MatRadioModule } from '@angular/material/radio'
import { MatDividerModule } from '@angular/material/divider'
import { MatSearchBarComponent } from './mat-search-bar/mat-search-bar.component'

const placeholderToken = 'placeholder-token'

describe('logout revocation', () => {
  afterEach(() => {
    localStorage.removeItem('token')
    sessionStorage.clear()
  })

  it('side menu logout posts the session token before clearing it', async () => {
    const http = await mount(SidenavComponent, sidenavImports())
    await expectLogoutPostsTokenBeforeClearing(http, () => TestBed.createComponent(SidenavComponent))
  })

  it('top bar logout posts the session token before clearing it', async () => {
    const http = await mount(NavbarComponent, navbarImports())
    await expectLogoutPostsTokenBeforeClearing(http, () => TestBed.createComponent(NavbarComponent))
  })
})

async function mount (component: unknown, imports: unknown[]) {
  localStorage.setItem('token', placeholderToken)
  TestBed.resetTestingModule()
  await TestBed.configureTestingModule({
    imports: [
      TranslateModule.forRoot(),
      CookieModule.forRoot(),
      RouterTestingModule,
      ...imports,
      component
    ],
    providers: [
      UserService,
      TranslateService,
      { provide: AdministrationService, useValue: { getApplicationVersion: () => of(null) } },
      { provide: ChallengeService, useValue: { find: () => of([{ name: 'Score Board', solved: false }]) } },
      { provide: ConfigurationService, useValue: { getApplicationConfiguration: () => of({ application: { welcomeBanner: {} }, hackingInstructor: {} }) } },
      { provide: SocketIoService, useValue: { socket: () => ({ on: () => undefined }) } },
      { provide: LoginGuard, useValue: { tokenDecode: () => ({}) } },
      { provide: LanguagesService, useValue: { getLanguages: () => of([{ key: 'en', shortKey: 'EN', lang: 'English' }]) } },
      { provide: BasketService, useValue: { getItemTotal: () => of(0), updateNumberOfCartItems: () => undefined } },
      { provide: WindowRefService, useValue: { nativeWindow: { location: { reload: () => undefined } } } },
      { provide: CookieService, useValue: { get: () => 'en', remove: vi.fn(), put: vi.fn() } },
      { provide: MatSnackBar, useValue: { open: () => ({ onAction: () => of(undefined) }) } },
      { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true },
      provideHttpClient(withInterceptorsFromDi()),
      provideHttpClientTesting()
    ]
  }).compileComponents()
  return TestBed.inject(HttpTestingController)
}

function sidenavImports () {
  return [MatToolbarModule, MatIconModule, MatButtonModule, MatMenuModule, MatListModule]
}

function navbarImports () {
  return [MatToolbarModule, MatIconModule, MatButtonModule, MatMenuModule, MatTooltipModule, MatFormFieldModule, MatInputModule, MatRadioModule, MatDividerModule, MatSearchBarComponent]
}

function flushStartup (http: HttpTestingController) {
  for (const pending of http.match((candidate) => !candidate.url.includes('/rest/user/logout'))) {
    pending.flush({ user: {} })
  }
}

async function expectLogoutPostsTokenBeforeClearing (http: HttpTestingController, create: () => { detectChanges: () => void, whenStable: () => Promise<unknown>, componentInstance: { logout: () => void } }) {
  const fixture = create()
  fixture.detectChanges()
  flushStartup(http)
  fixture.componentInstance.logout()
  const posted = http.match((candidate) => candidate.url.includes('/rest/user/logout') && candidate.method === 'POST')
  expect(posted.length).toBe(1)
  expect(posted[0].request.headers.get('Authorization')).toBe('Bearer ' + placeholderToken)
  posted[0].flush({ status: 'success' })
  flushStartup(http)
  await fixture.whenStable()
  expect(localStorage.getItem('token')).toBeNull()
  http.verify()
}
