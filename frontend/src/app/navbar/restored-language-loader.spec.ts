/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { firstValueFrom, Subject } from 'rxjs'
import { CookieModule, CookieService } from 'ngy-cookie'
import { provideTranslateService, TranslateModule } from '@ngx-translate/core'
import { provideTranslateHttpLoader } from '@ngx-translate/http-loader'
import { MatSnackBar } from '@angular/material/snack-bar'
import { RouterTestingModule } from '@angular/router/testing'
import { MatToolbarModule } from '@angular/material/toolbar'
import { MatIconModule } from '@angular/material/icon'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatSelectModule } from '@angular/material/select'
import { MatButtonModule } from '@angular/material/button'
import { MatMenuModule } from '@angular/material/menu'
import { MatTooltipModule } from '@angular/material/tooltip'
import { MatCardModule } from '@angular/material/card'
import { MatInputModule } from '@angular/material/input'
import { MatTableModule } from '@angular/material/table'
import { MatPaginatorModule } from '@angular/material/paginator'
import { MatDialogModule } from '@angular/material/dialog'
import { MatDividerModule } from '@angular/material/divider'
import { MatGridListModule } from '@angular/material/grid-list'
import { MatRadioModule } from '@angular/material/radio'
import { NavbarComponent } from './navbar.component'
import { SearchResultComponent } from '../search-result/search-result.component'
import { MatSearchBarComponent } from '../mat-search-bar/mat-search-bar.component'
import { ScoreBoardAdditionalSettingsDialogComponent } from '../score-board/components/filter-settings/components/score-board-additional-settings-dialog/score-board-additional-settings-dialog.component'
import { LocalBackupService } from '../Services/local-backup.service'
import { RequestInterceptor } from '../Services/request.interceptor'
import { LanguagesService } from '../Services/languages.service'
import { AdministrationService } from '../Services/administration.service'
import { ConfigurationService } from '../Services/configuration.service'
import { UserService } from '../Services/user.service'
import { ChallengeService } from '../Services/challenge.service'
import { SocketIoService } from '../Services/socket-io.service'
import { LoginGuard } from '../app.guard'
import { BasketService } from '../Services/basket.service'
import { WindowRefService } from '../Services/window-ref.service'
import { of } from 'rxjs'

const locales = [
  { key: 'en', lang: 'English', shortKey: 'EN' },
  { key: 'de', lang: 'German', shortKey: 'DE' }
]

const passwordLanguage = '../../rest/user/change-password?new=placeholder-chosen&repeat=placeholder-chosen#'
const loginIpLanguage = '../../rest/saveLoginIp#'
const localeFile = /^\/assets\/i18n\/[A-Za-z0-9_-]+\.json$/

describe('restored language loader', () => {
  let fixture: ComponentFixture<NavbarComponent>
  let dialogFixture: ComponentFixture<ScoreBoardAdditionalSettingsDialogComponent>
  let httpMock: HttpTestingController
  let cookieService: CookieService

  beforeEach(async () => {
    localStorage.setItem('token', 'placeholder-token')
    await TestBed.configureTestingModule({
      imports: [
        RouterTestingModule.withRoutes([
          { path: 'search', component: SearchResultComponent }
        ]),
        CookieModule.forRoot(),
        TranslateModule.forRoot(),
        MatToolbarModule,
        MatIconModule,
        MatFormFieldModule,
        MatSelectModule,
        MatButtonModule,
        MatMenuModule,
        MatTooltipModule,
        MatCardModule,
        MatInputModule,
        MatTableModule,
        MatPaginatorModule,
        MatDialogModule,
        MatDividerModule,
        MatGridListModule,
        MatRadioModule,
        NavbarComponent,
        SearchResultComponent,
        MatSearchBarComponent,
        ScoreBoardAdditionalSettingsDialogComponent
      ],
      providers: [
        provideTranslateService({
          loader: provideTranslateHttpLoader({
            prefix: '/assets/i18n/',
            suffix: '.json'
          }),
          fallbackLang: 'en'
        }),
        {
          provide: HTTP_INTERCEPTORS,
          useClass: RequestInterceptor,
          multi: true
        },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: AdministrationService, useValue: { getApplicationVersion: () => of(undefined) } },
        { provide: ConfigurationService, useValue: { getApplicationConfiguration: () => of({}) } },
        {
          provide: UserService,
          useValue: {
            whoAmI: () => of({}),
            getLoggedInState: () => of(false),
            saveLastLoginIp: () => of({}),
            isLoggedIn: { next: () => undefined }
          }
        },
        {
          provide: ChallengeService,
          useValue: {
            find: () => of([{ solved: false }]),
            continueCode: () => of(''),
            continueCodeFindIt: () => of(''),
            continueCodeFixIt: () => of(''),
            restoreProgress: () => of(true),
            restoreProgressFindIt: () => of(true),
            restoreProgressFixIt: () => of(true)
          }
        },
        { provide: SocketIoService, useValue: { socket: () => ({ on: () => undefined }) } },
        { provide: LoginGuard, useValue: { tokenDecode: () => undefined } },
        { provide: LanguagesService, useValue: { getLanguages: () => of(locales) } },
        {
          provide: BasketService,
          useValue: {
            getItemTotal: () => of(0),
            updateNumberOfCartItems: () => undefined
          }
        },
        {
          provide: WindowRefService,
          useValue: { nativeWindow: { location: { reload: () => undefined } } }
        },
        {
          provide: MatSnackBar,
          useValue: { open: () => ({ onAction: () => new Subject() }) }
        }
      ]
    }).compileComponents()

    cookieService = TestBed.inject(CookieService)
    cookieService.remove('language')
    httpMock = TestBed.inject(HttpTestingController)
    dialogFixture = TestBed.createComponent(ScoreBoardAdditionalSettingsDialogComponent)
    dialogFixture.detectChanges()
    fixture = TestBed.createComponent(NavbarComponent)
  })

  afterEach(() => {
    for (const pending of httpMock.match(() => true)) {
      pending.flush({})
    }
    httpMock.verify()
    localStorage.removeItem('token')
    cookieService.remove('language')
  })

  it('loads a listed backup language as that locale file', async () => {
    await restoreBackup({ version: 1, language: 'de' })

    activateNavbar()

    const requests = captureRequests()
    expect(requests.map((request) => request.url)).toContain('/assets/i18n/de.json')
    expect(requests.filter((request) => !isLocaleFile(request.url))).toEqual([])
    expect(cookieService.get('language')).toBe('de')
  })

  it('does not request a password-change URL stored as the backup language', async () => {
    await restoreBackup({ version: 1, language: passwordLanguage })

    activateNavbar()

    expect(outsideLocale(captureRequests())).toEqual([])
    expect(cookieService.get('language') ?? '').not.toContain('change-password')
  })

  it('does not request a login-ip URL stored as the backup language', async () => {
    await restoreBackup({ version: 1, language: loginIpLanguage })

    activateNavbar()

    expect(outsideLocale(captureRequests())).toEqual([])
    expect(cookieService.get('language') ?? '').not.toContain('saveLoginIp')
  })

  it('does not load a language cookie that leaves the locale directory', () => {
    cookieService.put('language', passwordLanguage)

    activateNavbar()

    expect(outsideLocale(captureRequests())).toEqual([])
  })

  it('does not load an arbitrary value passed to the language handler', () => {
    fixture.componentInstance.languages = locales
    fixture.componentInstance.changeLanguage(passwordLanguage)

    expect(outsideLocale(captureRequests())).toEqual([])
    expect(cookieService.get('language') ?? '').not.toContain('change-password')
  })

  async function restoreBackup (backup: object): Promise<void> {
    const service = TestBed.inject(LocalBackupService)
    const input = dialogFixture.nativeElement.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File([JSON.stringify(backup)], 'backup.json', { type: 'application/json' })
    Object.defineProperty(input, 'files', {
      configurable: true,
      value: {
        0: file,
        length: 1,
        item: (index: number) => index === 0 ? file : null
      }
    })
    let restored = Promise.resolve()
    const original = service.restore.bind(service)
    vi.spyOn(service, 'restore').mockImplementation((backupFile: File) => {
      const result = original(backupFile)
      restored = firstValueFrom(result).then(() => undefined)
      return result
    })
    input.dispatchEvent(new Event('change'))
    await restored
  }

  function activateNavbar (): void {
    try {
      fixture.detectChanges()
    } catch {
      // An unlisted language cookie has no short label. The translation request is already queued.
    }
  }

  function captureRequests (): Array<{ method: string, url: string, authorization: string | null }> {
    return httpMock.match(() => true).map((pending) => {
      const recorded = {
        method: pending.request.method,
        url: pending.request.urlWithParams,
        authorization: pending.request.headers.get('Authorization')
      }
      pending.flush({})
      return recorded
    })
  }
})

function isLocaleFile (url: string): boolean {
  const path = url.split('?')[0].split('#')[0]
  return localeFile.test(path)
}

function outsideLocale (requests: Array<{ method: string, url: string, authorization: string | null }>): Array<{ method: string, url: string, authorization: string | null }> {
  return requests.filter((request) => !isLocaleFile(request.url))
}
