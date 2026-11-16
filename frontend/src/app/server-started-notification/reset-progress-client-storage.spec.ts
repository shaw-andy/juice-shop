/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { EventEmitter } from '@angular/core'
import { HttpEventType, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { ActivatedRoute, Router } from '@angular/router'
import { RouterTestingModule } from '@angular/router/testing'
import { MatButtonModule } from '@angular/material/button'
import { MatCardModule } from '@angular/material/card'
import { MatIconModule } from '@angular/material/icon'
import { MatListModule } from '@angular/material/list'
import { MatMenuModule } from '@angular/material/menu'
import { MatSnackBarModule } from '@angular/material/snack-bar'
import { MatToolbarModule } from '@angular/material/toolbar'
import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { CookieModule, CookieService } from 'ngy-cookie'
import { of, Subject, throwError } from 'rxjs'
import { LoginGuard } from '../app.guard'
import { ChatConversationComponent } from '../chatbot/chat-conversation/chat-conversation.component'
import { ChatWelcomePageComponent } from '../chatbot/chat-welcome-page/chat-welcome-page.component'
import { LoginComponent } from '../login/login.component'
import { NavbarComponent } from '../navbar/navbar.component'
import { SidenavComponent } from '../sidenav/sidenav.component'
import { AdministrationService } from '../Services/administration.service'
import { BasketService } from '../Services/basket.service'
import { ChallengeService } from '../Services/challenge.service'
import { ConfigurationService } from '../Services/configuration.service'
import { LanguagesService } from '../Services/languages.service'
import { SocketIoService } from '../Services/socket-io.service'
import { UserService } from '../Services/user.service'
import { WindowRefService } from '../Services/window-ref.service'
import { TwoFactorAuthEnterComponent } from '../two-factor-auth-enter/two-factor-auth-enter.component'
import { TwoFactorAuthService } from '../Services/two-factor-auth-service'
import { ServerStartedNotificationComponent } from './server-started-notification.component'

const CHAT_STORAGE_KEY = 'juiceshop_chat_conversations'
const INTERIM_TOKEN_KEY = 'totp_tmp_token'
const CONVERSATION_ID = 'conversation-under-test'
const ORDER_QUESTION = 'Where is order order-1?'
const ORDER_REPLY = 'Packed order total 12.00 status shipped.'
const INTERIM_TOKEN = 'interim-token-placeholder'
const SESSION_TOKEN = 'session-token-placeholder'
const CONTINUE_CODE = 'continue-code-placeholder'
const AUTHENTICATOR_CODE = '000000'

class RecordingSocket {
  private handler: (() => void) | null = null

  on (_event: string, callback: () => void) {
    this.handler = callback
  }

  emitServerStarted () {
    this.handler?.()
  }
}

function orderReplySse (): string {
  const toolCall = {
    choices: [{
      delta: {
        tool_calls: [{
          id: 'tool-1',
          type: 'function',
          function: { name: 'getOrderById', arguments: JSON.stringify({ orderId: 'order-1' }) }
        }]
      }
    }]
  }
  const text = { choices: [{ delta: { content: ORDER_REPLY } }] }
  const finish = { choices: [{ finish_reason: 'stop' }] }
  return `data: ${JSON.stringify(toolCall)}\n\ndata: ${JSON.stringify(text)}\n\ndata: ${JSON.stringify(finish)}\n\ndata: [DONE]\n\n`
}

function emptyConfig () {
  return {
    getApplicationConfiguration: vi.fn().mockReturnValue(of({}))
  }
}

describe('client storage left behind after the session is dropped', () => {
  afterEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    TestBed.resetTestingModule()
  })

  async function persistSignedInOrderReply (): Promise<void> {
    TestBed.resetTestingModule()
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), CookieModule.forRoot(), RouterTestingModule, ChatConversationComponent],
      providers: [
        { provide: ConfigurationService, useValue: emptyConfig() },
        { provide: UserService, useValue: { whoAmI: vi.fn() } },
        LoginGuard,
        CookieService,
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              params: { id: CONVERSATION_ID },
              queryParams: {}
            }
          }
        },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    const fixture = TestBed.createComponent(ChatConversationComponent)
    fixture.detectChanges()
    const pending = fixture.componentInstance.sendMessage(ORDER_QUESTION)
    const httpMock = TestBed.inject(HttpTestingController)
    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    const body = orderReplySse()
    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: body.length,
      total: body.length,
      partialText: body
    })
    req.flush(body)
    await pending
    fixture.destroy()
  }

  async function storeInterimTokenViaLogin (): Promise<void> {
    TestBed.resetTestingModule()
    const userService = {
      login: vi.fn().mockReturnValue(throwError(() => ({
        error: {
          status: 'totp_token_required',
          data: { tmpToken: INTERIM_TOKEN }
        }
      }))),
      isLoggedIn: { next: vi.fn() }
    }
    const basketService = {
      mergeGuestBasketIntoUserBasket: vi.fn().mockReturnValue(of(undefined)),
      updateNumberOfCartItems: vi.fn()
    }
    const windowRefService = {
      nativeWindow: {
        location: {
          protocol: 'http:',
          host: 'localhost:4200',
          replace: vi.fn()
        }
      }
    }

    await TestBed.configureTestingModule({
      imports: [RouterTestingModule, CookieModule.forRoot(), TranslateModule.forRoot(), LoginComponent],
      providers: [
        { provide: UserService, useValue: userService },
        { provide: ConfigurationService, useValue: emptyConfig() },
        { provide: BasketService, useValue: basketService },
        { provide: WindowRefService, useValue: windowRefService },
        CookieService,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    const fixture = TestBed.createComponent(LoginComponent)
    fixture.detectChanges()
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true)
    fixture.componentInstance.emailControl.setValue('customer@example.test')
    fixture.componentInstance.passwordControl.setValue('placeholder-password')
    fixture.componentInstance.login()
    await fixture.whenStable()
    fixture.destroy()
  }

  function seedSessionArtifacts (): void {
    localStorage.setItem('token', SESSION_TOKEN)
    const cookieService = TestBed.inject(CookieService)
    cookieService.put('token', SESSION_TOKEN)
    cookieService.put('continueCode', CONTINUE_CODE)
  }

  async function openChatAndReadOrderReply (): Promise<string> {
    TestBed.resetTestingModule()
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), RouterTestingModule, ChatWelcomePageComponent],
      providers: [
        { provide: ConfigurationService, useValue: emptyConfig() }
      ]
    }).compileComponents()

    const welcome = TestBed.createComponent(ChatWelcomePageComponent)
    welcome.detectChanges()
    const welcomeText = welcome.nativeElement.textContent as string
    welcome.destroy()

    TestBed.resetTestingModule()
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), CookieModule.forRoot(), RouterTestingModule, ChatConversationComponent],
      providers: [
        { provide: ConfigurationService, useValue: emptyConfig() },
        { provide: UserService, useValue: { whoAmI: vi.fn() } },
        LoginGuard,
        CookieService,
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              params: { id: CONVERSATION_ID },
              queryParams: {}
            }
          }
        },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    const conversation = TestBed.createComponent(ChatConversationComponent)
    conversation.detectChanges()
    const conversationText = conversation.nativeElement.textContent as string
    conversation.destroy()
    return welcomeText + conversationText
  }

  async function submitAuthenticatorCode (): Promise<{ tmpToken: string | null, totpToken: string }> {
    TestBed.resetTestingModule()
    await TestBed.configureTestingModule({
      imports: [RouterTestingModule, CookieModule.forRoot(), TranslateModule.forRoot(), TwoFactorAuthEnterComponent],
      providers: [
        TwoFactorAuthService,
        { provide: UserService, useValue: { isLoggedIn: { next: vi.fn() } } },
        CookieService,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    const fixture = TestBed.createComponent(TwoFactorAuthEnterComponent)
    fixture.detectChanges()
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true)
    fixture.componentInstance.twoFactorForm.setValue({ token: AUTHENTICATOR_CODE })
    fixture.componentInstance.verify()
    const httpMock = TestBed.inject(HttpTestingController)
    const req = httpMock.expectOne('http://localhost:3000/rest/2fa/verify')
    const body = req.request.body as { tmpToken: string | null, totpToken: string }
    req.flush('unauthorized', { status: 401, statusText: 'Unauthorized' })
    httpMock.verify()
    fixture.destroy()
    return body
  }

  async function clickResetProgress (): Promise<ComponentFixture<ServerStartedNotificationComponent>> {
    TestBed.resetTestingModule()
    const socket = new RecordingSocket()
    const challengeService = {
      restoreProgress: vi.fn().mockReturnValue(of({})),
      restoreProgressFindIt: vi.fn().mockReturnValue(of({})),
      restoreProgressFixIt: vi.fn().mockReturnValue(of({}))
    }
    const translateService = {
      get: vi.fn().mockReturnValue(of('Progress restored')),
      onLangChange: new EventEmitter(),
      onTranslationChange: new EventEmitter(),
      onFallbackLangChange: new EventEmitter(),
      onDefaultLangChange: new EventEmitter()
    }

    await TestBed.configureTestingModule({
      imports: [
        TranslateModule.forRoot(),
        CookieModule.forRoot(),
        MatCardModule,
        MatButtonModule,
        MatIconModule,
        ServerStartedNotificationComponent
      ],
      providers: [
        { provide: ChallengeService, useValue: challengeService },
        { provide: TranslateService, useValue: translateService },
        { provide: SocketIoService, useValue: { socket: () => socket } },
        CookieService,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    seedSessionArtifacts()
    const fixture = TestBed.createComponent(ServerStartedNotificationComponent)
    fixture.detectChanges()
    socket.emitServerStarted()
    fixture.detectChanges()

    const resetButton = fixture.nativeElement.querySelector('button[mat-stroked-button]') as HTMLButtonElement
    expect(resetButton).toBeTruthy()
    expect(resetButton.disabled).toBe(false)
    resetButton.click()
    fixture.detectChanges()
    return fixture
  }

  it('clears the chatbot transcript and the pre-two-factor token when the reset-progress button is clicked', async () => {
    await persistSignedInOrderReply()
    await storeInterimTokenViaLogin()

    const savedTranscript = localStorage.getItem(CHAT_STORAGE_KEY)
    expect(savedTranscript).toContain(ORDER_REPLY)
    expect(savedTranscript).toContain('getOrderById')
    expect(localStorage.getItem(INTERIM_TOKEN_KEY)).toBe(INTERIM_TOKEN)

    const transcriptBeforeReset = await openChatAndReadOrderReply()
    expect(transcriptBeforeReset).toContain(ORDER_QUESTION)
    expect(transcriptBeforeReset).toContain(ORDER_REPLY)

    const verifyBeforeReset = await submitAuthenticatorCode()
    expect(verifyBeforeReset).toEqual({ tmpToken: INTERIM_TOKEN, totpToken: AUTHENTICATOR_CODE })

    const fixture = await clickResetProgress()
    const cookieService = TestBed.inject(CookieService)
    expect(localStorage.getItem('token')).toBeNull()
    expect(cookieService.get('token')).toBeUndefined()
    expect(cookieService.get('continueCode')).toBeUndefined()
    expect(fixture.componentInstance.hackingProgress.cleared).toBe(true)
    fixture.destroy()

    expect({
      chat: localStorage.getItem(CHAT_STORAGE_KEY),
      interim: localStorage.getItem(INTERIM_TOKEN_KEY)
    }).toEqual({ chat: null, interim: null })

    const transcriptAfterReset = await openChatAndReadOrderReply()
    expect(transcriptAfterReset).not.toContain(ORDER_QUESTION)
    expect(transcriptAfterReset).not.toContain(ORDER_REPLY)

    const verifyAfterReset = await submitAuthenticatorCode()
    expect(verifyAfterReset).toEqual({ tmpToken: null, totpToken: AUTHENTICATOR_CODE })
  })

  async function mountNavbar (): Promise<ComponentFixture<NavbarComponent>> {
    TestBed.resetTestingModule()
    const userService = {
      whoAmI: vi.fn().mockReturnValue(of({ email: 'customer@example.test' })),
      getLoggedInState: vi.fn().mockReturnValue(of(true)),
      saveLastLoginIp: vi.fn().mockReturnValue(of({})),
      isLoggedIn: { next: vi.fn() }
    }
    const itemTotal = new Subject<number>()
    await TestBed.configureTestingModule({
      imports: [
        RouterTestingModule,
        CookieModule.forRoot(),
        TranslateModule.forRoot(),
        MatToolbarModule,
        MatMenuModule,
        MatSnackBarModule,
        NavbarComponent
      ],
      providers: [
        { provide: AdministrationService, useValue: { getApplicationVersion: vi.fn().mockReturnValue(of(undefined)) } },
        { provide: ConfigurationService, useValue: emptyConfig() },
        { provide: UserService, useValue: userService },
        { provide: ChallengeService, useValue: { find: vi.fn().mockReturnValue(of([{ solved: false }])) } },
        { provide: SocketIoService, useValue: { socket: () => ({ on: () => undefined }) } },
        { provide: LoginGuard, useValue: { tokenDecode: vi.fn().mockReturnValue(null) } },
        { provide: LanguagesService, useValue: { getLanguages: vi.fn().mockReturnValue(of([{ key: 'en', lang: 'English', shortKey: 'EN' }])) } },
        {
          provide: BasketService,
          useValue: {
            getItemTotal: vi.fn().mockReturnValue(itemTotal.asObservable()),
            updateNumberOfCartItems: vi.fn()
          }
        },
        {
          provide: WindowRefService,
          useValue: { nativeWindow: { location: { reload: vi.fn() } } }
        },
        CookieService,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    const cookieService = TestBed.inject(CookieService)
    cookieService.put('language', 'en')
    cookieService.put('token', SESSION_TOKEN)
    const fixture = TestBed.createComponent(NavbarComponent)
    fixture.detectChanges()
    return fixture
  }

  async function mountSidenav (): Promise<ComponentFixture<SidenavComponent>> {
    TestBed.resetTestingModule()
    const userService = {
      whoAmI: vi.fn().mockReturnValue(of({ email: 'customer@example.test' })),
      getLoggedInState: vi.fn().mockReturnValue(of(true)),
      saveLastLoginIp: vi.fn().mockReturnValue(of({})),
      isLoggedIn: { next: vi.fn() }
    }
    await TestBed.configureTestingModule({
      imports: [
        RouterTestingModule,
        CookieModule.forRoot(),
        TranslateModule.forRoot(),
        MatToolbarModule,
        MatListModule,
        SidenavComponent
      ],
      providers: [
        { provide: AdministrationService, useValue: { getApplicationVersion: vi.fn().mockReturnValue(of(undefined)) } },
        { provide: ConfigurationService, useValue: emptyConfig() },
        { provide: UserService, useValue: userService },
        { provide: ChallengeService, useValue: { find: vi.fn().mockReturnValue(of([{ solved: false }])) } },
        { provide: SocketIoService, useValue: { socket: () => ({ on: () => undefined }) } },
        { provide: LoginGuard, useValue: { tokenDecode: vi.fn().mockReturnValue(null) } },
        CookieService,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    const cookieService = TestBed.inject(CookieService)
    cookieService.put('token', SESSION_TOKEN)
    const fixture = TestBed.createComponent(SidenavComponent)
    fixture.detectChanges()
    return fixture
  }

  it('clears the chatbot transcript and the pre-two-factor token when the navbar logout button handler runs', async () => {
    await persistSignedInOrderReply()
    await storeInterimTokenViaLogin()
    localStorage.setItem('token', SESSION_TOKEN)
    expect(localStorage.getItem(CHAT_STORAGE_KEY)).toContain(ORDER_REPLY)
    expect(localStorage.getItem(INTERIM_TOKEN_KEY)).toBe(INTERIM_TOKEN)

    const fixture = await mountNavbar()
    fixture.componentInstance.logout()
    fixture.detectChanges()

    expect(localStorage.getItem('token')).toBeNull()
    expect({
      chat: localStorage.getItem(CHAT_STORAGE_KEY),
      interim: localStorage.getItem(INTERIM_TOKEN_KEY)
    }).toEqual({ chat: null, interim: null })
    fixture.destroy()
  })

  it('clears the chatbot transcript and the pre-two-factor token when the sidenav logout control runs', async () => {
    await persistSignedInOrderReply()
    await storeInterimTokenViaLogin()
    localStorage.setItem('token', SESSION_TOKEN)
    expect(localStorage.getItem(CHAT_STORAGE_KEY)).toContain(ORDER_REPLY)
    expect(localStorage.getItem(INTERIM_TOKEN_KEY)).toBe(INTERIM_TOKEN)

    const fixture = await mountSidenav()
    const logout = fixture.nativeElement.querySelector('[aria-label="Logout"]') as HTMLElement
    expect(logout).toBeTruthy()
    logout.click()
    fixture.detectChanges()

    expect(localStorage.getItem('token')).toBeNull()
    expect({
      chat: localStorage.getItem(CHAT_STORAGE_KEY),
      interim: localStorage.getItem(INTERIM_TOKEN_KEY)
    }).toEqual({ chat: null, interim: null })
    fixture.destroy()
  })
})
