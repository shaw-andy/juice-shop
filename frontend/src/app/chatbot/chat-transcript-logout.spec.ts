/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component } from '@angular/core'
import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute } from '@angular/router'
import { HTTP_INTERCEPTORS, HttpEventType, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { MatMenuTrigger } from '@angular/material/menu'
import { RouterTestingModule } from '@angular/router/testing'
import { TranslateModule } from '@ngx-translate/core'
import { CookieModule, CookieService } from 'ngy-cookie'
import { EMPTY, Subject, of, throwError } from 'rxjs'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { LoginGuard } from '../app.guard'
import { NavbarComponent } from '../navbar/navbar.component'
import { SidenavComponent } from '../sidenav/sidenav.component'
import { LoginComponent } from '../login/login.component'
import { OAuthComponent } from '../oauth/oauth.component'
import { TwoFactorAuthEnterComponent } from '../two-factor-auth-enter/two-factor-auth-enter.component'
import { ServerStartedNotificationComponent } from '../server-started-notification/server-started-notification.component'
import { AdministrationService } from '../Services/administration.service'
import { BasketService } from '../Services/basket.service'
import { ChallengeService } from '../Services/challenge.service'
import { ConfigurationService } from '../Services/configuration.service'
import { LanguagesService } from '../Services/languages.service'
import { RequestInterceptor } from '../Services/request.interceptor'
import { SocketIoService } from '../Services/socket-io.service'
import { TwoFactorAuthService } from '../Services/two-factor-auth-service'
import { UserService } from '../Services/user.service'
import { ChatConversationComponent } from './chat-conversation/chat-conversation.component'
import { ChatWelcomePageComponent } from './chat-welcome-page/chat-welcome-page.component'
import { ChatWelcomeScreenComponent } from './chat-welcome-screen/chat-welcome-screen.component'

const STORAGE_KEY = 'juiceshop_chat_conversations'
const CONVERSATION_ID = 'conv-order'
const CHAT_URL = 'http://localhost:3000/rest/chat'
const USER_PHRASE = 'Where is my saved order?'
const BENIGN_REPLY = 'I can help with that.'
const ORDER_ID = 'abcd-0123456789abcdef'
const ITEM_NAME = 'Quince Juice'
const ITEM_TOTAL = '9.99'
const COUPON_CODE = 'coupon-placeholder'
const ACCOUNT_A = 'placeholder-token-account-a'
const ACCOUNT_B = 'placeholder-token-account-b'

@Component({ selector: 'app-blank', template: '', standalone: true })
class BlankComponent {}

function dataErasureTemplate (): string {
    const candidates = [
        resolve(process.cwd(), 'views/dataErasureResult.hbs'),
        resolve(process.cwd(), '../views/dataErasureResult.hbs')
    ]
    const found = candidates.find(path => existsSync(path))
    if (!found) {
        throw new Error('dataErasureResult.hbs not found from ' + process.cwd())
    }
    return readFileSync(found, 'utf8')
}

function serverEvent (delta: object): object {
    return { choices: [{ delta }] }
}

function toolCallEvent (): object {
    return serverEvent({
        tool_calls: [{
            id: 'call_ord',
            type: 'function',
            function: {
                name: 'getOrderById',
                arguments: JSON.stringify({ orderId: ORDER_ID })
            }
        }]
    })
}

function sseBody (events: object[]): string {
    return events.map(event => `data: ${JSON.stringify(event)}\n\n`).join('') + 'data: [DONE]\n\n'
}

describe('chat transcript survives the end of a session', () => {
    let httpMock: HttpTestingController
    let userService: any
    let twoFactorAuthService: any
    let configurationService: any

    beforeEach(async () => {
        localStorage.clear()
        sessionStorage.clear()
        vi.spyOn(console, 'log').mockImplementation(() => {})

        const loggedIn = new Subject<boolean>()
        userService = {
            whoAmI: vi.fn().mockReturnValue(of({ email: 'reader@example.test' })),
            getLoggedInState: vi.fn().mockReturnValue(loggedIn.asObservable()),
            saveLastLoginIp: vi.fn().mockReturnValue(of({})),
            login: vi.fn().mockReturnValue(of({ token: ACCOUNT_B, bid: 2 })),
            save: vi.fn().mockReturnValue(of({})),
            oauthLogin: vi.fn().mockReturnValue(EMPTY),
            isLoggedIn: loggedIn
        }
        twoFactorAuthService = {
            verify: vi.fn().mockReturnValue(of({ token: ACCOUNT_B, bid: 3 }))
        }
        configurationService = {
            getApplicationConfiguration: vi.fn().mockReturnValue(of({
                application: {
                    name: 'OWASP Juice Shop',
                    showGitHubLinks: true,
                    welcomeBanner: { showOnFirstStart: false },
                    chatBot: { name: 'Juicy', avatar: 'JuicyBot.png' }
                },
                hackingInstructor: { isEnabled: false }
            }))
        }
        const administrationService = {
            getApplicationVersion: vi.fn().mockReturnValue(of('1.0.0'))
        }
        const challengeService = {
            find: vi.fn().mockReturnValue(of([{ name: 'Score Board', solved: false }])),
            restoreProgress: vi.fn().mockReturnValue(of({})),
            restoreProgressFindIt: vi.fn().mockReturnValue(of({})),
            restoreProgressFixIt: vi.fn().mockReturnValue(of({}))
        }
        const languagesService = {
            getLanguages: vi.fn().mockReturnValue(of([{ key: 'en', lang: 'English', shortKey: 'EN' }]))
        }
        const basketService = {
            getItemTotal: vi.fn().mockReturnValue(of(0)),
            updateNumberOfCartItems: vi.fn(),
            mergeGuestBasketIntoUserBasket: vi.fn().mockReturnValue(of(undefined))
        }
        const socketIoService = {
            socket: vi.fn().mockReturnValue({ on () {} })
        }

        await TestBed.configureTestingModule({
            imports: [
                CookieModule.forRoot(),
                TranslateModule.forRoot(),
                RouterTestingModule.withRoutes([
                    { path: '', component: BlankComponent },
                    { path: 'search', component: BlankComponent },
                    { path: 'login', component: BlankComponent }
                ]),
                NavbarComponent,
                SidenavComponent,
                LoginComponent,
                OAuthComponent,
                TwoFactorAuthEnterComponent,
                ServerStartedNotificationComponent,
                ChatConversationComponent,
                ChatWelcomeScreenComponent,
                ChatWelcomePageComponent
            ],
            providers: [
                { provide: UserService, useValue: userService },
                { provide: TwoFactorAuthService, useValue: twoFactorAuthService },
                { provide: ConfigurationService, useValue: configurationService },
                { provide: AdministrationService, useValue: administrationService },
                { provide: ChallengeService, useValue: challengeService },
                { provide: LanguagesService, useValue: languagesService },
                { provide: BasketService, useValue: basketService },
                { provide: SocketIoService, useValue: socketIoService },
                {
                    provide: ActivatedRoute,
                    useValue: {
                        snapshot: {
                            params: { id: CONVERSATION_ID },
                            queryParams: {},
                            queryParamMap: { get: () => null },
                            data: { params: '' }
                        }
                    }
                },
                LoginGuard,
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: RequestInterceptor,
                    multi: true
                },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        }).compileComponents()

        httpMock = TestBed.inject(HttpTestingController)
        TestBed.inject(CookieService).put('language', 'en')
    })

    afterEach(() => {
        httpMock.verify()
        localStorage.clear()
        sessionStorage.clear()
        vi.restoreAllMocks()
    })

    async function persistTranscript (userText: string, assistantText: string, leadingEvents: object[] = []) {
        localStorage.setItem('token', ACCOUNT_A)
        const fixture = TestBed.createComponent(ChatConversationComponent)
        fixture.detectChanges()
        const sent = fixture.componentInstance.sendMessage(userText)
        const req = httpMock.expectOne(CHAT_URL)
        expect(req.request.headers.get('Authorization')).toBe('Bearer ' + localStorage.getItem('token'))
        const body = sseBody([
            ...leadingEvents,
            serverEvent({ content: assistantText }),
            { choices: [{ finish_reason: 'stop' }] }
        ])
        req.event({
            type: HttpEventType.DownloadProgress,
            loaded: body.length,
            total: body.length,
            partialText: body
        })
        req.flush('')
        await sent
        fixture.destroy()
    }

    function openSavedConversation (): string {
        const welcome = TestBed.createComponent(ChatWelcomePageComponent)
        welcome.detectChanges()
        TestBed.inject(CookieService).put('show_tool_calls', 'true')
        const conversation = TestBed.createComponent(ChatConversationComponent)
        conversation.detectChanges()
        const text = `${welcome.nativeElement.textContent ?? ''}\n${conversation.nativeElement.textContent ?? ''}`
        welcome.destroy()
        conversation.destroy()
        return text
    }

    function storedTranscript (): string {
        return localStorage.getItem(STORAGE_KEY) ?? ''
    }

    async function expectTranscriptCleared (endSession: () => void | Promise<void>) {
        await persistTranscript(USER_PHRASE, BENIGN_REPLY)
        expect(storedTranscript()).toContain(USER_PHRASE)
        expect(storedTranscript()).toContain(BENIGN_REPLY)
        await endSession()
        expect(storedTranscript()).not.toContain(USER_PHRASE)
        expect(storedTranscript()).not.toContain(BENIGN_REPLY)
        const visible = openSavedConversation()
        expect(visible).not.toContain(USER_PHRASE)
        expect(visible).not.toContain(BENIGN_REPLY)
    }

    it('stores the customer question but not order details or coupon text from the assistant reply', async () => {
        const reply = `Order ${ORDER_ID} includes ${ITEM_NAME} for a total of ${ITEM_TOTAL}. Coupon ${COUPON_CODE}.`
        await persistTranscript(USER_PHRASE, reply, [toolCallEvent()])

        const stored = storedTranscript()
        expect(stored).toContain(USER_PHRASE)
        expect(stored).not.toContain(ORDER_ID)
        expect(stored).not.toContain(ITEM_NAME)
        expect(stored).not.toContain(ITEM_TOTAL)
        expect(stored).not.toContain(COUPON_CODE)

        localStorage.removeItem('token')
        const visible = openSavedConversation()
        expect(visible).toContain(USER_PHRASE)
        expect(visible).not.toContain(ORDER_ID)
        expect(visible).not.toContain(ITEM_NAME)
        expect(visible).not.toContain(ITEM_TOTAL)
        expect(visible).not.toContain(COUPON_CODE)
    })

    it('navbar logout removes the saved transcript before the next visitor opens the chatbot', async () => {
        await expectTranscriptCleared(async () => {
            const fixture = TestBed.createComponent(NavbarComponent)
            fixture.detectChanges()
            const account = fixture.debugElement.query(By.css('#navbarAccount'))
            account.injector.get(MatMenuTrigger).openMenu()
            fixture.detectChanges()
            await fixture.whenStable()
            const logout = document.querySelector('#navbarLogoutButton') as HTMLButtonElement | null
            expect(logout).toBeTruthy()
            logout?.click()
            await fixture.whenStable()
            fixture.destroy()
        })
    })

    it('sidenav logout removes the saved transcript before the next visitor opens the chatbot', async () => {
        await expectTranscriptCleared(() => {
            const fixture = TestBed.createComponent(SidenavComponent)
            fixture.detectChanges()
            const logout = fixture.nativeElement.querySelector('a[aria-label="Logout"]') as HTMLAnchorElement
            expect(logout).toBeTruthy()
            logout.click()
            fixture.destroy()
        })
    })

    it('signing in as a different account removes the previous transcript', async () => {
        await expectTranscriptCleared(() => {
            userService.login.mockReturnValue(of({ token: ACCOUNT_B, bid: 2 }))
            const fixture = TestBed.createComponent(LoginComponent)
            fixture.detectChanges()
            fixture.componentInstance.emailControl.setValue('reader@example.test')
            fixture.componentInstance.passwordControl.setValue('placeholder-password')
            fixture.detectChanges()
            const form = fixture.nativeElement.querySelector('#login-form') as HTMLFormElement
            form.requestSubmit()
            expect(localStorage.getItem('token')).toBe(ACCOUNT_B)
            fixture.destroy()
        })
    })

    it('a failed login removes the saved transcript together with the session token', async () => {
        await expectTranscriptCleared(() => {
            userService.login.mockReturnValue(throwError(() => ({ error: 'Error' })))
            const fixture = TestBed.createComponent(LoginComponent)
            fixture.detectChanges()
            fixture.componentInstance.emailControl.setValue('reader@example.test')
            fixture.componentInstance.passwordControl.setValue('placeholder-password')
            fixture.detectChanges()
            const form = fixture.nativeElement.querySelector('#login-form') as HTMLFormElement
            form.requestSubmit()
            expect(localStorage.getItem('token')).toBeNull()
            fixture.destroy()
        })
    })

    it('oauth sign-in removes the previous transcript', async () => {
        await expectTranscriptCleared(() => {
            userService.oauthLogin.mockReturnValue(of({ email: 'reader@example.test' }))
            userService.login.mockReturnValue(of({ token: ACCOUNT_B, bid: 2 }))
            const fixture = TestBed.createComponent(OAuthComponent)
            fixture.detectChanges()
            expect(localStorage.getItem('token')).toBe(ACCOUNT_B)
            fixture.destroy()
        })
    })

    it('a failed oauth sign-in removes the saved transcript together with the session token', async () => {
        await expectTranscriptCleared(() => {
            userService.oauthLogin.mockReturnValue(throwError(() => new Error('placeholder')))
            const fixture = TestBed.createComponent(OAuthComponent)
            fixture.detectChanges()
            expect(localStorage.getItem('token')).toBeNull()
            fixture.destroy()
        })
    })

    it('two-factor sign-in removes the previous transcript', async () => {
        await expectTranscriptCleared(() => {
            const fixture = TestBed.createComponent(TwoFactorAuthEnterComponent)
            fixture.detectChanges()
            fixture.componentInstance.twoFactorForm.controls['token'].setValue('000000')
            fixture.detectChanges()
            const form = fixture.nativeElement.querySelector('form') as HTMLFormElement
            form.requestSubmit()
            expect(localStorage.getItem('token')).toBe(ACCOUNT_B)
            fixture.destroy()
        })
    })

    it('clearing hacking progress removes the saved transcript together with the session token', async () => {
        await expectTranscriptCleared(() => {
            const fixture = TestBed.createComponent(ServerStartedNotificationComponent)
            fixture.componentInstance.hackingProgress.autoRestoreMessage = 'restored'
            fixture.detectChanges()
            const button = fixture.nativeElement.querySelector('button[mat-stroked-button]') as HTMLButtonElement
            expect(button).toBeTruthy()
            button.click()
            expect(localStorage.getItem('token')).toBeNull()
            fixture.destroy()
        })
    })

    it('the data erasure result page removes the saved transcript together with the session token', async () => {
        await persistTranscript(USER_PHRASE, BENIGN_REPLY)
        expect(storedTranscript()).toContain(USER_PHRASE)
        const html = dataErasureTemplate()
        const match = html.match(/<script>([\s\S]*?)<\/script>/)
        expect(match).toBeTruthy()
        const script = document.createElement('script')
        script.textContent = match?.[1] ?? ''
        document.body.appendChild(script)
        script.remove()
        expect(localStorage.getItem('token')).toBeNull()
        expect(storedTranscript()).not.toContain(USER_PHRASE)
        expect(storedTranscript()).not.toContain(BENIGN_REPLY)
        const visible = openSavedConversation()
        expect(visible).not.toContain(USER_PHRASE)
    })
})
