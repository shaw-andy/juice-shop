/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, type OnInit } from '@angular/core'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { Location } from '@angular/common'
import { Router, RouterOutlet } from '@angular/router'
import { CookieModule } from 'ngy-cookie'
import { TranslateModule } from '@ngx-translate/core'
import { Observable, of } from 'rxjs'
import { vi } from 'vitest'
import { Routing } from '../app.routing'
import { LoginComponent } from './login.component'
import { TrackResultComponent } from '../track-result/track-result.component'
import { UserService } from '../Services/user.service'
import { ConfigurationService } from '../Services/configuration.service'
import { BasketService } from '../Services/basket.service'
import { WindowRefService } from '../Services/window-ref.service'
import { SocketIoService } from '../Services/socket-io.service'
import { DeluxeGuard, LoginGuard } from '../app.guard'
import { MatSnackBarModule } from '@angular/material/snack-bar'

if (typeof globalThis.ResizeObserver === 'undefined') {
    globalThis.ResizeObserver = class ResizeObserver {
        observe () {}
        unobserve () {}
        disconnect () {}
    } as any
}

const sessionPlaceholder = 'placeholder-session'

function imageMarkup (marker: string) {
    return `<img src=x onerror=window.${marker}=1>`
}

@Component({
    selector: 'app-redirect-host',
    template: '<router-outlet></router-outlet>',
    imports: [RouterOutlet]
})
class RedirectHostComponent implements OnInit {
    ngOnInit () {}
}

describe('post-login redirectUrl', () => {
    let fixture: ComponentFixture<RedirectHostComponent>
    let router: Router
    let httpMock: HttpTestingController
    let userService: any
    let basketService: any
    let originBefore: string

    beforeEach(async () => {
        localStorage.clear()
        sessionStorage.clear()
        delete (window as any).__markupA
        delete (window as any).__markupB
        originBefore = window.location.origin

        userService = {
            login: vi.fn().mockReturnValue(of({ token: sessionPlaceholder, bid: 1 })),
            whoAmI: vi.fn().mockReturnValue(of({ email: 'customer@example.test' })),
            isLoggedIn: { next: vi.fn() }
        }
        basketService = {
            mergeGuestBasketIntoUserBasket: vi.fn().mockReturnValue(of(undefined)),
            updateNumberOfCartItems: vi.fn(),
            find: vi.fn().mockReturnValue(of({ Products: [] })),
            getGuestBasketItems: vi.fn().mockReturnValue([])
        }

        await TestBed.configureTestingModule({
            imports: [
                Routing,
                RedirectHostComponent,
                CookieModule.forRoot(),
                TranslateModule.forRoot(),
                MatSnackBarModule
            ],
            providers: [
                LoginGuard,
                DeluxeGuard,
                { provide: UserService, useValue: userService },
                {
                    provide: ConfigurationService,
                    useValue: { getApplicationConfiguration: () => of({}) }
                },
                { provide: BasketService, useValue: basketService },
                {
                    provide: WindowRefService,
                    useValue: {
                        nativeWindow: {
                            location: {
                                protocol: window.location.protocol,
                                host: window.location.host,
                                replace: vi.fn()
                            }
                        }
                    }
                },
                {
                    provide: SocketIoService,
                    useValue: { socket: () => ({ emit () {}, on () {} }) }
                },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        }).compileComponents()

        router = TestBed.inject(Router)
        httpMock = TestBed.inject(HttpTestingController)
        fixture = TestBed.createComponent(RedirectHostComponent)
        await settle()
    })

    afterEach(() => {
        httpMock.verify()
        localStorage.clear()
        sessionStorage.clear()
    })

    it('keeps an allow-listed search redirect and does not treat it as HTML', async () => {
        await signInWithRedirect('/search')

        expect(router.url).toBe('/search')
        expect(TestBed.inject(Location).prepareExternalUrl(router.url)).toBe('#/search')
        expect(window.location.origin).toBe(originBefore)
        expect(document.querySelector('#searchValue')).toBeNull()
        expect(localStorage.getItem('token')).toBe(sessionPlaceholder)
    })

    it('keeps an allow-listed basket redirect', async () => {
        await signInWithRedirect('/basket')

        expect(router.url).toBe('/basket')
        expect(TestBed.inject(Location).prepareExternalUrl(router.url)).toBe('#/basket')
        expect(window.location.origin).toBe(originBefore)
        expect(localStorage.getItem('token')).toBe(sessionPlaceholder)
    })

    it('does not open a search query as HTML after the session token is stored', async () => {
        const markup = imageMarkup('__markupA')
        await signInWithRedirect('/search?q=' + markup)

        expect(landing()).toEqual({
            url: '/search',
            external: '#/search',
            origin: originBefore,
            tokenStored: true,
            handlerHtml: null,
            marker: null
        })
    })

    it('does not open the catch-all route when its query is attacker-controlled HTML', async () => {
        const markup = imageMarkup('__markupA')
        await signInWithRedirect('/no-such-page?q=' + markup)

        expect(landing()).toEqual({
            url: '/search',
            external: '#/search',
            origin: originBefore,
            tokenStored: true,
            handlerHtml: null,
            marker: null
        })
    })

    it('does not open track-result when the id is attacker-controlled HTML', async () => {
        const markup = imageMarkup('__markupA')
        await signInWithRedirect('/track-result?id=' + markup)
        fixture.detectChanges()
        const trackEl = fixture.debugElement.query((node) => node.componentInstance instanceof TrackResultComponent)?.nativeElement as HTMLElement | undefined

        expect({
            ...landing(),
            orderHtml: trackEl?.innerHTML ?? null
        }).toEqual({
            url: '/search',
            external: '#/search',
            origin: originBefore,
            tokenStored: true,
            handlerHtml: null,
            marker: null,
            orderHtml: expect.not.stringContaining('onerror')
        })
    })

    it('does not follow a redirectUrl that uses a scheme', async () => {
        const markup = imageMarkup('__markupA')
        await signInWithRedirect('https://attacker.example/search?q=' + markup)

        expect(window.location.hostname).not.toBe('attacker.example')
        expect(landing().origin).toBe(originBefore)
        expect(landing().url).toBe('/search')
        expect(landing().handlerHtml).toBeNull()
    })

    it('does not follow a protocol-relative redirectUrl', async () => {
        const markup = imageMarkup('__markupA')
        await signInWithRedirect('//attacker.example/search?q=' + markup)

        expect(window.location.hostname).not.toBe('attacker.example')
        expect(landing().origin).toBe(originBefore)
        expect(landing().url).toBe('/search')
        expect(landing().handlerHtml).toBeNull()
    })

    it('does not follow a redirectUrl with a slash sequence into an HTML query', async () => {
        const markup = imageMarkup('__markupA')
        await signInWithRedirect('/search/../track-result?id=' + markup)

        expect(landing()).toEqual({
            url: '/search',
            external: '#/search',
            origin: originBefore,
            tokenStored: true,
            handlerHtml: null,
            marker: null
        })
    })

    it('still ignores redirectUrl when the query changes again before navigation', async () => {
        const first = '/search?q=' + imageMarkup('__markupA')
        const second = '/track-result?id=' + imageMarkup('__markupB')
        basketService.mergeGuestBasketIntoUserBasket.mockReturnValue(new Observable((subscriber) => {
            void router.navigateByUrl('/login?redirectUrl=' + encodeURIComponent(second)).then(() => {
                subscriber.next(undefined)
                subscriber.complete()
            })
        }))

        await signInWithRedirect(first)

        expect(landing()).toEqual({
            url: '/search',
            external: '#/search',
            origin: originBefore,
            tokenStored: true,
            handlerHtml: null,
            marker: null
        })
        expect(document.body.innerHTML).not.toContain('__markupA')
        expect(document.body.innerHTML).not.toContain('__markupB')
    })

    async function signInWithRedirect (redirectUrl: string) {
        const loginUrl = '/login?redirectUrl=' + encodeURIComponent(redirectUrl)
        await router.navigateByUrl(loginUrl)
        await settle()

        const login = fixture.debugElement.query((node) => node.componentInstance instanceof LoginComponent)?.componentInstance as LoginComponent
        expect(login).toBeTruthy()
        login.emailControl.setValue('customer@example.test')
        login.passwordControl.setValue('placeholder-password')
        login.login()
        await settle()
    }

    async function settle () {
        for (let i = 0; i < 8; i++) {
            fixture.detectChanges()
            await fixture.whenStable()
            const pending = httpMock.match(() => true)
            if (pending.length === 0) {
                continue
            }
            for (const req of pending) {
                respond(req)
            }
            fixture.detectChanges()
            await fixture.whenStable()
        }
    }

    function respond (req: ReturnType<HttpTestingController['match']>[number]) {
        const url = req.request.url
        if (url.includes('/rest/products/search') || url.includes('/api/Quantitys')) {
            req.flush({ data: [] })
            return
        }
        if (url.includes('/rest/track-order/')) {
            const encodedId = url.split('/rest/track-order/')[1]
            const id = decodeURIComponent(encodedId)
            req.flush({ status: 'success', data: [{ orderId: id }] })
            return
        }
        req.flush({})
    }

    function landing () {
        const handler = document.querySelector('#searchValue, h1')
        return {
            url: router.url,
            external: TestBed.inject(Location).prepareExternalUrl(router.url),
            origin: window.location.origin,
            tokenStored: localStorage.getItem('token') === sessionPlaceholder,
            handlerHtml: handler?.innerHTML ?? null,
            marker: (window as any).__markupA ?? (window as any).__markupB ?? null
        }
    }
})
