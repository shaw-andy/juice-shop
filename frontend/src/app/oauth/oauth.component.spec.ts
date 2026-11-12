/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { MatIconModule } from '@angular/material/icon'
import { MatCheckboxModule } from '@angular/material/checkbox'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'
import { MatInputModule } from '@angular/material/input'

import { provideHttpClientTesting } from '@angular/common/http/testing'
import { RouterTestingModule } from '@angular/router/testing'

import { OAuthComponent } from './oauth.component'
import { LoginComponent } from '../login/login.component'
import { ReactiveFormsModule } from '@angular/forms'
import { ActivatedRoute } from '@angular/router'
import { MatTooltipModule } from '@angular/material/tooltip'
import { of, throwError } from 'rxjs'
import { UserService } from '../Services/user.service'
import { CookieModule } from 'ngy-cookie'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('OAuthComponent', () => {
    let component: OAuthComponent
    let fixture: ComponentFixture<OAuthComponent>
    let userService: any

    beforeEach(async () => {
        userService = {
            oauthLogin: vi.fn().mockName("UserService.oauthLogin"),
            login: vi.fn().mockName("UserService.login"),
            save: vi.fn().mockName("UserService.save")
        }
        userService.oauthLogin.mockReturnValue(of({ email: '' }))
        userService.login.mockReturnValue(of({}))
        userService.save.mockReturnValue(of({}))
        userService.isLoggedIn = {
            next: vi.fn().mockName("userService.isLoggedIn.next")
        }
        userService.isLoggedIn.next.mockReturnValue({})

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: 'login', component: LoginComponent }
                ]),
                ReactiveFormsModule,
                CookieModule.forRoot(),
                TranslateModule.forRoot(),
                MatInputModule,
                MatIconModule,
                MatCardModule,
                MatFormFieldModule,
                MatCheckboxModule,
                MatTooltipModule,
                OAuthComponent, LoginComponent],
            providers: [
                { provide: ActivatedRoute, useValue: { snapshot: { data: { params: '?alt=json&access_token=TEST' } } } },
                { provide: UserService, useValue: userService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(OAuthComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('removes authentication token and basket id on failed OAuth login attempt', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.oauthLogin.mockReturnValue(throwError({ error: 'Error' }))
        component.ngOnInit()
        expect(localStorage.getItem('token')).toBeNull()
        expect(sessionStorage.getItem('bid')).toBeNull()
    })

    it('will create regular user account with base64 encoded reversed email as password', () => {
        userService.oauthLogin.mockReturnValue(of({ email: 'test@test.com' }))
        component.ngOnInit()
        expect(userService.save).toHaveBeenCalledWith({ email: 'test@test.com', password: 'bW9jLnRzZXRAdHNldA==', passwordRepeat: 'bW9jLnRzZXRAdHNldA==' })
    })

    it('logs in user even after failed account creation as account might already have existed from previous OAuth login', () => {
        userService.oauthLogin.mockReturnValue(of({ email: 'test@test.com' }))
        userService.save.mockReturnValue(throwError({ error: 'Account already exists' }))
        component.ngOnInit()
        expect(userService.login).toHaveBeenCalledWith({ email: 'test@test.com', password: 'bW9jLnRzZXRAdHNldA==', oauth: true })
    })

    it('removes authentication token and basket id on failed subsequent regular login attempt', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.login.mockReturnValue(throwError({ error: 'Error' }))
        component.login({ email: '' })
        expect(localStorage.getItem('token')).toBeNull()
        expect(sessionStorage.getItem('bid')).toBeNull()
    })

    it('does not register or log in with a password derived only from the profile email', () => {
        const emails = ['oauth.probe.8673@example.test', 'second.oauth.probe.8673@example.test']
        for (const email of emails) {
            userService.save.mockClear()
            userService.login.mockClear()
            userService.oauthLogin.mockReturnValue(of({ email }))
            component.ngOnInit()
            const derived = btoa(email.split('').reverse().join(''))
            const saved = userService.save.mock.calls.some((call: [{ password?: string, passwordRepeat?: string }]) => call[0]?.password === derived || call[0]?.passwordRepeat === derived)
            const loggedIn = userService.login.mock.calls.some((call: [{ password?: string }]) => call[0]?.password === derived)
            expect(saved).toBe(false)
            expect(loggedIn).toBe(false)
        }
    })

    it('does not log in with a password derived only from the email when registration fails', () => {
        const email = 'already.present.8673@example.test'
        userService.save.mockClear()
        userService.login.mockClear()
        userService.oauthLogin.mockReturnValue(of({ email }))
        userService.save.mockReturnValue(throwError({ error: 'Account already exists' }))
        component.ngOnInit()
        const derived = btoa(email.split('').reverse().join(''))
        const loggedIn = userService.login.mock.calls.some((call: [{ password?: string }]) => call[0]?.password === derived)
        expect(loggedIn).toBe(false)
    })

    it('does not log in from login() with a password derived only from the profile email', () => {
        const email = 'direct.login.8673@example.test'
        userService.login.mockClear()
        component.login({ email })
        const derived = btoa(email.split('').reverse().join(''))
        const loggedIn = userService.login.mock.calls.some((call: [{ password?: string }]) => call[0]?.password === derived)
        expect(loggedIn).toBe(false)
    })
})
