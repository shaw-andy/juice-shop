/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { EventEmitter } from '@angular/core'
import { of, throwError } from 'rxjs'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { LastLoginIpComponent } from './last-login-ip.component'
import { MatCardModule } from '@angular/material/card'
import { DomSanitizer } from '@angular/platform-browser'
import { UserService } from '../Services/user.service'

describe('LastLoginIpComponent', () => {
    let component: LastLoginIpComponent
    let fixture: ComponentFixture<LastLoginIpComponent>
    let sanitizer
    let translateService
    let userService

    beforeEach(async () => {
        userService = {
            whoAmI: vi.fn().mockName("UserService.whoAmI")
        }
        userService.whoAmI.mockReturnValue(of({}))
        sanitizer = {
            bypassSecurityTrustHtml: vi.fn().mockName("DomSanitizer.bypassSecurityTrustHtml"),
            sanitize: vi.fn().mockName("DomSanitizer.sanitize")
        }
        sanitizer.bypassSecurityTrustHtml.mockImplementation((args: any) => args)
        sanitizer.sanitize.mockReturnValue({})
        translateService = {
            get: vi.fn().mockName("TranslateService.get")
        }
        translateService.get.mockReturnValue(of({}))
        translateService.onLangChange = new EventEmitter()
        translateService.onTranslationChange = new EventEmitter()
        translateService.onFallbackLangChange = new EventEmitter()
        translateService.onDefaultLangChange = new EventEmitter()

        TestBed.configureTestingModule({
            providers: [
                { provide: DomSanitizer, useValue: sanitizer },
                { provide: TranslateService, useValue: translateService },
                { provide: UserService, useValue: userService }
            ],
            imports: [
                MatCardModule,
                LastLoginIpComponent,
                TranslateModule.forRoot()
            ]
        }).compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(LastLoginIpComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should compile', () => {
        expect(component).toBeTruthy()
    })

    it('should request only the last login IP of the current user', () => {
        expect(userService.whoAmI).toHaveBeenCalledWith(['lastLoginIp'])
    })

    it('should log error from retrieving the current user to console', () => {
        console.log = vi.fn()
        userService.whoAmI.mockReturnValue(throwError(() => new Error('Error')))
        component.ngOnInit()
        expect(console.log).toHaveBeenCalled()
    })

    it('should set Last-Login IP of the current user as trusted HTML', () => {
        userService.whoAmI.mockReturnValue(of({ lastLoginIp: '1.2.3.4' }))
        component.ngOnInit()
        expect(sanitizer.bypassSecurityTrustHtml).toHaveBeenCalledWith('<small>1.2.3.4</small>')
    })

    it('should not set Last-Login IP if the current user has none', () => {
        userService.whoAmI.mockReturnValue(of({}))
        component.ngOnInit()
        expect(sanitizer.bypassSecurityTrustHtml).not.toHaveBeenCalled()
    })
})
