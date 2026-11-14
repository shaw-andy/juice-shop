/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { UserService } from '../Services/user.service'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { ChangePasswordComponent } from './change-password.component'
import { ReactiveFormsModule } from '@angular/forms'

import { MatButtonModule } from '@angular/material/button'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'
import { of, throwError } from 'rxjs'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('ChangePasswordComponent', () => {
    let component: ChangePasswordComponent
    let fixture: ComponentFixture<ChangePasswordComponent>
    let userService: any

    beforeEach(async () => {
        userService = {
            changePassword: vi.fn().mockName("UserService.changePassword")
        }
        userService.changePassword.mockReturnValue(of({}))

        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(),
                ReactiveFormsModule,
                MatCardModule,
                MatFormFieldModule,
                MatInputModule,
                MatButtonModule,
                ChangePasswordComponent],
            providers: [{ provide: UserService, useValue: userService }, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(ChangePasswordComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should be compulsory to give password', () => {
        component.passwordControl.setValue('')
        expect(component.passwordControl.valid).toBeFalsy()
        component.passwordControl.setValue('pass')
        expect(component.passwordControl.valid).toBe(true)
    })

    it('length of new password must be 5-40 characters', () => {
        component.newPasswordControl.setValue('old')
        expect(component.newPasswordControl.valid).toBeFalsy()
        component.newPasswordControl.setValue('new password')
        expect(component.newPasswordControl.valid).toBe(true)
        component.newPasswordControl.setValue('new password new password')
        expect(component.newPasswordControl.valid).toBe(true)
        component.newPasswordControl.setValue('new password new password new password new password')
        expect(component.newPasswordControl.valid).toBeFalsy()
    })

    it('should be compulsory to repeat new password', () => {
        component.repeatNewPasswordControl.setValue('')
        expect(component.passwordControl.valid).toBeFalsy()
        component.newPasswordControl.setValue('passed')
        component.repeatNewPasswordControl.setValue('passed')
        expect(component.repeatNewPasswordControl.valid).toBe(true)
    })

    it('should reinitizalise forms by calling resetForm', () => {
        component.passwordControl.setValue('password')
        component.newPasswordControl.setValue('newPassword')
        component.repeatNewPasswordControl.setValue('newPassword')
        component.resetForm()
        expect(component.passwordControl.value).toBe('')
        expect(component.passwordControl.pristine).toBe(true)
        expect(component.passwordControl.untouched).toBe(true)
        expect(component.newPasswordControl.value).toBe('')
        expect(component.newPasswordControl.pristine).toBe(true)
        expect(component.newPasswordControl.untouched).toBe(true)
        expect(component.repeatNewPasswordControl.value).toBe('')
        expect(component.repeatNewPasswordControl.pristine).toBe(true)
        expect(component.repeatNewPasswordControl.untouched).toBe(true)
    })

    it('should clear form and show confirmation after changing password', () => {
        userService.changePassword.mockReturnValue(of({}))
        vi.spyOn(component, 'resetForm')
        component.passwordControl.setValue('old')
        component.newPasswordControl.setValue('foobar')
        component.repeatNewPasswordControl.setValue('foobar')
        component.changePassword()
        expect(component.error).toBeUndefined()
        expect(component.confirmation).toBeDefined()
        expect(component.resetForm).toHaveBeenCalled()
    })

    it('should clear form and gracefully handle error on password change', () => {
        userService.changePassword.mockReturnValue(throwError('Error'))
        vi.spyOn(component, 'resetPasswords')
        console.log = vi.fn()
        component.passwordControl.setValue('old')
        component.newPasswordControl.setValue('foobar')
        component.repeatNewPasswordControl.setValue('fooabar')
        component.changePassword()
        expect(component.confirmation).toBeUndefined()
        expect(component.error).toBe('Error')
        expect(console.log).toHaveBeenCalledWith('Error')
        expect(component.resetPasswords).toHaveBeenCalled()
    })

    describe('support administrator password policy', () => {
        const supportEmail = 'support@juice-sh.op'
        const fiveCharacters = 'aaaaa'
        const missingCharacterClass = 'Placeholder1'
        const compliantPassword = 'Placeholder1!'

        afterEach(() => {
            localStorage.removeItem('email')
        })

        function fillPasswords (current: string, next: string) {
            component.passwordControl.setValue(current)
            component.newPasswordControl.setValue(next)
            component.repeatNewPasswordControl.setValue(next)
        }

        it('aligns the form length rule with the privileged password policy', () => {
            fillPasswords('current-placeholder', 'a'.repeat(5))
            expect(component.newPasswordControl.valid).toBe(false)
            expect(component.repeatNewPasswordControl.valid).toBe(false)
            fillPasswords('current-placeholder', 'a'.repeat(11))
            expect(component.newPasswordControl.valid).toBe(false)
            fillPasswords('current-placeholder', 'a'.repeat(12))
            expect(component.newPasswordControl.valid).toBe(true)
            expect(component.repeatNewPasswordControl.valid).toBe(true)
            fillPasswords('current-placeholder', 'a'.repeat(30))
            expect(component.newPasswordControl.valid).toBe(true)
            fillPasswords('current-placeholder', 'a'.repeat(31))
            expect(component.newPasswordControl.valid).toBe(false)
            expect(component.repeatNewPasswordControl.valid).toBe(false)
            fixture.detectChanges()
            const button: HTMLButtonElement = fixture.nativeElement.querySelector('#changeButton')
            expect(button.disabled).toBe(true)
        })

        it('does not submit a five-character password for the support account', () => {
            localStorage.setItem('email', supportEmail)
            fillPasswords('current-placeholder', fiveCharacters)
            vi.spyOn(component, 'resetForm')
            component.changePassword()
            expect(userService.changePassword).not.toHaveBeenCalled()
            expect(component.confirmation).toBeUndefined()
            expect(component.error).toBeTruthy()
            expect(component.resetForm).not.toHaveBeenCalled()
        })

        it('does not submit a password that misses a required character class', () => {
            localStorage.setItem('email', supportEmail)
            fillPasswords('current-placeholder', missingCharacterClass)
            component.changePassword()
            expect(userService.changePassword).not.toHaveBeenCalled()
            expect(component.confirmation).toBeUndefined()
            expect(component.error).toBeTruthy()
        })

        it('submits a password that meets the privileged account policy', () => {
            localStorage.setItem('email', supportEmail)
            fillPasswords('current-placeholder', compliantPassword)
            component.changePassword()
            expect(userService.changePassword).toHaveBeenCalledWith({
                current: 'current-placeholder',
                new: compliantPassword,
                repeat: compliantPassword
            })
        })

        it('still submits a short password for an account that is not support', () => {
            localStorage.setItem('email', 'customer@juice-sh.op')
            fillPasswords('current-placeholder', fiveCharacters)
            component.changePassword()
            expect(userService.changePassword).toHaveBeenCalled()
        })
    })
})
