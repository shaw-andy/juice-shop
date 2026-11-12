/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'

import { UserService } from './user.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('UserService changePassword', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            providers: [UserService, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('sends the passwords in the body and not in the request URL', () => {
        const service = TestBed.inject(UserService)
        const httpMock = TestBed.inject(HttpTestingController)
        const current = 'PLACEHOLDER_FORM_CURRENT'
        const updated = 'PLACEHOLDER_FORM_UPDATED'

        service.changePassword({ current, new: updated, repeat: updated }).subscribe()

        const req = httpMock.expectOne((candidate) => {
            return candidate.url.startsWith('http://localhost:3000/rest/user/change-password')
        })
        expect(req.request.method).toBe('POST')
        expect(req.request.url).not.toContain(current)
        expect(req.request.url).not.toContain(updated)
        expect(req.request.body).toEqual({ current, new: updated, repeat: updated })
        req.flush({ user: 'apiResponse' })
        httpMock.verify()
    })
})
