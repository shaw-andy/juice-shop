/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { TrackResultComponent } from './track-result.component'
import { MatCardModule } from '@angular/material/card'
import { MatTableModule } from '@angular/material/table'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { ActivatedRoute } from '@angular/router'

const markup = '<img src=x onerror=document.title=localStorage.token>'
const challengeMarkup = '<iframe src="javascript:alert(`xss`)">'

describe('TrackResultComponent order id rendering', () => {
    let fixture: ComponentFixture<TrackResultComponent>
    let httpMock: HttpTestingController

    async function renderTrackingId (id: string, routeData: Record<string, string> = {}): Promise<HTMLElement> {
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), MatCardModule, MatTableModule, TrackResultComponent],
            providers: [
                {
                    provide: ActivatedRoute,
                    useValue: { snapshot: { queryParams: { id }, data: routeData } }
                },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        }).compileComponents()

        fixture = TestBed.createComponent(TrackResultComponent)
        httpMock = TestBed.inject(HttpTestingController)
        localStorage.setItem('token', 'placeholder-session')
        document.title = 'before'
        fixture.detectChanges()

        const req = httpMock.expectOne('http://localhost:3000/rest/track-order/' + encodeURIComponent(id))
        expect(req.request.method).toBe('GET')
        req.flush({ status: 'success', data: [{ orderId: id }] })
        fixture.detectChanges()
        httpMock.verify()
        return fixture.nativeElement as HTMLElement
    }

    afterEach(() => {
        localStorage.removeItem('token')
        TestBed.resetTestingModule()
    })

    it('shows an ordinary order id as text', async () => {
        const host = await renderTrackingId('order-safe-1')
        expect(host.querySelector('h1')?.textContent).toContain('order-safe-1')
    })

    it('shows a script-bearing tracking id as text on the track-result page', async () => {
        const host = await renderTrackingId(markup)
        const heading = host.querySelector('h1')
        expect(heading?.querySelector('img, iframe, script, svg')).toBeNull()
        expect(heading?.textContent).toContain(markup)
        expect(document.title).toBe('before')
    })

    it('shows the reflected XSS challenge payload as text on the new-order tracking page', async () => {
        const host = await renderTrackingId(challengeMarkup, { type: 'new' })
        const heading = host.querySelector('h1')
        expect(heading?.querySelector('img, iframe, script, svg')).toBeNull()
        expect(heading?.textContent).toContain(challengeMarkup)
        expect(document.title).toBe('before')
    })
})
