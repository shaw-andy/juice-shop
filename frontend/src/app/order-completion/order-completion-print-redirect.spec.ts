/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { ActivatedRoute, convertToParamMap, DefaultUrlSerializer } from '@angular/router'
import { MatCardModule } from '@angular/material/card'
import { MatTableModule } from '@angular/material/table'
import { of, throwError } from 'rxjs'
import { OrderCompletionComponent } from './order-completion.component'
import { TrackOrderService } from '../Services/track-order.service'
import { MatIconModule } from '@angular/material/icon'
import { BasketService } from '../Services/basket.service'
import { MatTooltipModule } from '@angular/material/tooltip'
import { AddressService } from '../Services/address.service'
import { ConfigurationService } from '../Services/configuration.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { provideZoneChangeDetection } from '@angular/core'

const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/

describe('OrderCompletionComponent print target', () => {
    let fixture: ComponentFixture<OrderCompletionComponent>
    let trackOrderService: any
    let activatedRoute: { paramMap: any }
    let basketService: { hostServer: string }

    beforeEach(async () => {
        trackOrderService = { find: vi.fn().mockName('TrackOrderService.find') }
        trackOrderService.find.mockReturnValue(throwError(() => new Error('not found')))
        activatedRoute = { paramMap: of(convertToParamMap({ id: 'unused' })) }
        basketService = { hostServer: '.' }

        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), MatTableModule, MatCardModule, MatIconModule, MatTooltipModule, OrderCompletionComponent],
            providers: [
                { provide: TrackOrderService, useValue: trackOrderService },
                { provide: ActivatedRoute, useValue: activatedRoute },
                { provide: BasketService, useValue: basketService },
                { provide: ConfigurationService, useValue: { getApplicationConfiguration: () => of({}) } },
                { provide: AddressService, useValue: { getById: () => of({}) } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting(),
                provideZoneChangeDetection()
            ]
        }).compileComponents()
    })

    const openFromRouteId = (routeId: string) => {
        const parsed = new DefaultUrlSerializer().parse('/order-completion/' + encodeURIComponent(routeId))
        const id = parsed.root.children.primary.segments[1].path
        activatedRoute.paramMap = of(convertToParamMap({ id }))
        fixture = TestBed.createComponent(OrderCompletionComponent)
        fixture.detectChanges()
        const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
        const button: HTMLButtonElement = fixture.nativeElement.querySelector('button[aria-label="Print order confirmation"]')
        button.click()
        return openSpy
    }

    it('does not open a print tab for a route id that is not a server order id', () => {
        const openSpy = openFromRouteId('../../../redirect?to=http://attacker.example/%23https://github.com/juice-shop/juice-shop')
        expect(openSpy).not.toHaveBeenCalled()
        openSpy.mockRestore()
    })

    it('opens only the hex order pdf and blocks the new tab from navigating this one', () => {
        const orderId = 'ad9b-96017e7cb1ae7bf9'
        expect(orderId).toMatch(orderIdPattern)
        trackOrderService.find.mockReturnValue(of({ data: [{ orderId, products: [], totalPrice: 0, promotionalAmount: 0, deliveryPrice: 0 }] }))
        const openSpy = openFromRouteId(orderId)
        expect(openSpy).toHaveBeenCalledTimes(1)
        const [url, target, features] = openSpy.mock.calls[0]
        const resolved = new URL(String(url), 'https://shop.example/')
        expect(resolved.origin).toBe('https://shop.example')
        expect(resolved.pathname).toBe(`/ftp/order_${orderId}.pdf`)
        expect(resolved.search).toBe('')
        expect(target).toBe('_blank')
        expect(String(features)).toContain('noopener')
        openSpy.mockRestore()
    })
})
