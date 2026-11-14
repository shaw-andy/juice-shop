/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { MatDividerModule } from '@angular/material/divider'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { MatGridListModule } from '@angular/material/grid-list'
import { MatCardModule } from '@angular/material/card'
import { MatTableModule } from '@angular/material/table'
import { MatPaginatorModule } from '@angular/material/paginator'
import { MatDialogModule } from '@angular/material/dialog'
import { of } from 'rxjs'
import { OrderCompletionComponent } from './order-completion.component'
import { TrackOrderService } from '../Services/track-order.service'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { MatIconModule } from '@angular/material/icon'
import { BasketService } from '../Services/basket.service'
import { MatTooltipModule } from '@angular/material/tooltip'
import { AddressService } from '../Services/address.service'
import { ConfigurationService } from '../Services/configuration.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { provideZoneChangeDetection } from '@angular/core'

const attackerName = 'Juice&url=https://attacker.example&'
const seededAmpersandName = 'DSOMM & Juice Shop User Day Ticket'

describe('OrderCompletionComponent tweet link', () => {
    let fixture: ComponentFixture<OrderCompletionComponent>
    let trackOrderService: { find: ReturnType<typeof vi.fn> }
    let configurationService: { getApplicationConfiguration: ReturnType<typeof vi.fn> }
    let addressService: { getById: ReturnType<typeof vi.fn> }

    beforeEach(async () => {
        configurationService = {
            getApplicationConfiguration: vi.fn().mockName('ConfigurationService.getApplicationConfiguration')
        }
        configurationService.getApplicationConfiguration.mockReturnValue(of({
            application: { social: { twitterUrl: 'https://twitter.com/owasp_juiceshop' } }
        }))
        trackOrderService = {
            find: vi.fn().mockName('TrackOrderService.find')
        }
        trackOrderService.find.mockReturnValue(of({ data: [{ products: [] }] }))
        addressService = {
            getById: vi.fn().mockName('AddressService.getById')
        }
        addressService.getById.mockReturnValue(of({}))

        TestBed.configureTestingModule({
            imports: [RouterTestingModule,
                TranslateModule.forRoot(),
                MatTableModule,
                MatPaginatorModule,
                MatDialogModule,
                MatDividerModule,
                MatGridListModule,
                MatCardModule,
                MatIconModule,
                MatTooltipModule,
                OrderCompletionComponent],
            providers: [
                { provide: TrackOrderService, useValue: trackOrderService },
                {
                    provide: ActivatedRoute,
                    useValue: { paramMap: of(convertToParamMap({ id: 'ad9b-96017e7cb1ae7bf9' })) }
                },
                { provide: BasketService, useValue: {} },
                { provide: ConfigurationService, useValue: configurationService },
                { provide: AddressService, useValue: addressService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting(),
                provideZoneChangeDetection()
            ]
        })
            .compileComponents()
    })

    function renderOrder (names: string[]) {
        const products = names.map((name) => ({ name, price: 1.99, quantity: 1, total: 1.99 }))
        trackOrderService.find.mockReturnValue(of({
            data: [{ products, totalPrice: 1.99, addressId: 1, paymentId: 1 }]
        }))
        fixture = TestBed.createComponent(OrderCompletionComponent)
        fixture.detectChanges()
        const anchor: HTMLAnchorElement = fixture.nativeElement.querySelector('a[aria-label="Tweet"]')
        expect(anchor).toBeTruthy()
        return new URL(anchor.href)
    }

    it('keeps every product name inside a single text query parameter', () => {
        const tweet = renderOrder([
            attackerName,
            seededAmpersandName
        ])
        expect(tweet.searchParams.get('url')).toBeNull()
        expect([...tweet.searchParams.keys()]).toEqual(['text', 'hashtags'])
        expect(tweet.searchParams.get('hashtags')).toBe('security')
        const text = tweet.searchParams.get('text') ?? ''
        expect(text).toContain(attackerName)
        expect(text).toContain(seededAmpersandName)
        expect(text).toContain('https://attacker.example')
    })

    it('keeps a product name inside the text parameter when social text is not appended', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({}))
        const tweet = renderOrder(['Juice&url=https://attacker.example'])
        expect(tweet.searchParams.get('url')).toBeNull()
        expect([...tweet.searchParams.keys()]).toEqual(['text', 'hashtags'])
        expect(tweet.searchParams.get('text')).toContain('Juice&url=https://attacker.example')
    })
})
