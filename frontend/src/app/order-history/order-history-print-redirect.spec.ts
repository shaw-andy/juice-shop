/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { OrderHistoryComponent } from './order-history.component'
import { OrderHistoryService } from '../Services/order-history.service'
import { BasketService } from '../Services/basket.service'
import { ProductService } from '../Services/product.service'
import { MatDialog } from '@angular/material/dialog'
import { Router } from '@angular/router'
import { MatCardModule } from '@angular/material/card'
import { MatTableModule } from '@angular/material/table'
import { MatIconModule } from '@angular/material/icon'
import { MatTooltipModule } from '@angular/material/tooltip'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('OrderHistoryComponent print target', () => {
    let fixture: ComponentFixture<OrderHistoryComponent>
    let component: OrderHistoryComponent

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), MatCardModule, MatTableModule, MatIconModule, MatTooltipModule, OrderHistoryComponent],
            providers: [
                { provide: OrderHistoryService, useValue: { get: () => of([]) } },
                { provide: ProductService, useValue: { get: () => of({}) } },
                { provide: MatDialog, useValue: { open: () => null } },
                { provide: BasketService, useValue: { hostServer: '.' } },
                { provide: Router, useValue: { navigate: vi.fn().mockResolvedValue(true) } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        }).compileComponents()
        fixture = TestBed.createComponent(OrderHistoryComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('does not open a print tab for an order id that is not the server hex form', () => {
        const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
        component.openConfirmationPDF('../../../redirect?to=http://attacker.example/%23https://github.com/juice-shop/juice-shop')
        expect(openSpy).not.toHaveBeenCalled()
        openSpy.mockRestore()
    })

    it('opens the hex order pdf without letting the new tab navigate this one', () => {
        const orderId = 'ad9b-96017e7cb1ae7bf9'
        const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
        component.openConfirmationPDF(orderId)
        expect(openSpy).toHaveBeenCalledTimes(1)
        const [url, target, features] = openSpy.mock.calls[0]
        const resolved = new URL(String(url), 'https://shop.example/')
        expect(resolved.pathname).toBe(`/ftp/order_${orderId}.pdf`)
        expect(resolved.search).toBe('')
        expect(target).toBe('_blank')
        expect(String(features)).toContain('noopener')
        openSpy.mockRestore()
    })
})
