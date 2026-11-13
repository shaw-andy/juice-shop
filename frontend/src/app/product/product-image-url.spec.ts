/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { provideZoneChangeDetection } from '@angular/core'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { MAT_DIALOG_DATA, MatDialog } from '@angular/material/dialog'
import { MatSnackBar } from '@angular/material/snack-bar'
import { TranslateModule } from '@ngx-translate/core'
import { of } from 'rxjs'

import { DeluxeGuard } from '../app.guard'
import { type Product, type ProductTableEntry } from '../Models/product.model'
import { ProductDetailsComponent } from '../product-details/product-details.component'
import { ProductReviewService } from '../Services/product-review.service'
import { UserService } from '../Services/user.service'
import { PurchaseBasketComponent } from '../purchase-basket/purchase-basket.component'
import { BasketService } from '../Services/basket.service'
import { ProductService } from '../Services/product.service'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { ProductComponent } from './product.component'

const SHOP_PAGE = 'http://127.0.0.1:3000/#/search'
const PRODUCT_IMAGE_DIR = '/assets/public/images/products/'
const ALLOWLISTED_REDIRECT = 'https://github.com/juice-shop/juice-shop'
const EXTERNAL_TARGET = `https://example.invalid/owned?marker=${ALLOWLISTED_REDIRECT}`
const TRAVERSAL_IMAGE = `../../../../redirect?to=${EXTERNAL_TARGET}`
const SAFE_IMAGE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:png|jpe?g|gif|webp|svg)$/

function expectCatalogImageUrl (value: string | null) {
    expect(value).toBeTruthy()
    const raw = String(value)
    const cssUrl = raw.match(/^url\((['"]?)(.*)\1\)$/)
    const bound = new URL(cssUrl ? cssUrl[2] : raw, SHOP_PAGE)
    const filename = bound.pathname.startsWith(PRODUCT_IMAGE_DIR)
        ? bound.pathname.slice(PRODUCT_IMAGE_DIR.length)
        : ''
    expect(bound.pathname).toBe(PRODUCT_IMAGE_DIR + filename)
    expect(filename.includes('/')).toBe(false)
    expect(bound.search).toBe('')
    expect(bound.hash).toBe('')
    expect(filename).toMatch(SAFE_IMAGE_NAME)
}

describe('product image URL binding', () => {
    const maliciousProduct: Product = {
        id: 1,
        name: 'Apple Juice',
        description: 'probe',
        image: TRAVERSAL_IMAGE,
        price: 1.99,
        deluxePrice: 0.99
    }

    it('keeps the search card image and background inside the products folder', async () => {
        const productService = {
            search: vi.fn().mockReturnValue(of([])),
            get: vi.fn().mockReturnValue(of(maliciousProduct))
        }
        const basketService = {
            find: vi.fn().mockReturnValue(of({ Products: [] })),
            get: vi.fn().mockReturnValue(of({})),
            put: vi.fn().mockReturnValue(of({})),
            save: vi.fn().mockReturnValue(of({})),
            updateNumberOfCartItems: vi.fn()
        }
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), ProductComponent],
            providers: [
                { provide: MatDialog, useValue: { open: vi.fn() } },
                { provide: ProductService, useValue: productService },
                { provide: BasketService, useValue: basketService },
                { provide: SnackBarHelperService, useValue: { open: vi.fn() } },
                provideZoneChangeDetection()
            ]
        }).compileComponents()

        const fixture: ComponentFixture<ProductComponent> = TestBed.createComponent(ProductComponent)
        const item: ProductTableEntry = { ...maliciousProduct, quantity: 5 }
        fixture.componentRef.setInput('item', item)
        fixture.componentRef.setInput('isLoggedIn', false)
        fixture.componentRef.setInput('isDeluxe', false)
        fixture.detectChanges()

        const image = fixture.nativeElement.querySelector('img') as HTMLImageElement
        const frame = fixture.nativeElement.querySelector('.image-container') as HTMLElement
        expectCatalogImageUrl(image.getAttribute('src'))
        expectCatalogImageUrl(image.src)
        expectCatalogImageUrl(frame.style.backgroundImage)
    })

    it('keeps the product details image inside the products folder', async () => {
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), ProductDetailsComponent],
            providers: [
                { provide: MAT_DIALOG_DATA, useValue: { productData: { ...maliciousProduct } } },
                { provide: MatDialog, useValue: { open: vi.fn() } },
                { provide: ProductReviewService, useValue: { get: vi.fn().mockReturnValue(of([])), create: vi.fn().mockReturnValue(of({})) } },
                { provide: UserService, useValue: { whoAmI: vi.fn().mockReturnValue(of({})) } },
                provideZoneChangeDetection()
            ]
        }).compileComponents()

        const fixture = TestBed.createComponent(ProductDetailsComponent)
        fixture.detectChanges()
        const image = fixture.nativeElement.querySelector('img') as HTMLImageElement
        expectCatalogImageUrl(image.getAttribute('src'))
        expectCatalogImageUrl(image.src)
    })

    it('keeps the basket image inside the products folder', async () => {
        localStorage.setItem('token', 'token')
        const basketService = {
            find: vi.fn().mockReturnValue(of({
                Products: [{
                    ...maliciousProduct,
                    BasketItem: { id: 1, quantity: 1 }
                }]
            })),
            del: vi.fn().mockReturnValue(of({})),
            get: vi.fn().mockReturnValue(of({})),
            put: vi.fn().mockReturnValue(of({})),
            updateNumberOfCartItems: vi.fn(),
            getGuestBasketItems: vi.fn().mockReturnValue([]),
            removeGuestBasketItem: vi.fn(),
            updateGuestBasketItemQuantity: vi.fn()
        }
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), PurchaseBasketComponent],
            providers: [
                { provide: BasketService, useValue: basketService },
                { provide: UserService, useValue: { whoAmI: vi.fn().mockReturnValue(of({})) } },
                { provide: ProductService, useValue: { get: vi.fn().mockReturnValue(of(maliciousProduct)) } },
                { provide: DeluxeGuard, useValue: { isDeluxe: vi.fn().mockReturnValue(false) } },
                { provide: MatSnackBar, useValue: { open: vi.fn() } },
                { provide: SnackBarHelperService, useValue: { open: vi.fn() } },
                provideZoneChangeDetection()
            ]
        }).compileComponents()

        const fixture = TestBed.createComponent(PurchaseBasketComponent)
        fixture.detectChanges()
        const image = fixture.nativeElement.querySelector('img') as HTMLImageElement
        expectCatalogImageUrl(image.getAttribute('src'))
        expectCatalogImageUrl(image.src)
        localStorage.removeItem('token')
    })
})
