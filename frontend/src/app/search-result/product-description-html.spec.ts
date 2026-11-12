/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { provideZoneChangeDetection } from '@angular/core'
import { TestBed, type ComponentFixture } from '@angular/core/testing'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { MAT_DIALOG_DATA, MatDialog } from '@angular/material/dialog'
import { provideRouter } from '@angular/router'
import { TranslateModule } from '@ngx-translate/core'
import { of } from 'rxjs'
import { SearchResultComponent } from './search-result.component'
import { ProductDetailsComponent } from '../product-details/product-details.component'
import { SocketIoService } from '../Services/socket-io.service'
import { DeluxeGuard } from '../app.guard'
import { UserService } from '../Services/user.service'
import { ProductReviewService } from '../Services/product-review.service'
import { type ProductTableEntry } from '../Models/product.model'

if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class ResizeObserver {
    observe () {}
    unobserve () {}
    disconnect () {}
  } as any
}

const descriptionMarkup = '<iframe src="javascript:alert(`xss`)"></iframe><img src="x" onerror="window.__productDescriptionRan=1">'

describe('product description HTML', () => {
  let searchFixture: ComponentFixture<SearchResultComponent>
  let httpMock: HttpTestingController

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), SearchResultComponent],
      providers: [
        provideZoneChangeDetection(),
        provideRouter([]),
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: SocketIoService, useValue: { socket: () => ({ on () {}, emit () {} }) } },
        { provide: DeluxeGuard, useValue: { isDeluxe: () => false } }
      ]
    }).compileComponents()

    searchFixture = TestBed.createComponent(SearchResultComponent)
    httpMock = TestBed.inject(HttpTestingController)
    searchFixture.detectChanges()
    httpMock.expectOne('http://localhost:3000/api/Quantitys/').flush({ status: 'success', data: [] })
    httpMock.expectOne('http://localhost:3000/rest/products/search?q=').flush({
      status: 'success',
      data: [{
        id: 1,
        name: 'Apple Juice (1000ml)',
        description: descriptionMarkup,
        price: 1.99,
        deluxePrice: 0.99,
        image: 'apple_juice.jpg'
      }]
    })
    searchFixture.detectChanges()
  })

  afterEach(() => {
    httpMock.verify()
    delete (window as unknown as { __productDescriptionRan?: number }).__productDescriptionRan
  })

  it('does not insert a product description as HTML when the product is opened from search', async () => {
    const item = searchFixture.componentInstance.dataSource.data[0] as ProductTableEntry
    expect(searchFixture.nativeElement.querySelector('iframe')).toBeNull()
    expect(searchFixture.nativeElement.querySelector('img[onerror]')).toBeNull()

    TestBed.resetTestingModule()
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), ProductDetailsComponent],
      providers: [
        provideZoneChangeDetection(),
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: UserService, useValue: { whoAmI: () => of({}) } },
        { provide: ProductReviewService, useValue: { get: () => of([]), create: () => of({}) } },
        { provide: MatDialog, useValue: { open: () => ({ afterClosed: () => of({}) }) } },
        { provide: MAT_DIALOG_DATA, useValue: { productData: item } }
      ]
    }).compileComponents()

    const detailsFixture = TestBed.createComponent(ProductDetailsComponent)
    detailsFixture.detectChanges()
    const details = detailsFixture.nativeElement as HTMLElement

    expect((window as unknown as { __productDescriptionRan?: number }).__productDescriptionRan).toBeUndefined()
    expect(details.querySelector('iframe')).toBeNull()
    expect(details.querySelector('img[onerror]')).toBeNull()
  })
})
