/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { provideZoneChangeDetection } from '@angular/core'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { provideRouter } from '@angular/router'
import { provideNoopAnimations } from '@angular/platform-browser/animations'
import { MatDialogModule } from '@angular/material/dialog'
import { TranslateModule } from '@ngx-translate/core'

import { SearchResultComponent } from './search-result.component'
import { ProductDetailsComponent } from '../product-details/product-details.component'
import { SocketIoService } from '../Services/socket-io.service'
import { DeluxeGuard } from '../app.guard'

if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class ResizeObserver {
    observe () {}
    unobserve () {}
    disconnect () {}
  } as any
}

// Same markup the API test stores. innerHTML must not turn it into elements.
const activeDescription = '<img id="pd-xss" src="x" alt="pd-xss" onerror="window.__productDescriptionRan=1"><iframe id="pd-xss-frame" src="javascript:alert(`xss`)">'

describe('product description rendering', () => {
  let fixture: ComponentFixture<SearchResultComponent>
  let httpMock: HttpTestingController

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [
        TranslateModule.forRoot(),
        MatDialogModule,
        SearchResultComponent,
        ProductDetailsComponent
      ],
      providers: [
        provideRouter([]),
        provideZoneChangeDetection(),
        provideNoopAnimations(),
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: DeluxeGuard, useValue: { isDeluxe: () => false } },
        {
          provide: SocketIoService,
          useValue: { socket: () => ({ on () {}, emit () {} }) }
        }
      ]
    }).compileComponents()

    httpMock = TestBed.inject(HttpTestingController)
    fixture = TestBed.createComponent(SearchResultComponent)
    fixture.detectChanges()

    const quantities = httpMock.expectOne('http://localhost:3000/api/Quantitys/')
    const search = httpMock.expectOne('http://localhost:3000/rest/products/search?q=')
    quantities.flush({ data: [] })
    search.flush({
      data: [{
        id: 1,
        name: 'Apple Juice',
        description: activeDescription,
        price: 1.99,
        deluxePrice: 0.99,
        image: 'apple_juice.jpg'
      }]
    })
    fixture.detectChanges()
  })

  it('does not insert a searched product description as HTML in the product dialog', () => {
    const section: HTMLElement | null = fixture.nativeElement.querySelector('section')
    expect(section).not.toBeNull()
    section?.click()
    fixture.detectChanges()

    for (const pending of httpMock.match(() => true)) {
      if (pending.request.url.includes('whoami')) {
        pending.flush({ user: {} })
      } else {
        pending.flush({ data: [] })
      }
    }
    fixture.detectChanges()

    const dialog = document.querySelector('[aria-label="Close Dialog"]')
    const insertedImage = document.getElementById('pd-xss')
    const insertedFrame = document.getElementById('pd-xss-frame')
    expect(dialog, 'product dialog did not open').not.toBeNull()
    expect(insertedImage, insertedImage?.outerHTML ?? '').toBeNull()
    expect(insertedFrame, insertedFrame?.outerHTML ?? '').toBeNull()
  })
})
