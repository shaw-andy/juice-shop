/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { provideRouter, withHashLocation } from '@angular/router'
import { RouterTestingHarness } from '@angular/router/testing'
import { TranslateModule } from '@ngx-translate/core'
import { of } from 'rxjs'
import { DeluxeGuard } from '../app.guard'
import { ProductService } from '../Services/product.service'
import { QuantityService } from '../Services/quantity.service'
import { SocketIoService } from '../Services/socket-io.service'
import { SearchResultComponent } from './search-result.component'

if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class ResizeObserver {
    observe () {}
    unobserve () {}
    disconnect () {}
  } as any
}

const imageMarkup = '<img src="x" onerror="document.documentElement.dataset.searchRan=\'1\';document.documentElement.dataset.sawToken=localStorage.getItem(\'token\')?\'yes\':\'no\'">'
const svgMarkup = '<svg onload="document.documentElement.dataset.searchRan=\'1\'"></svg>'

describe('Search query HTML rendering', () => {
  beforeEach(() => {
    localStorage.clear()
    delete document.documentElement.dataset.searchRan
    delete document.documentElement.dataset.sawToken
    TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), SearchResultComponent],
      providers: [
        provideRouter([
          { path: 'search', component: SearchResultComponent }
        ], withHashLocation()),
        { provide: ProductService, useValue: { search: () => of([]), get: () => of({}) } },
        { provide: QuantityService, useValue: { getAll: () => of([]) } },
        { provide: SocketIoService, useValue: { socket: () => ({ emit () {}, on () {} }) } },
        { provide: DeluxeGuard, useValue: { isDeluxe: () => false } }
      ]
    })
  })

  afterEach(() => {
    localStorage.clear()
    delete document.documentElement.dataset.searchRan
    delete document.documentElement.dataset.sawToken
  })

  async function openSearch (query: string) {
    const harness = await RouterTestingHarness.create()
    await harness.navigateByUrl('/search?q=' + encodeURIComponent(query))
    return harness
  }

  function expectRenderedAsText (root: ParentNode, query: string) {
    const el = root.querySelector('#searchValue')
    expect(el).toBeTruthy()
    expect(el?.querySelector('*')).toBeNull()
    expect(el?.textContent).toBe(query.trim())
    expect(document.documentElement.dataset.searchRan).toBeUndefined()
    expect(document.documentElement.dataset.sawToken).toBeUndefined()
  }

  it('renders the q query from the search link as text', async () => {
    localStorage.setItem('token', 'placeholder-token')
    const harness = await openSearch('  ' + imageMarkup + '  ')
    expectRenderedAsText(harness.routeNativeElement as ParentNode, imageMarkup)
  })

  it('renders a changed q query as text when the route updates', async () => {
    localStorage.setItem('token', 'placeholder-token')
    const harness = await openSearch('apple')
    await harness.navigateByUrl('/search?q=' + encodeURIComponent(svgMarkup))
    expectRenderedAsText(harness.routeNativeElement as ParentNode, svgMarkup)
  })
})
