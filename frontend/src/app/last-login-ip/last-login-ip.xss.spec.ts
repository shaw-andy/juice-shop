/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { EventEmitter } from '@angular/core'
import { of } from 'rxjs'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { LastLoginIpComponent } from './last-login-ip.component'
import { MatCardModule } from '@angular/material/card'

function sessionToken (lastLoginIp: string): string {
  const encode = (value: object) => btoa(JSON.stringify(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode({ data: { lastLoginIp } })}.placeholder-signature`
}

describe('LastLoginIpComponent untrusted last login IP', () => {
  let fixture: ComponentFixture<LastLoginIpComponent>

  beforeEach(async () => {
    const translateService = {
      get: vi.fn().mockName('TranslateService.get'),
      onLangChange: new EventEmitter(),
      onTranslationChange: new EventEmitter(),
      onFallbackLangChange: new EventEmitter(),
      onDefaultLangChange: new EventEmitter()
    }
    translateService.get.mockReturnValue(of({}))

    await TestBed.configureTestingModule({
      providers: [
        { provide: TranslateService, useValue: translateService }
      ],
      imports: [
        MatCardModule,
        LastLoginIpComponent,
        TranslateModule.forRoot()
      ]
    }).compileComponents()
  })

  afterEach(() => {
    localStorage.clear()
  })

  function render (lastLoginIp: string): HTMLElement {
    localStorage.setItem('token', sessionToken(lastLoginIp))
    fixture = TestBed.createComponent(LastLoginIpComponent)
    fixture.detectChanges()
    return fixture.nativeElement.querySelector('dd')
  }

  it('shows a plain address as text', () => {
    const dd = render('203.0.113.10')
    expect(dd.textContent).toContain('203.0.113.10')
    expect(dd.querySelector('iframe, script, img, svg')).toBeNull()
  })

  it('does not parse an iframe, script, or event-handler payload from the session token as HTML', () => {
    const dd = render('<iframe src="javascript:alert(`xss`)"></iframe><script>marker</script><img src="x" onerror="marker">')
    expect(dd.querySelector('iframe')).toBeNull()
    expect(dd.querySelector('script')).toBeNull()
    expect(dd.querySelector('img')).toBeNull()
  })

  it('does not parse a payload that closes the surrounding small element', () => {
    const dd = render('</small><img src="x" onerror="marker"><iframe src="javascript:alert(`xss`)"></iframe>')
    expect(dd.querySelector('img')).toBeNull()
    expect(dd.querySelector('iframe')).toBeNull()
  })
})
