/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { MatDialog } from '@angular/material/dialog'
import { TranslateModule } from '@ngx-translate/core'
import { CookieService } from 'ngy-cookie'
import { of } from 'rxjs'

import { AdministrationComponent } from './administration.component'
import { FeedbackService } from '../Services/feedback.service'
import { UserService } from '../Services/user.service'

const emailMarkup = '</span><img id="pxss" src="x" onerror="document.documentElement.setAttribute(\'data-ran\',\'1\')">'

describe('AdministrationComponent email HTML', () => {
  let fixture: ComponentFixture<AdministrationComponent>

  beforeEach(async () => {
    const userService = {
      find: vi.fn().mockName('UserService.find')
    }
    userService.find.mockReturnValue(of([{ id: 1, email: emailMarkup }]))
    const feedbackService = {
      find: vi.fn().mockName('FeedbackService.find'),
      del: vi.fn().mockName('FeedbackService.del')
    }
    feedbackService.find.mockReturnValue(of([]))
    const cookieService = {
      get: vi.fn().mockName('CookieService.get'),
      put: vi.fn().mockName('CookieService.put')
    }
    cookieService.get.mockReturnValue('false')

    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), AdministrationComponent],
      providers: [
        { provide: MatDialog, useValue: { open: vi.fn() } },
        { provide: UserService, useValue: userService },
        { provide: FeedbackService, useValue: feedbackService },
        { provide: CookieService, useValue: cookieService },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()

    fixture = TestBed.createComponent(AdministrationComponent)
    fixture.detectChanges()
  })

  it('renders a registered email as text in every administration user table', () => {
    const root = fixture.nativeElement as HTMLElement
    const emailCells = root.querySelectorAll('.mat-column-email.mat-cell, .mat-column-email.mat-mdc-cell')

    expect(emailCells.length).toBeGreaterThanOrEqual(2)
    expect(root.querySelector('#pxss')).toBeNull()
    for (const cell of Array.from(emailCells)) {
      expect(cell.querySelector('#pxss')).toBeNull()
      expect(cell.innerHTML).not.toContain('onerror')
      expect(cell.textContent).toContain(emailMarkup)
    }
  })
})
