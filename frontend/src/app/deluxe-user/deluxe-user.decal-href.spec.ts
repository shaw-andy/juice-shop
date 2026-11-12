/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { HashLocationStrategy, type PlatformLocation } from '@angular/common'
import { ActivatedRoute, DefaultUrlSerializer, Router } from '@angular/router'
import { TranslateModule } from '@ngx-translate/core'
import { of } from 'rxjs'

import { DeluxeUserComponent } from './deluxe-user.component'
import { ConfigurationService } from '../Services/configuration.service'
import { UserService } from '../Services/user.service'
import { SocketIoService } from '../Services/socket-io.service'

const SHOP_ORIGIN = 'http://localhost:3000/'
const CONFIGURED_LOGO = 'JuiceShop_Logo.png'
const REMOTE_IMAGE = 'https://attacker.example/decal.png?x=https://github.com/juice-shop/juice-shop'
const TRAVERSAL_DECAL = `../../../redirect?to=${REMOTE_IMAGE}`

describe('DeluxeUserComponent testDecal image href', () => {
  afterEach(() => {
    TestBed.resetTestingModule()
  })

  it('keeps the configured local logo on every membership sticker when testDecal is absent', async () => {
    const fixture = await renderMembership(undefined, CONFIGURED_LOGO)

    for (const href of boundDecalHrefs(fixture)) {
      expect(href).toBe(`assets/public/images/${CONFIGURED_LOGO}`)
      expectLocalImageHref(href)
    }
  })

  it('does not let a testDecal path walk the membership stickers onto the redirect route', async () => {
    const fixture = await renderMembership(TRAVERSAL_DECAL, CONFIGURED_LOGO)

    for (const href of boundDecalHrefs(fixture)) {
      expectLocalImageHref(href)
    }
  })

  it('does not let a testDecal path walk the membership stickers onto the redirect route when the configured logo is an absolute URL', async () => {
    const fixture = await renderMembership(TRAVERSAL_DECAL, 'https://cdn.example/themes/Logo.png')

    for (const href of boundDecalHrefs(fixture)) {
      expectLocalImageHref(href)
    }
  })

  it('does not let a backslash testDecal path walk the membership stickers onto the redirect route', async () => {
    const fixture = await renderMembership(`..\\..\\..\\redirect?to=${REMOTE_IMAGE}`, CONFIGURED_LOGO)

    for (const href of boundDecalHrefs(fixture)) {
      expectLocalImageHref(href)
    }
  })

  it('does not place an absolute testDecal URL into the membership sticker hrefs', async () => {
    const fixture = await renderMembership(REMOTE_IMAGE, CONFIGURED_LOGO)

    for (const href of boundDecalHrefs(fixture)) {
      expectLocalImageHref(href)
    }
  })
})

function membershipQueryParams (decal: string): { testDecal: string } {
  const platform = { hash: `#/deluxe-membership?testDecal=${encodeURIComponent(decal)}` } as PlatformLocation
  const internalPath = new HashLocationStrategy(platform).path()
  const testDecal = new DefaultUrlSerializer().parse(internalPath).queryParams.testDecal
  if (typeof testDecal !== 'string') {
    throw new Error('testDecal was not a single query value')
  }
  return { testDecal }
}

async function renderMembership (decal: string | undefined, logo: string): Promise<ComponentFixture<DeluxeUserComponent>> {
  const configurationService = {
    getApplicationConfiguration: vi.fn().mockReturnValue(of({
      application: { name: 'OWASP Juice Shop', logo }
    }))
  }
  const userService = {
    deluxeStatus: vi.fn().mockReturnValue(of({ membershipCost: 0 }))
  }

  await TestBed.configureTestingModule({
    imports: [TranslateModule.forRoot(), DeluxeUserComponent],
    providers: [
      { provide: UserService, useValue: userService },
      { provide: ConfigurationService, useValue: configurationService },
      {
        provide: ActivatedRoute,
        useValue: { snapshot: { queryParams: decal === undefined ? {} : membershipQueryParams(decal) } }
      },
      { provide: Router, useValue: { navigate: vi.fn() } satisfies Partial<Router> },
      { provide: SocketIoService, useValue: { socket: () => ({ emit: () => undefined }) } }
    ]
  }).compileComponents()

  const fixture = TestBed.createComponent(DeluxeUserComponent)
  fixture.detectChanges()
  return fixture
}

function boundDecalHrefs (fixture: ComponentFixture<DeluxeUserComponent>): string[] {
  const images = Array.from(fixture.nativeElement.querySelectorAll('image')) as SVGImageElement[]
  const hrefs = images.map(image => image.getAttribute('href'))
  const bound = hrefs.filter(href => href !== 'assets/public/images/deluxe/blankBoxes.png')
  expect(new Set(bound).size).toBe(1)
  expect(bound).toHaveLength(5)
  return bound.filter((href): href is string => typeof href === 'string')
}

function expectLocalImageHref (href: string): void {
  expect(href).not.toContain('..')
  expect(href).not.toContain('\\')
  expect(href).not.toContain('?')
  expect(href).not.toContain('#')
  expect(href).not.toContain('://')
  expect(href).not.toContain('redirect')
  const resolved = new URL(href, SHOP_ORIGIN)
  expect(resolved.origin).toBe('http://localhost:3000')
  expect(resolved.pathname.startsWith('/assets/public/images/')).toBe(true)
  const name = resolved.pathname.slice('/assets/public/images/'.length)
  expect(name).toMatch(/^[A-Za-z0-9._-]+$/)
  expect(resolved.search).toBe('')
  expect(resolved.hash).toBe('')
}
