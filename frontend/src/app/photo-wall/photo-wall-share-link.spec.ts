/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { MatDividerModule } from '@angular/material/divider'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { MatGridListModule } from '@angular/material/grid-list'
import { MatCardModule } from '@angular/material/card'
import { MatTableModule } from '@angular/material/table'
import { MatPaginatorModule } from '@angular/material/paginator'
import { of } from 'rxjs'
import { MatFormFieldModule } from '@angular/material/form-field'
import { PhotoWallComponent } from './photo-wall.component'
import { PhotoWallService } from '../Services/photo-wall.service'
import { FormsModule, ReactiveFormsModule } from '@angular/forms'
import { ConfigurationService } from '../Services/configuration.service'
import { MatIconModule } from '@angular/material/icon'
import { MatTooltipModule } from '@angular/material/tooltip'
import { MatDialogModule } from '@angular/material/dialog'
import { MatExpansionModule } from '@angular/material/expansion'
import { MatInputModule } from '@angular/material/input'
import { MatSnackBar } from '@angular/material/snack-bar'
import { EventEmitter } from '@angular/core'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

const caption = 'Hi&url=https://attacker.example&'

describe('PhotoWallComponent share links', () => {
    let fixture: ComponentFixture<PhotoWallComponent>
    let photoWallService: { get: ReturnType<typeof vi.fn>, addMemory: ReturnType<typeof vi.fn> }
    let configurationService: { getApplicationConfiguration: ReturnType<typeof vi.fn> }

    beforeEach(async () => {
        configurationService = {
            getApplicationConfiguration: vi.fn().mockName('ConfigurationService.getApplicationConfiguration')
        }
        configurationService.getApplicationConfiguration.mockReturnValue(of({
            application: {
                social: {
                    twitterUrl: 'https://twitter.com/owasp_juiceshop',
                    blueSkyUrl: 'https://bsky.app/profile/owasp-juice.shop',
                    mastodonUrl: 'https://fosstodon.org/@owasp_juiceshop'
                }
            }
        }))
        photoWallService = {
            get: vi.fn().mockName('PhotoWallService.get'),
            addMemory: vi.fn().mockName('PhotoWallService.addMemory')
        }
        photoWallService.get.mockReturnValue(of([{ imagePath: 'a.png', caption }]))
        photoWallService.addMemory.mockReturnValue(of({}))
        const translateService = {
            get: vi.fn().mockName('TranslateService.get'),
            onLangChange: new EventEmitter(),
            onTranslationChange: new EventEmitter(),
            onFallbackLangChange: new EventEmitter(),
            onDefaultLangChange: new EventEmitter()
        }
        translateService.get.mockReturnValue(of({}))

        TestBed.configureTestingModule({
            imports: [RouterTestingModule,
                TranslateModule.forRoot(),
                MatTableModule,
                MatPaginatorModule,
                MatFormFieldModule,
                MatDividerModule,
                MatGridListModule,
                MatCardModule,
                MatIconModule,
                MatTooltipModule,
                MatDialogModule,
                MatExpansionModule,
                FormsModule,
                ReactiveFormsModule,
                MatInputModule,
                PhotoWallComponent],
            providers: [
                { provide: PhotoWallService, useValue: photoWallService },
                { provide: ConfigurationService, useValue: configurationService },
                { provide: TranslateService, useValue: translateService },
                { provide: MatSnackBar, useValue: { open: vi.fn() } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    function shareUrl (selector: string) {
        fixture = TestBed.createComponent(PhotoWallComponent)
        fixture.detectChanges()
        const anchor: HTMLAnchorElement = fixture.nativeElement.querySelector(selector)
        expect(anchor).toBeTruthy()
        return new URL(anchor.href)
    }

    it('keeps a memory caption inside the tweet text parameter', () => {
        const tweet = shareUrl('a[href*="twitter.com/intent/tweet"]')
        expect(tweet.searchParams.get('url')).toBeNull()
        expect([...tweet.searchParams.keys()].filter((key) => key !== 'text' && key !== 'hashtags')).toEqual([])
        expect(tweet.searchParams.get('hashtags')).toBe('appsec')
        expect(tweet.searchParams.get('text')).toContain(caption)
    })

    it('keeps a memory caption inside the bluesky text parameter', () => {
        const post = shareUrl('a[href*="bsky.app/intent/compose"]')
        expect(post.searchParams.get('url')).toBeNull()
        expect([...post.searchParams.keys()]).toEqual(['text'])
        expect(post.searchParams.get('text')).toContain(caption)
    })

    it('keeps a memory caption inside the mastodon text parameter', () => {
        const post = shareUrl('a[href*="mastodonshare.com"]')
        expect(post.searchParams.get('url')).toBeNull()
        expect([...post.searchParams.keys()]).toEqual(['text'])
        expect(post.searchParams.get('text')).toContain(caption)
    })
})
