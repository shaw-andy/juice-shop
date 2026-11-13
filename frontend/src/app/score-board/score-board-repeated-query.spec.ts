/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { ChangeDetectionStrategy, Component, ErrorHandler } from '@angular/core'
import { BrowserPlatformLocation, HashLocationStrategy, Location, LocationStrategy, PlatformLocation } from '@angular/common'
import { Router, RouterModule, RouterOutlet, NavigationEnd } from '@angular/router'
import { TranslateModule } from '@ngx-translate/core'
import { filter, firstValueFrom } from 'rxjs'

import { ChallengeService } from '../Services/challenge.service'
import { ConfigurationService, type Config } from '../Services/configuration.service'
import { HintService } from '../Services/hint.service'
import { SocketIoService } from '../Services/socket-io.service'
import { type Challenge } from '../Models/challenge.model'
import { ScoreBoardComponent } from './score-board.component'

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'app-score-board-repeated-query-host',
  template: '<router-outlet></router-outlet>',
  imports: [RouterOutlet]
})
class ScoreBoardRepeatedQueryHostComponent {}

class RecordingErrorHandler implements ErrorHandler {
  errors: unknown[] = []

  handleError (error: unknown): void {
    this.errors.push(error)
  }
}

function createChallenge (overwrites: Partial<Challenge>): Challenge {
  return {
    name: 'placeholder',
    key: 'placeholder',
    category: 'category-blue',
    difficulty: 1,
    description: 'placeholder description',
    tags: 'easy',
    disabledEnv: null,
    solved: false,
    tutorialOrder: null,
    hasTutorial: false,
    hasSnippet: false,
    codingChallengeStatus: 0,
    mitigationUrl: '',
    hasCodingChallenge: false,
    ...overwrites
  }
}

const CHALLENGES: Challenge[] = [
  createChallenge({
    name: 'Alpha Challenge',
    key: 'alpha-challenge',
    category: 'category-blue',
    difficulty: 1,
    description: 'alpha only text',
    tags: 'easy',
    solved: true
  }),
  createChallenge({
    name: 'Beta Challenge',
    key: 'beta-challenge',
    category: 'category-red',
    difficulty: 6,
    description: 'beta only text',
    tags: 'hard',
    solved: false,
    disabledEnv: 'Docker'
  })
]

const APPLICATION_CONFIGURATION = {
  challenges: {
    restrictToTutorialsFirst: true,
    codingChallengesEnabled: 'solved',
    showHints: true,
    showMitigations: true
  },
  ctf: {
    showFlagsInNotifications: true
  },
  hackingInstructor: {
    isEnabled: false
  }
} as Config

describe('ScoreBoardComponent repeated query parameters', () => {
  let errorHandler: RecordingErrorHandler

  beforeEach(async () => {
    errorHandler = new RecordingErrorHandler()
    await TestBed.configureTestingModule({
      imports: [
        TranslateModule.forRoot(),
        RouterModule.forRoot([
          { path: 'score-board', component: ScoreBoardComponent }
        ], { useHash: true }),
        ScoreBoardRepeatedQueryHostComponent
      ],
      providers: [
        ChallengeService,
        HintService,
        ConfigurationService,
        { provide: SocketIoService, useValue: { socket: () => ({ on () {}, off () {} }) } },
        { provide: PlatformLocation, useClass: BrowserPlatformLocation },
        { provide: LocationStrategy, useClass: HashLocationStrategy },
        Location,
        { provide: ErrorHandler, useValue: errorHandler },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents()
  })

  afterEach(() => {
    TestBed.inject(HttpTestingController).verify()
    window.location.hash = ''
  })

  async function openScoreboard (hash: string): Promise<{ fixture: ComponentFixture<ScoreBoardRepeatedQueryHostComponent>, scoreboard: ScoreBoardComponent }> {
    window.location.hash = hash
    const fixture = TestBed.createComponent(ScoreBoardRepeatedQueryHostComponent)
    fixture.detectChanges()
    const router = TestBed.inject(Router)
    const navigated = firstValueFrom(router.events.pipe(filter((event) => event instanceof NavigationEnd)))
    router.initialNavigation()
    await navigated
    fixture.detectChanges()
    flushChallengeLoad()
    await fixture.whenStable()
    fixture.detectChanges()
    const scoreboardDebug = fixture.debugElement.query(By.directive(ScoreBoardComponent))
    if (scoreboardDebug === null) {
      throw new Error(`Scoreboard was not created. url=${router.url} html=${fixture.nativeElement.innerHTML}`)
    }
    const scoreboard = scoreboardDebug.componentInstance as ScoreBoardComponent
    return { fixture, scoreboard }
  }

  function flushChallengeLoad (): void {
    const http = TestBed.inject(HttpTestingController)
    const requests = http.match(() => true)
    const challenges = requests.find((request) => request.request.url.startsWith('http://localhost:3000/api/Challenges/'))
    const hints = requests.find((request) => request.request.url.startsWith('http://localhost:3000/api/Hints/'))
    const configuration = requests.find((request) => request.request.url === 'http://localhost:3000/rest/admin/application-configuration')
    if (challenges === undefined || hints === undefined || configuration === undefined) {
      throw new Error(`Missing scoreboard requests: ${requests.map((request) => request.request.url).join(', ')}`)
    }
    challenges.flush({ data: CHALLENGES })
    hints.flush({ data: [] })
    configuration.flush({ config: APPLICATION_CONFIGURATION })
  }

  function visibleChallengeNames (fixture: ComponentFixture<ScoreBoardRepeatedQueryHostComponent>): string[] {
    return Array.from(fixture.nativeElement.querySelectorAll('challenge-card'))
      .map((card: Element) => card.textContent ?? '')
  }

  it('loads the challenge list for a single searchQuery', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?searchQuery=alpha')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.searchQuery).toBe('alpha')
    expect(scoreboard.filteredChallenges.map((challenge) => challenge.key)).toEqual(['alpha-challenge'])
    expect(visibleChallengeNames(fixture).join(' ')).toContain('Alpha Challenge')
    expect(visibleChallengeNames(fixture).join(' ')).not.toContain('Beta Challenge')
  })

  it('leaves the loading spinner when searchQuery is repeated', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?searchQuery=alpha&searchQuery=beta')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.searchQuery).toBe('alpha')
    expect(scoreboard.filteredChallenges.map((challenge) => challenge.key)).toEqual(['alpha-challenge'])
    const names = visibleChallengeNames(fixture).join(' ')
    expect(names).toContain('Alpha Challenge')
    expect(names).not.toContain('Beta Challenge')
  })

  it('loads challenges when difficulties is repeated', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?difficulties=1&difficulties=6')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.difficulties).toEqual([1])
    const names = visibleChallengeNames(fixture).join(' ')
    expect(names).toContain('Alpha Challenge')
    expect(names).not.toContain('Beta Challenge')
  })

  it('loads challenges when tags is repeated', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?tags=easy&tags=hard')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.tags).toEqual(['easy'])
    const names = visibleChallengeNames(fixture).join(' ')
    expect(names).toContain('Alpha Challenge')
    expect(names).not.toContain('Beta Challenge')
  })

  it('loads challenges when categories is repeated', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?categories=category-blue&categories=category-red')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.categories).toEqual(['category-blue'])
    const names = visibleChallengeNames(fixture).join(' ')
    expect(names).toContain('Alpha Challenge')
    expect(names).not.toContain('Beta Challenge')
  })

  it('loads challenges when status is repeated', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?status=solved&status=unsolved')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.status).toBe('solved')
    const names = visibleChallengeNames(fixture).join(' ')
    expect(names).toContain('Alpha Challenge')
    expect(names).not.toContain('Beta Challenge')
  })

  it('keeps disabled challenges visible when showDisabledChallenges is repeated with true first', async () => {
    const { fixture, scoreboard } = await openScoreboard('#/score-board?showDisabledChallenges=true&showDisabledChallenges=false')

    expect(errorHandler.errors).toEqual([])
    expect(scoreboard.isInitialized).toBe(true)
    expect(fixture.nativeElement.querySelector('mat-spinner')).toBeNull()
    expect(scoreboard.filterSetting.showDisabledChallenges).toBe(true)
    const names = visibleChallengeNames(fixture).join(' ')
    expect(names).toContain('Alpha Challenge')
    expect(names).toContain('Beta Challenge')
  })
})
