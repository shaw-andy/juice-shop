/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, type OnInit, DestroyRef, type ElementRef, inject, viewChild, ChangeDetectionStrategy } from '@angular/core'
import { takeUntilDestroyed } from '@angular/core/rxjs-interop'
import { type HttpErrorResponse } from '@angular/common/http'
import { ActivatedRoute, RouterLink } from '@angular/router'
import { MatButtonModule } from '@angular/material/button'
import { MatIconModule } from '@angular/material/icon'
import { MatProgressSpinner } from '@angular/material/progress-spinner'
import { TranslateModule } from '@ngx-translate/core'
import { forkJoin, of } from 'rxjs'
import { catchError, switchMap } from 'rxjs/operators'

import { CodeSnippetService, hasSnippetText, type CodeSnippet } from '../Services/code-snippet.service'
import { CodeFixesService } from '../Services/code-fixes.service'
import { ChallengeService } from '../Services/challenge.service'
import { CodingChallengeFindItComponent } from './components/coding-challenge-find-it/coding-challenge-find-it.component'
import { CodingChallengeFixItComponent } from './components/coding-challenge-fix-it/coding-challenge-fix-it.component'

function snippetErrorMessage (response: unknown): string {
  const body = (response as { error?: unknown } | null)?.error
  if (typeof body === 'string') return body
  const message = (body as { error?: unknown } | null)?.error
  if (typeof message === 'string') return message
  return 'Code snippet could not be loaded'
}

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'coding-challenge-page',
  templateUrl: './coding-challenge-page.component.html',
  styleUrls: ['./coding-challenge-page.component.scss'],
  imports: [MatButtonModule, MatIconModule, MatProgressSpinner, RouterLink, TranslateModule, CodingChallengeFindItComponent, CodingChallengeFixItComponent]
})
export class CodingChallengePageComponent implements OnInit {
  private readonly route = inject(ActivatedRoute)
  private readonly destroyRef = inject(DestroyRef)
  private readonly codeSnippetService = inject(CodeSnippetService)
  private readonly codeFixesService = inject(CodeFixesService)
  private readonly challengeService = inject(ChallengeService)

  readonly fixItSection = viewChild<ElementRef>('fixItSection')

  public challengeKey: string
  public challengeName: string
  public snippet: CodeSnippet = null
  public error: string = null
  public fixes: string[] = null
  public findItSolved = false
  public fixItSolved = false
  public isLoaded = false

  ngOnInit (): void {
    this.route.params.pipe(
      switchMap((params) => {
        this.challengeKey = params['challengeKey']
        this.isLoaded = false
        return forkJoin({
          challenges: this.challengeService.find({ sort: 'name' }),
          snippet: this.codeSnippetService.get(this.challengeKey).pipe(
            catchError((err: HttpErrorResponse) => of(err))
          ),
          fixes: this.codeFixesService.get(this.challengeKey).pipe(
            catchError(() => of(null))
          )
        })
      }),
      takeUntilDestroyed(this.destroyRef)
    ).subscribe(({ challenges, snippet, fixes }) => {
      const challenge = challenges.find(c => c.key === this.challengeKey)
      if (challenge) {
        this.challengeName = challenge.name
        this.findItSolved = challenge.codingChallengeStatus >= 1
        this.fixItSolved = challenge.codingChallengeStatus >= 2
      }
      if (hasSnippetText(snippet)) {
        this.snippet = snippet
        this.error = null
      } else {
        this.snippet = null
        this.error = snippetErrorMessage(snippet)
      }
      this.fixes = fixes?.fixes ?? null
      this.isLoaded = true
    })
  }

  onFindItSolved (): void {
    this.findItSolved = true
    if (this.fixes !== null) {
      setTimeout(() => {
        this.fixItSection()?.nativeElement?.scrollIntoView({ behavior: 'smooth' })
      }, 300)
    }
  }

  onFixItSolved (): void {
    this.fixItSolved = true
  }
}
