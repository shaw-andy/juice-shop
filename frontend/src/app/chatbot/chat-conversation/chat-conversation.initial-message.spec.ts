/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { HashLocationStrategy, Location, LocationStrategy, PlatformLocation } from '@angular/common'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { Component, provideZoneChangeDetection } from '@angular/core'
import { Router, RouterOutlet, UrlSerializer } from '@angular/router'
import { TranslateModule } from '@ngx-translate/core'
import { CookieModule } from 'ngy-cookie'
import { of } from 'rxjs'
import { Routing } from '../../app.routing'
import { LoginGuard } from '../../app.guard'
import { ConfigurationService } from '../../Services/configuration.service'
import { ConversationStorageService } from '../../Services/conversation-storage.service'
import { ChatConversationComponent } from './chat-conversation.component'

const CHAT_URL = 'http://localhost:3000/rest/chat'
const STORAGE_KEY = 'juiceshop_chat_conversations'

@Component({
  selector: 'app-conversation-initial-message-host',
  template: '<router-outlet />',
  imports: [RouterOutlet]
})
class ConversationInitialMessageHost {}

interface StoredConversationRecord {
  id: string
  title: unknown
  messages: { role: string, content: unknown, error?: boolean }[]
}

describe('ChatConversationComponent repeated initialMessage', () => {
  let httpMock: HttpTestingController
  let fixture: ComponentFixture<ConversationInitialMessageHost>
  let router: Router
  const rejections: unknown[] = []
  const consoleErrors: unknown[][] = []
  let consoleErrorSpy: { mockRestore: () => void }

  const onRejection = (event: PromiseRejectionEvent) => {
    rejections.push(event.reason)
    event.preventDefault()
  }

  beforeEach(async () => {
    localStorage.clear()
    rejections.length = 0
    consoleErrors.length = 0
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args)
    })
    window.addEventListener('unhandledrejection', onRejection)
    window.history.replaceState(null, '', 'http://localhost:3000/')

    await TestBed.configureTestingModule({
      imports: [
        Routing,
        TranslateModule.forRoot(),
        CookieModule.forRoot(),
        ConversationInitialMessageHost
      ],
      providers: [
        provideZoneChangeDetection(),
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: LocationStrategy, useClass: HashLocationStrategy },
        {
          provide: Location,
          useFactory: (strategy: LocationStrategy) => new Location(strategy),
          deps: [LocationStrategy]
        },
        LoginGuard,
        {
          provide: ConfigurationService,
          useValue: {
            getApplicationConfiguration: () => of({
              application: { chatBot: { name: 'Juicy', avatar: 'JuicyBot.png' } }
            })
          }
        }
      ]
    }).compileComponents()

    httpMock = TestBed.inject(HttpTestingController)
    router = TestBed.inject(Router)
    fixture = TestBed.createComponent(ConversationInitialMessageHost)
    fixture.detectChanges()
  })

  afterEach(() => {
    window.removeEventListener('unhandledrejection', onRejection)
    consoleErrorSpy.mockRestore()
    localStorage.clear()
    httpMock.verify()
  })

  it('opens the conversation for a visitor with no token', () => {
    localStorage.removeItem('token')
    const chatbot = router.config.find(route => route.path === 'chatbot')
    const conversation = chatbot?.children?.find(route => route.path === 'conversation/:id')

    expect(chatbot).toBeTruthy()
    expect(conversation?.component).toBe(ChatConversationComponent)
    expect(chatbot?.canActivate).toBeUndefined()
    expect(conversation?.canActivate).toBeUndefined()
  })

  it('keeps the conversation usable when the hash link repeats initialMessage', async () => {
    const opened = await openHashLink('/chatbot/conversation/repeated-conv?initialMessage=alpha&initialMessage=beta')

    expect(opened.internalPath).toContain('initialMessage=alpha')
    expect(opened.internalPath).toContain('initialMessage=beta')
    expect(opened.parsedInitialMessage).toEqual(['alpha', 'beta'])
    expect(safetyProblems(opened)).toEqual([])
  })

  it('keeps the conversation usable when initialMessage is repeated enough to exceed a title limit', async () => {
    const values = Array.from({ length: 51 }, (_, index) => `m${index}`)
    const query = values.map(value => `initialMessage=${value}`).join('&')
    const opened = await openHashLink(`/chatbot/conversation/long-conv?${query}`)

    expect(opened.parsedInitialMessage).toEqual(values)
    expect(safetyProblems(opened)).toEqual([])
  })

  it('still delivers one initialMessage string from a hash link', async () => {
    const opened = await openHashLink('/chatbot/conversation/string-conv?initialMessage=hello')

    expect(opened.parsedInitialMessage).toBe('hello')
    expect(opened.renderError).toBeUndefined()
    expect(opened.activated).toBe(true)
    expect(opened.posted).toHaveLength(1)
    expect(opened.posted[0]).toEqual({ messages: [{ role: 'user', content: 'hello' }] })
    const stored = opened.stored.find(conversation => conversation.id === 'string-conv')
    expect(stored?.messages.find(message => message.role === 'user')?.content).toBe('hello')
    expect(typeof stored?.title).toBe('string')
  })

  it('renders a conversation reopened from storage when a message body is not a string', async () => {
    const storage = TestBed.inject(ConversationStorageService)
    storage.save({
      id: 'poisoned-conv',
      title: 'poisoned',
      messages: [
        { role: 'user', content: ['alpha', 'beta'] as unknown as string },
        { role: 'assistant', content: ['nope'] as unknown as string, error: true }
      ],
      createdAt: 1,
      updatedAt: 2
    })
    const reloaded = storage.getById('poisoned-conv')
    expect(reloaded?.messages[0].content).toEqual(['alpha', 'beta'])
    expect(reloaded?.messages[1].content).toEqual(['nope'])

    const opened = await openHashLink('/chatbot/conversation/poisoned-conv')

    expect(opened.parsedInitialMessage).toBeUndefined()
    expect(opened.activated).toBe(true)
    expect(opened.renderError).toBeUndefined()
    expect(opened.rejections).toEqual([])
    expect(templateTrimFailures(opened.consoleErrors)).toEqual([])
    expect(opened.native.querySelector('.chat-window')).toBeTruthy()

    const conversationDebug = fixture.debugElement.query(de => de.componentInstance instanceof ChatConversationComponent)
    const conversation = conversationDebug.componentInstance as ChatConversationComponent
    conversation.messages.set([
      { role: 'user', content: ['alpha', 'beta'] as unknown as string },
      { role: 'assistant', content: ['nope'] as unknown as string, error: true }
    ])
    expect(() => { fixture.detectChanges() }).not.toThrow()
    expect(templateTrimFailures(consoleErrors)).toEqual([])
    const bubbles = opened.native.querySelectorAll('.message-content')
    expect(bubbles.length).toBeGreaterThan(0)
    for (const bubble of Array.from(bubbles)) {
      expect(typeof bubble.textContent).toBe('string')
    }
  })

  async function openHashLink (pathAndQuery: string) {
    localStorage.removeItem('token')
    const hash = pathAndQuery.startsWith('#') ? pathAndQuery : `#${pathAndQuery}`
    TestBed.inject(PlatformLocation).replaceState(null, '', `http://localhost:3000/${hash}`)
    const internalPath = TestBed.inject(Location).path(true)
    const parsedInitialMessage = TestBed.inject(UrlSerializer).parse(internalPath).queryParams.initialMessage
    let renderError: unknown
    try {
      await router.navigateByUrl(internalPath)
      fixture.detectChanges()
    } catch (err) {
      renderError = err
    }

    const posted: unknown[] = []
    for (const req of httpMock.match(request => request.url === CHAT_URL)) {
      posted.push(req.request.body)
      req.flush('data: [DONE]\n\n', { status: 500, statusText: 'Server Error' })
    }

    try {
      await fixture.whenStable()
    } catch (err) {
      renderError ??= err
    }
    await new Promise(resolve => setTimeout(resolve, 0))
    try {
      fixture.detectChanges()
    } catch (err) {
      renderError ??= err
    }

    const activated = fixture.debugElement.query(de => de.componentInstance instanceof ChatConversationComponent) != null
    return {
      internalPath,
      parsedInitialMessage,
      renderError,
      posted,
      stored: readStored(),
      activated,
      rejections: [...rejections],
      consoleErrors: consoleErrors.slice(),
      native: fixture.nativeElement as HTMLElement
    }
  }
})

function readStored (): StoredConversationRecord[] {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return []
  return JSON.parse(raw) as StoredConversationRecord[]
}

function templateTrimFailures (consoleErrors: unknown[][]): string[] {
  return consoleErrors
    .map(args => args.map(arg => String(arg)).join(' '))
    .filter(message => message.includes('trim'))
}

function safetyProblems (opened: {
  renderError: unknown
  rejections: unknown[]
  posted: unknown[]
  stored: StoredConversationRecord[]
  activated: boolean
  consoleErrors: unknown[][]
  native: HTMLElement
}): string[] {
  const problems: string[] = []
  if (!opened.activated) problems.push('conversation page did not activate')
  if (!opened.native.querySelector('.chat-window')) problems.push('chat window did not render')
  if (opened.renderError) problems.push(`render threw: ${String(opened.renderError)}`)
  for (const reason of opened.rejections) problems.push(`async failure: ${String(reason)}`)
  for (const message of templateTrimFailures(opened.consoleErrors)) problems.push(`template error: ${message}`)
  for (const body of opened.posted) {
    const messages = (body as { messages?: { content: unknown }[] }).messages ?? []
    for (const message of messages) {
      if (typeof message.content !== 'string') {
        problems.push(`chat request content was ${Object.prototype.toString.call(message.content)}`)
      }
    }
  }
  for (const conversation of opened.stored) {
    if (typeof conversation.title !== 'string') {
      problems.push(`stored title was ${Object.prototype.toString.call(conversation.title)}`)
    }
    for (const message of conversation.messages) {
      if (typeof message.content !== 'string') {
        problems.push(`stored content was ${Object.prototype.toString.call(message.content)}`)
      }
    }
  }
  return problems
}
