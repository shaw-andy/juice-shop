/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ChildProcess, spawn } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { environment } from '../../environments/environment'
import { RequestInterceptor } from '../Services/request.interceptor'
import { ChangePasswordComponent } from './change-password.component'

const repoRoot = findRepoRoot(process.cwd())
const CURRENT_PLACEHOLDER = 'CURRENT_PLACEHOLDER'
const AMPERSAND_PASSWORD = 'N&EW_PART_TWO_PLACEHOLDER'
const PLUS_PASSWORD = 'NEW_PART_ONE+NEW_PART_TWO'
const HASH_PASSWORD = 'NEW_PART_ONE#NEW_PART_TWO'
const CURRENT_WITH_AMPERSAND = 'CURRENT_PART_ONE&CURRENT_PART_TWO'
const REPLACEMENT_PLACEHOLDER = 'REPLACEMENT_PLACEHOLDER'

describe('change-password query encoding', () => {
  let baseUrl: string
  let harness: ChildProcess
  let harnessLog: string
  let fixture: ComponentFixture<ChangePasswordComponent>
  let component: ChangePasswordComponent

  beforeAll(async () => {
    const portFile = join(mkdtempSync(join(tmpdir(), 'change-password-encoding-')), 'port')
    harnessLog = ''
    harness = spawn(process.execPath, [
      '--import', './test/api/helpers/test-env.mjs',
      '--import', 'tsx',
      './test/api/helpers/change-password-encoding-harness.ts'
    ], {
      cwd: repoRoot,
      env: { ...process.env, NODE_ENV: 'test', CHANGE_PASSWORD_ENCODING_PORT_FILE: portFile },
      stdio: ['ignore', 'pipe', 'pipe']
    })
    const append = (chunk: Buffer) => {
      harnessLog += chunk.toString()
    }
    harness.stdout?.on('data', append)
    harness.stderr?.on('data', append)

    const port = await waitForPort(portFile, () => harness.exitCode, () => harnessLog)
    baseUrl = `http://127.0.0.1:${port}`
    environment.hostServer = baseUrl
  }, 120000)

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), ChangePasswordComponent],
      providers: [
        provideHttpClient(withInterceptorsFromDi()),
        { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true }
      ]
    }).compileComponents()

    fixture = TestBed.createComponent(ChangePasswordComponent)
    component = fixture.componentInstance
    fixture.detectChanges()
  })

  afterAll(() => {
    harness?.kill('SIGTERM')
  })

  it('stores an ampersand password exactly as entered on the change-password page', async () => {
    const email = uniqueEmail('ampersand')
    await registerAndSignIn(baseUrl, email, CURRENT_PLACEHOLDER)

    submitChange(CURRENT_PLACEHOLDER, AMPERSAND_PASSWORD)
    await waitForChangeToSettle(component)

    expect(component.error).toBeUndefined()
    expect(typeof component.confirmation).toBe('string')
    expect((await login(baseUrl, email, AMPERSAND_PASSWORD)).status).toBe(200)
    expect((await login(baseUrl, email, 'N')).status).not.toBe(200)
  })

  it('stores a plus-sign password exactly as entered on the change-password page', async () => {
    const email = uniqueEmail('plus')
    await registerAndSignIn(baseUrl, email, CURRENT_PLACEHOLDER)

    submitChange(CURRENT_PLACEHOLDER, PLUS_PASSWORD)
    await waitForChangeToSettle(component)

    expect(component.error).toBeUndefined()
    expect(typeof component.confirmation).toBe('string')
    expect((await login(baseUrl, email, PLUS_PASSWORD)).status).toBe(200)
    expect((await login(baseUrl, email, 'NEW_PART_ONE NEW_PART_TWO')).status).not.toBe(200)
  })

  it('stores a hash-sign password exactly as entered on the change-password page', async () => {
    const email = uniqueEmail('hash')
    await registerAndSignIn(baseUrl, email, CURRENT_PLACEHOLDER)

    submitChange(CURRENT_PLACEHOLDER, HASH_PASSWORD)
    await waitForChangeToSettle(component)

    expect(component.error).toBeUndefined()
    expect(typeof component.confirmation).toBe('string')
    expect((await login(baseUrl, email, HASH_PASSWORD)).status).toBe(200)
  })

  it('accepts the current password when it contains an ampersand', async () => {
    const email = uniqueEmail('current')
    await registerAndSignIn(baseUrl, email, CURRENT_WITH_AMPERSAND)

    submitChange(CURRENT_WITH_AMPERSAND, REPLACEMENT_PLACEHOLDER)
    await waitForChangeToSettle(component)

    expect(component.error).toBeUndefined()
    expect(typeof component.confirmation).toBe('string')
    expect((await login(baseUrl, email, REPLACEMENT_PLACEHOLDER)).status).toBe(200)
    expect((await login(baseUrl, email, CURRENT_WITH_AMPERSAND)).status).not.toBe(200)
  })

  function submitChange (current: string, chosen: string) {
    component.passwordControl.setValue(current)
    component.newPasswordControl.setValue(chosen)
    component.repeatNewPasswordControl.setValue(chosen)
    fixture.detectChanges()

    const button = fixture.nativeElement.querySelector('#changeButton') as HTMLButtonElement
    expect(button.disabled).toBe(false)
    button.click()
    fixture.detectChanges()
  }
})

function uniqueEmail (label: string) {
  return `change-password-${label}-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
}

async function registerAndSignIn (baseUrl: string, email: string, current: string) {
  const registered = await fetch(`${baseUrl}/api/Users/`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email,
      password: current,
      passwordRepeat: current,
      securityQuestion: null,
      securityAnswer: null
    })
  })
  if (registered.status !== 201 && registered.status !== 200) {
    throw new Error(`Failed to register '${email}': ${registered.status}`)
  }

  const signedIn = await login(baseUrl, email, current)
  if (signedIn.status !== 200) {
    throw new Error(`Failed to sign in '${email}': ${signedIn.status}`)
  }
  const body = await signedIn.json() as { authentication: { token: string } }
  localStorage.setItem('token', body.authentication.token)
  localStorage.setItem('email', email)
}

async function login (baseUrl: string, email: string, password: string) {
  return await fetch(`${baseUrl}/rest/user/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
}

async function waitForChangeToSettle (component: ChangePasswordComponent) {
  const started = Date.now()
  while (component.confirmation === undefined && component.error === undefined) {
    if (Date.now() - started > 10000) {
      throw new Error('change-password page did not settle')
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 20)
    })
  }
}

function findRepoRoot (start: string) {
  let dir = start
  for (let i = 0; i < 6; i++) {
    if (existsSync(join(dir, 'test/api/helpers/setup.ts'))) {
      return dir
    }
    const parent = dirname(dir)
    if (parent === dir) {
      break
    }
    dir = parent
  }
  throw new Error(`Could not find the Juice Shop repository from ${start}`)
}

async function waitForPort (portFile: string, exitCode: () => number | null, readStderr: () => string) {
  const started = Date.now()
  while (Date.now() - started < 90000) {
    if (existsSync(portFile)) {
      return readFileSync(portFile, 'utf8').trim()
    }
    if (exitCode() != null) {
      throw new Error(`change-password encoding harness exited ${exitCode()}: ${readStderr()}`)
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 100)
    })
  }
  throw new Error(`change-password encoding harness did not listen: ${readStderr()}`)
}
