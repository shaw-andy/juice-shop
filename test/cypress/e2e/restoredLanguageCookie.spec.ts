/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

describe('restored language cookie', () => {
  const chosenPassword = 'placeholder-chosen'
  const currentPassword = 'placeholder-current'
  const otherPassword = 'placeholder-other'

  beforeEach(() => {
    cy.clearLocalStorage()
    cy.setCookie('cookieconsent_status', 'dismiss')
    cy.setCookie('welcomebanner_status', 'dismiss')
    cy.clearCookie('language')
  })

  it('still loads a listed language from a backup', () => {
    const email = 'language-cookie-listed-' + Date.now() + '@example.com'
    signIn(email, currentPassword)
    openBackupDialog()
    chooseBackup({ version: 1, language: 'de' })

    cy.window().its('document.cookie').should((cookie) => {
      expect(decodeURIComponent(String(cookie))).to.include('language=de')
    })
  })

  it('does not let a backup language change the signed-in customer password', () => {
    const email = 'language-cookie-password-' + Date.now() + '@example.com'
    const otherEmail = 'language-cookie-other-' + Date.now() + '@example.com'
    register(otherEmail, otherPassword)
    signIn(email, currentPassword)
    openBackupDialog()
    chooseBackup({
      version: 1,
      language: '../../rest/user/change-password?new=' + chosenPassword + '&repeat=' + chosenPassword + '#'
    })

    cy.window().its('document.cookie').should((cookie) => {
      expect(decodeURIComponent(String(cookie))).to.not.match(/change-password|\.\.|[?#]/)
    })

    let passwordChangeCount = 0
    cy.intercept('GET', /\/rest\/user\/change-password/, () => {
      passwordChangeCount += 1
    })
    cy.reload()
    cy.wait(1000)
    cy.then(() => {
      expect(passwordChangeCount).to.equal(0)
    })

    loginStatus(email, currentPassword).should('eq', 200)
    loginStatus(email, chosenPassword).should('eq', 401)
    loginStatus(otherEmail, otherPassword).should('eq', 200)
    loginStatus(otherEmail, chosenPassword).should('eq', 401)
  })

  it('does not let a backup language call the login-ip endpoint', () => {
    const email = 'language-cookie-ip-' + Date.now() + '@example.com'
    signIn(email, currentPassword)
    openBackupDialog()
    chooseBackup({
      version: 1,
      language: '../../rest/saveLoginIp#'
    })

    cy.window().its('document.cookie').should((cookie) => {
      expect(decodeURIComponent(String(cookie))).to.not.match(/saveLoginIp|\.\.|[?#]/)
    })

    let loginIpCount = 0
    cy.intercept('GET', /\/rest\/saveLoginIp/, () => {
      loginIpCount += 1
    })
    cy.reload()
    cy.wait(1000)
    cy.then(() => {
      expect(loginIpCount).to.equal(0)
    })
  })
})

function register (email: string, password: string): void {
  cy.request('POST', '/api/Users', { email, password }).its('status').should('eq', 201)
}

function signIn (email: string, password: string): void {
  register(email, password)
  cy.request('POST', '/rest/user/login', { email, password }).then((response) => {
    expect(response.status).to.equal(200)
    const token = response.body.authentication.token
    cy.visit('/#/score-board', {
      onBeforeLoad (win) {
        win.localStorage.setItem('token', token)
      }
    })
  })
}

function openBackupDialog (): void {
  cy.get('button[aria-label="Open additional settings dialog"]', { timeout: 20000 }).click({ force: true })
}

function chooseBackup (backup: { version: number, language: string }): void {
  cy.get('score-board-additional-settings-dialog input[type="file"]').selectFile({
    contents: Cypress.Buffer.from(JSON.stringify(backup)),
    fileName: 'backup.json',
    mimeType: 'application/json'
  }, { force: true })
  cy.contains('Backup has been restored from backup.json', { timeout: 10000 }).should('be.visible')
}

function loginStatus (email: string, password: string): Cypress.Chainable<number> {
  return cy.request({
    method: 'POST',
    url: '/rest/user/login',
    body: { email, password },
    failOnStatusCode: false
  }).its('status')
}
