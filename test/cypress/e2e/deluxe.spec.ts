describe('/#/deluxe-membership', () => {
  describe('challenge "freeDeluxeChallenge"', () => {
    it('should upgrade to deluxe for free by making a post request to /rest/deluxe-membership by setting the paymentMode parameter to null', () => {
      cy.login({
        email: 'jim',
        password: 'ncc-1701'
      })
      cy.visit('/#/')
      cy.getCookie('token').then((token) => {
        cy.request({
          url: '/rest/deluxe-membership',
          method: 'POST',
          headers: { Authorization: `Bearer ${token?.value}` }
        }).then((response) => {
          expect(response.body.status).contains('success')
        })
      })
      cy.expectChallengeSolved({ challenge: 'Deluxe Fraud' })
    })
  })
})
