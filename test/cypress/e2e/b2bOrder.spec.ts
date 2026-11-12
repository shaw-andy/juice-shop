describe('/b2b/v2/order', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  const postOrderLines = (orderLinesData: string) => {
    cy.window().then((win) => {
      cy.request({
        method: 'POST',
        url: '/b2b/v2/orders/',
        failOnStatusCode: false,
        headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` },
        body: { orderLinesData }
      }).its('status').should('eq', 400)
    })
  }

  it('should reject an infinite loop payload instead of evaluating it', () => {
    postOrderLines('(function dos() { while(true); })()')
  })

  it('should reject a recursive regular expression payload instead of evaluating it', () => {
    postOrderLines("/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')")
  })
})
