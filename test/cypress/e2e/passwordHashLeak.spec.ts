describe('challenge "passwordHashLeakChallenge"', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash via fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password'
    }).then((res) => {
      expect(res.body.user.password).to.equal(undefined)
    })
  })
})
