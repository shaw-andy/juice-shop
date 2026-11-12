/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  waitForInputToHaveValue,
  waitForInputToNotBeEmpty,
  waitForElementToGetClicked,
  waitInMs,
  waitForAngularRouteToBeVisited, waitForLogOut, waitForAdminLogIn
} from '../helpers/helpers'
import { type ChallengeInstruction } from '../'

export const PasswordStrengthInstruction: ChallengeInstruction = {
  name: 'Password Strength',
  hints: [
    {
      text:
        "To start this challenge, you'll have to log out first.",
      fixture: '#navbarAccount',
      unskippable: true,
      resolved: waitForLogOut()
    },
    {
      text:
        "In this challenge we'll try to log into the administrator's user account using his original credentials.",
      fixture: 'app-navbar',
      resolved: waitInMs(7000)
    },
    {
      text:
        "If you don't know it already, you must first find out the admin's email address. The user feedback and product reviews are good places to look into. When you have it, go to the _Login_ page.",
      fixture: 'app-navbar',
      fixtureAfter: true,
      unskippable: true,
      resolved: waitForAngularRouteToBeVisited('login')
    },
    {
      text: "Enter the admin's email address into the **email field**.",
      fixture: '#email',
      unskippable: true,
      resolved: waitForInputToHaveValue('#email', 'admin@juice-sh.op', { replacement: ['juice-sh.op', 'application.domain'] })
    },
    {
      text: 'Now for the password. Lucky for us, the admin chose a really, really, **really** stupid one. Just try any that comes to your mind!',
      fixture: '#password',
      unskippable: true,
      resolved: waitForInputToNotBeEmpty('#password')
    },
    {
      text: 'Okay, now press the _Log in_ button.',
      fixture: '#rememberMe',
      unskippable: true,
      resolved: waitForElementToGetClicked('#loginButton')
    },
    {
      text: "🤦‍♂️ If that didn't work, keep trying! Think of the most common passwords and how someone might spice them up a little with some extra non-letter characters. I'll tell you when you're in.",
      fixture: '#password',
      unskippable: true,
      resolved: waitForAdminLogIn()
    },
    {
      text:
        '🎉 Congratulations! You have been logged in as the **administrator** of the shop thanks to his very ill chosen password!',
      fixture: 'app-navbar',
      resolved: waitInMs(20000)
    }
  ]
}
