/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, NgZone, type OnInit, inject, ChangeDetectionStrategy } from '@angular/core'
import { UserService } from '../Services/user.service'
import { Router } from '@angular/router'
import { ConfigurationService } from '../Services/configuration.service'
import { MatIconModule } from '@angular/material/icon'
import { MatButtonModule } from '@angular/material/button'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'app-deluxe-user',
  templateUrl: './deluxe-user.component.html',
  styleUrls: ['./deluxe-user.component.scss'],
  imports: [MatCardModule, TranslateModule, MatButtonModule, MatIconModule]
})

export class DeluxeUserComponent implements OnInit {
  private readonly router = inject(Router)
  private readonly userService = inject(UserService)
  private readonly configurationService = inject(ConfigurationService)
  private readonly ngZone = inject(NgZone)

  public membershipCost = 0
  public error?: string = undefined
  public applicationName = 'OWASP Juice Shop'
  public logoSrc = 'assets/public/images/JuiceShop_Logo.png'

  public SHOWCASES = [
    {
      icon: 'slideshow',
      name: 'LABEL_DEALS_OFFERS',
      description: 'DESCRIPTION_DEALS_OFFERS'
    },
    {
      icon: 'directions_car',
      name: 'LABEL_FREE_FAST_DELIVERY',
      description: 'DESCRIPTION_FREE_FAST_DELIVERY'
    },
    {
      icon: 'add',
      name: 'LABEL_UNLIMITED_PURCHASE',
      description: 'DESCRIPTION_UNLIMITED_PURCHASE'
    }
  ] as const

  ngOnInit (): void {
    this.configurationService.getApplicationConfiguration().subscribe({
      next: (config) => {
        if (config?.application) {
          if (config.application.name) {
            this.applicationName = config.application.name
          }
          if (config.application.logo) {
            let logo: string = config.application.logo

            if (logo.substring(0, 4) === 'http') {
              logo = decodeURIComponent(logo.substring(logo.lastIndexOf('/') + 1))
            }
            this.logoSrc = `assets/public/images/${logo}`
          }
        }
      },
      error: (err) => { console.log(err) }
    })
    this.userService.deluxeStatus().subscribe({
      next: (res) => {
        this.membershipCost = res.membershipCost
      },
      error: (err) => {
        this.error = err.error.error
      }
    })
  }

  upgradeToDeluxe () {
    this.ngZone.run(async () => await this.router.navigate(['/payment', 'deluxe']))
  }
}
