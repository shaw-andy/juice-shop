/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, inject, OnInit, ChangeDetectionStrategy } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'
import { UserService } from '../Services/user.service'

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'app-last-login-ip',
  templateUrl: './last-login-ip.component.html',
  styleUrls: ['./last-login-ip.component.scss'],
  imports: [MatCardModule, TranslateModule]
})

export class LastLoginIpComponent implements OnInit {
  private readonly sanitizer = inject(DomSanitizer)
  private readonly userService = inject(UserService)

  lastLoginIp: any = '?'

  ngOnInit (): void {
    this.userService.whoAmI(['lastLoginIp']).subscribe({
      next: (user: any) => {
        if (user?.lastLoginIp) {
          this.lastLoginIp = this.sanitizer.bypassSecurityTrustHtml(`<small>${user.lastLoginIp}</small>`)
        }
      },
      error: (err) => { console.log(err) }
    })
  }
}
