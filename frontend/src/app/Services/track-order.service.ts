/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { environment } from '../../environments/environment'
import { catchError, map } from 'rxjs/operators'
import { pathSegment } from './path-segment'

@Injectable({
  providedIn: 'root'
})
export class TrackOrderService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/track-order'

  find (params: string) {
    return this.http.get(`${this.host}/${pathSegment(params)}`).pipe(map((response: any) => response), catchError((error) => { throw error }))
  }
}
