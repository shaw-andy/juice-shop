/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { environment } from '../../environments/environment'
import { catchError, map } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class TrackOrderService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/track-order'

  find (params: string) {
    params = encodeURIComponent(params)
    return this.http.get(`${this.host}/${params}`).pipe(map((response: any) => response), catchError((error) => { throw error }))
  }

  confirmation (orderId: string) {
    return this.http.get(`${this.hostServer}/rest/order-confirmation/${encodeURIComponent(orderId)}`, { responseType: 'blob' }).pipe(catchError((error) => { throw error }))
  }
}
