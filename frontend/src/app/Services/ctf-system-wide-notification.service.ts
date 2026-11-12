/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable, inject } from '@angular/core'
import { HttpBackend, HttpClient } from '@angular/common/http'
import { type Observable } from 'rxjs'

export interface SystemWideNotificationResponse {
  message: string
  enabled: boolean
  updatedAt: string
}

@Injectable({
  providedIn: 'root'
})
export class CtfSystemWideNotificationService {
  // The notification URL is operator-configured and usually external, so it must bypass the interceptors that attach the shop session.
  private readonly http = new HttpClient(inject(HttpBackend))

  fetchNotification (url: string): Observable<SystemWideNotificationResponse> {
    return this.http.get<SystemWideNotificationResponse>(url)
  }
}
