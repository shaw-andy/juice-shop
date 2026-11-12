/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type HttpEvent, type HttpHandler, type HttpInterceptor, type HttpRequest } from '@angular/common/http'
import { Injectable } from '@angular/core'
import { type Observable } from 'rxjs'
import { environment } from '../../environments/environment'

function originOf (url: string): string | null {
  try {
    return new URL(url, document.baseURI).origin
  } catch {
    return null
  }
}

@Injectable()
export class RequestInterceptor implements HttpInterceptor {
  intercept (req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const shopOrigin = originOf(environment.hostServer)
    if (shopOrigin === null || originOf(req.url) !== shopOrigin) {
      return next.handle(req)
    }
    if (localStorage.getItem('token')) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${localStorage.getItem('token')}`
        }
      })
    }
    if (localStorage.getItem('email')) {
      req = req.clone({
        setHeaders: {
          'X-User-Email': String(localStorage.getItem('email'))
        }
      })
    }
    return next.handle(req)
  }
}
