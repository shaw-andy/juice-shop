/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class PhotoWallService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/memories'

  addMemory (caption: string, image: File) {
    const postData = new FormData()
    postData.append('image', image, caption)
    postData.append('caption', caption)
    return this.http.post(this.host, postData).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  get (offset = 0, limit = 10) {
    return this.http.get(this.host + '/', { params: { offset, limit } }).pipe(map((response: any) => ({ memories: response.data, total: response.total })), catchError((err: Error) => { throw err }))
  }
}
