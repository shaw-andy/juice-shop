{
    matcher: oauthMatcher,
    data: { params: (window.location.href).substr(window.location.href.indexOf('#')) },
    component: OAuthComponent
  },
  {
    path: 'coding-challenge/:challengeKey',
    loadComponent: async () => await loadCodingChallenge()
  },
  {
    path: '403',
    component: ErrorPageComponent
  },
  {
    path: '**',
    component: SearchResultComponent
  }
]

export const Routing = RouterModule.forRoot(routes, { useHash: true, relativeLinkResolution: 'legacy' })

export function oauthMatcher (url: UrlSegment[]): UrlMatchResult {
  if (url.length === 0) {
    return null as unknown as UrlMatchResult
  }
  const fragment = window.location.hash
  if (!fragment.startsWith('#/') && new URLSearchParams(fragment.substring(1)).has('access_token')) {
    return ({ consumed: url })
  }

  return null as unknown as UrlMatchResult
}