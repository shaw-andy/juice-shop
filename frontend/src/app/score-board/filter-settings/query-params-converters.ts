import type { Params } from '@angular/router'

import { DEFAULT_FILTER_SETTING, type FilterSetting, type SolvedStatus } from './FilterSetting'

// the router hands out repeated query parameters as arrays, so only the first value is used
function singleValue (value: unknown): string | undefined {
  const first = Array.isArray(value) ? value[0] : value
  return typeof first === 'string' ? first : undefined
}

export function fromQueryParams (queryParams: Readonly<Params>): FilterSetting {
  const filterSetting: FilterSetting = { ...structuredClone(DEFAULT_FILTER_SETTING) }
  const searchQuery = singleValue(queryParams.searchQuery)
  if (searchQuery) {
    filterSetting.searchQuery = searchQuery
  }
  const difficulties = singleValue(queryParams.difficulties)
  if (difficulties) {
    filterSetting.difficulties = difficulties
      .split(',')
      .map((difficulty) => parseInt(difficulty, 10))
      .filter((difficulty) => !isNaN(difficulty)) as FilterSetting['difficulties']
  }
  const tags = singleValue(queryParams.tags)
  if (tags) {
    filterSetting.tags = tags.split(',')
  }
  const status = singleValue(queryParams.status)
  if (status) {
    filterSetting.status = status as SolvedStatus
  }
  const categories = singleValue(queryParams.categories)
  if (categories) {
    filterSetting.categories = categories.split(',')
  }
  const showDisabledChallenges = singleValue(queryParams.showDisabledChallenges)
  if (showDisabledChallenges !== undefined) {
    filterSetting.showDisabledChallenges = showDisabledChallenges === 'true'
  }

  return filterSetting
}

export function toQueryParams (filterSetting: Readonly<FilterSetting>): Params {
  return {
    searchQuery: filterSetting.searchQuery ?? undefined,
    difficulties: filterSetting.difficulties.join(',') || undefined,
    status: filterSetting.status ?? undefined,
    tags: filterSetting.tags.join(',') || undefined,
    categories: filterSetting.categories.join(',') || undefined,
    showDisabledChallenges: !filterSetting.showDisabledChallenges ? 'false' : undefined
  }
}
