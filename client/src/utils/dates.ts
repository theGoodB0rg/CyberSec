export function parseServerDate(value?: string | null): Date | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!trimmed) return null

  let normalized = trimmed

  const hasTSeparator = normalized.includes('T')
  if (!hasTSeparator) {
    normalized = normalized.replace(' ', 'T')
  }

  const hasTimeZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(normalized)
  if (!hasTimeZone) {
    normalized += 'Z'
  }

  const parsed = new Date(normalized)
  if (!Number.isNaN(parsed.getTime())) {
    return parsed
  }

  const fallback = new Date(trimmed)
  return Number.isNaN(fallback.getTime()) ? null : fallback
}

export function toIsoString(value?: string | null): string | null {
  const date = parseServerDate(value)
  return date ? date.toISOString() : null
}
