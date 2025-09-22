// Client-side validation of custom SQLMap flags to reduce round-trips and confusion.
// Keep in sync with server whitelist in server/sqlmap.js parseCustomFlags()

export const allowedFlags = new Set([
  '--level', '--risk', '--threads', '--delay', '--timeout',
  '--tamper', '--technique', '--dbms', '--os', '--random-agent',
  '--batch', '--flush-session', '--fresh-queries', '--hex',
  '--dump-all', '--exclude-sysdbs', '--limit', '--start', '--stop',
  '--first', '--last', '--dbs', '--tables', '--columns', '--schema',
  '--count', '--dump', '--dump-table', '--dump-format', '--search',
  '--check-waf', '--identify-waf', '--skip-waf', '--mobile',
  '--smart', '--skip-heuristics', '--skip-static', '--unstable'
])

export function validateFlagsString(input: string): { ok: boolean; disallowed: string[] } {
  if (!input || !input.trim()) return { ok: true, disallowed: [] }
  const tokens = input.trim().split(/\s+/)
  const disallowed: string[] = []
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    if (t.startsWith('--')) {
      const name = t.split('=')[0]
      if (!allowedFlags.has(name)) {
        disallowed.push(name)
      }
    }
  }
  return { ok: disallowed.length === 0, disallowed }
}

export function wafPreset(level: 'light' | 'standard' | 'strict' = 'standard') {
  switch (level) {
    case 'light':
      return '--tamper=space2comment --threads=2 --delay=1'
    case 'strict':
      return '--tamper=space2comment,charencode,randomcase --threads=1 --delay=5'
    default:
      return '--tamper=space2comment,charencode,randomcase --threads=1 --delay=3'
  }
}
