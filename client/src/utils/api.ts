export type ApiOptions = RequestInit & { auth?: boolean };

function getToken() {
  try {
    return localStorage.getItem('authToken') || undefined;
  } catch {
    return undefined;
  }
}

export async function apiFetch<T = any>(input: string, init: ApiOptions = {}): Promise<T> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(init.headers || {}),
  };

  const token = getToken();
  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(input, { ...init, headers });
  const contentType = res.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');
  const body = isJson ? await res.json().catch(() => ({})) : await res.text();
  // Auto-handle unauthorized responses globally so the UI can react (logout, redirect)
  if (res.status === 401 || res.status === 403) {
    try {
      window.dispatchEvent(
        new CustomEvent('app:unauthorized', {
          detail: { status: res.status, body },
        })
      );
    } catch {
      // no-op if window is unavailable
    }
  }
  if (!res.ok) {
    const message = isJson && body?.error ? body.error : res.statusText;
    throw new Error(message || `HTTP ${res.status}`);
  }
  return body as T;
}

// Scan Events types and helper
export type ScanEvent = {
  id: string
  scan_id: string
  user_id?: string
  org_id?: string | null
  event_type: string
  at: string
  metadata?: any
}

export async function getScanEvents(scanId: string): Promise<ScanEvent[]> {
  return apiFetch<ScanEvent[]>(`/api/scans/${encodeURIComponent(scanId)}/events`)
}

export type VerifyFindingResult = {
  ok: boolean
  label?: 'Confirmed' | 'Likely' | 'Suspected' | 'Inconclusive'
  score?: number
  confirmations?: string[]
  signals?: string[]
  diff?: any
  poc?: Array<{ name: string, curl: string }>
  why?: string
  wafDetected?: boolean
  wafIndicators?: { header?: boolean, body?: boolean, status?: boolean, sources?: string[] }
  suggestions?: string[]
  seededPayloads?: string[]
  payloadAttempts?: Array<{ payload: string, url: string, status: number, timeMs: number, diff?: { identical?: boolean, added?: number, removed?: number, changed?: number } }>
  baselineConfidence?: { label: string | null, score: number | null }
  payloadConfirmed?: boolean
  dom?: {
    checked: boolean
    reflected: boolean
    matches: Array<{ selector: string, mode: 'text' | 'attribute', attribute?: string }>
    url?: string
    proof?: { filename: string, path: string }
  }
}

export async function verifyFinding(reportId: string, findingId: string): Promise<VerifyFindingResult> {
  return apiFetch<VerifyFindingResult>(`/api/findings/${encodeURIComponent(findingId)}/verify`, {
    method: 'POST',
    body: JSON.stringify({ reportId })
  })
}

// User settings & profiles
export type UserScanSettings = {
  user_id: string
  default_profile: string
  defaults: any
  last_used_profile: string | null
  updated_at: string | null
}

export async function getUserScanSettings(): Promise<UserScanSettings> {
  return apiFetch<UserScanSettings>(`/api/user/scan-settings`)
}

export async function updateUserScanSettings(payload: Partial<Pick<UserScanSettings, 'default_profile' | 'defaults' | 'last_used_profile'>>): Promise<UserScanSettings> {
  return apiFetch<UserScanSettings>(`/api/user/scan-settings`, { method: 'PUT', body: JSON.stringify(payload) })
}

export type ServerProfile = { key: string, name: string, description: string, flags: string[] }
export async function getServerSqlmapProfiles(): Promise<ServerProfile[]> {
  return apiFetch<ServerProfile[]>(`/api/sqlmap/profiles`)
}

export type UserProfile = { id: string, user_id: string, name: string, description: string, flags: string[], is_custom: boolean, created_at: string, updated_at: string }
export async function listUserProfiles(): Promise<UserProfile[]> {
  return apiFetch<UserProfile[]>(`/api/user/profiles`)
}

export async function createUserProfile(input: { name: string, description?: string, flags: string[] }): Promise<UserProfile> {
  return apiFetch<UserProfile>(`/api/user/profiles`, { method: 'POST', body: JSON.stringify(input) })
}

export async function updateUserProfile(id: string, input: { name?: string, description?: string, flags?: string[] }): Promise<UserProfile> {
  return apiFetch<UserProfile>(`/api/user/profiles/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(input) })
}

export async function deleteUserProfile(id: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/user/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export type SqlmapValidateResult = {
  ok: boolean
  disallowed: string[]
  warnings: string[]
  normalizedArgs: string[]
  commandPreview: string
  description: string
  impact: { speed: 'low' | 'medium' | 'high'; stealth: 'lower' | 'medium' | 'higher'; exfil: 'low' | 'high' }
}
export async function validateSqlmap(input: { target?: string, profile: string, customFlags?: string, options?: any }): Promise<SqlmapValidateResult> {
  return apiFetch<SqlmapValidateResult>(`/api/sqlmap/validate`, { method: 'POST', body: JSON.stringify(input) })
}
