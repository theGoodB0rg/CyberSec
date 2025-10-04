export type ApiOptions = RequestInit & { auth?: boolean };

const API_BASE_URL = (() => {
  const raw = import.meta.env?.VITE_API_BASE_URL;
  if (!raw) return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  try {
    const url = new URL(trimmed);
    return url.href.replace(/\/$/, '');
  } catch {
    return trimmed.replace(/\/$/, '');
  }
})();

const isAbsoluteUrl = (value: string) => /^https?:\/\//i.test(value);

const resolveUrl = (input: string) => {
  if (isAbsoluteUrl(input)) return input;
  if (!API_BASE_URL) return input;
  return input.startsWith('/')
    ? `${API_BASE_URL}${input}`
    : `${API_BASE_URL}/${input}`;
};

function getToken() {
  try {
    return localStorage.getItem('authToken') || undefined;
  } catch {
    return undefined;
  }
}

export async function apiFetch<T = any>(input: string, init: ApiOptions = {}): Promise<T> {
  const { auth = true, headers: initHeaders, ...rest } = init;

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(initHeaders || {}),
  };

  const token = auth ? getToken() : undefined;
  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  const url = resolveUrl(input);
  const res = await fetch(url, { ...rest, headers });
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

export type ContactRequestPayload = {
  name: string
  email: string
  organisation?: string
  message: string
  consent: boolean
}

export async function submitContactRequest(payload: ContactRequestPayload): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/contact`, {
    method: 'POST',
    body: JSON.stringify(payload),
    auth: false,
  })
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
  poc?: Array<{
    name: string
    curl: string
    expectedSignal?: {
      type?: string
      summary?: string
      metrics?: Record<string, number | string | null>
    }
    evidencePreview?: QuickVerifyEvidencePreview | null
    rawKey?: string | null
    rawEvidenceId?: string | null
    rawEvidenceHash?: string | null
    rawEvidenceLength?: number | null
  }>
  why?: string
  wafDetected?: boolean
  wafIndicators?: { header?: boolean, body?: boolean, status?: boolean, sources?: string[] }
  suggestions?: string[]
  seededPayloads?: string[]
  payloadAttempts?: Array<{
    payload: string
    url: string
    status: number
    timeMs: number
    diff?: { identical?: boolean, added?: number, removed?: number, changed?: number }
    fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } }
  }>
  baselineConfidence?: { label: string | null, score: number | null }
  payloadConfirmed?: boolean
  dom?: {
    checked: boolean
    reflected: boolean
    matches: Array<{ selector: string, mode: 'text' | 'attribute', attribute?: string }>
    url?: string
    proof?: { filename: string, path: string }
  }
  remediationSuspected?: boolean
  extraSignals?: Array<{
    type: string
    description: string
    payload?: string
    fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } }
    contentDiff?: { identical?: boolean, added?: number, removed?: number, changed?: number }
    statusChanged?: boolean
    lenDelta?: number
  }>
  bestPayload?: string | null
  driftCheck?: {
    url?: string
    status?: number
    timeMs?: number
    fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } }
    contentDiff?: { identical?: boolean, added?: number, removed?: number, changed?: number }
  } | null
  verificationStartedAt?: number
  verificationCompletedAt?: number
  verificationDurationMs?: number | null
  evidence?: QuickVerifyEvidence | null
  rawEvidence?: QuickVerifyEvidenceSummary[]
  consent?: {
    decision: boolean
    preference: QuickVerifyConsentPreference
  }
}

export type QuickVerifyEvidencePreview = {
  status: number | null
  timeMs: number | null
  length: number | null
  hash: string | null
  excerpt?: string | null
  headers?: Record<string, string>
  url?: string | null
  method?: string | null
}

export type QuickVerifySignalResponse = {
  preview?: QuickVerifyEvidencePreview | null
  snapshot?: {
    status?: number | null
    timeMs?: number | null
    length?: number | null
    headers?: Record<string, string>
  } | null
  rawKey?: string | null
  rawEvidenceId?: string | null
  rawEvidenceHash?: string | null
  rawEvidenceLength?: number | null
}

export type QuickVerifyEvidence = {
  baseline?: {
    preview?: QuickVerifyEvidencePreview | null
    rawKey?: string | null
    rawEvidenceId?: string | null
    rawEvidenceHash?: string | null
    rawEvidenceLength?: number | null
  } | null
  signals: {
    boolean: {
      diff?: { identical?: boolean, added?: number, removed?: number, changed?: number } | null
      lengthDelta?: number | null
      fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } } | null
      responses?: {
        true?: QuickVerifySignalResponse
        false?: QuickVerifySignalResponse
      }
    } | null
    time: {
      deltaMs?: number | null
      fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } } | null
      responses?: {
        baseline?: QuickVerifySignalResponse
        delayed?: QuickVerifySignalResponse
      }
    } | null
    error: {
      keywordMatch?: boolean
      preview?: QuickVerifyEvidencePreview | null
      rawKey?: string | null
      rawEvidenceId?: string | null
      rawEvidenceHash?: string | null
      rawEvidenceLength?: number | null
    } | null
    payloads: Array<{
      payload: string
      keywordHit?: boolean
      diff?: { identical?: boolean, added?: number, removed?: number, changed?: number } | null
      fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } } | null
      preview?: QuickVerifyEvidencePreview | null
      rawKey?: string | null
      rawEvidenceId?: string | null
      rawEvidenceHash?: string | null
      rawEvidenceLength?: number | null
    }>
  }
  drift?: {
    preview?: QuickVerifyEvidencePreview | null
    fingerprintDiff?: { statusChanged?: boolean, lengthDelta?: number, headers?: { added: string[], removed: string[], changed: string[] } } | null
    contentDiff?: { identical?: boolean, added?: number, removed?: number, changed?: number } | null
    rawKey?: string | null
    rawEvidenceId?: string | null
    rawEvidenceHash?: string | null
    rawEvidenceLength?: number | null
  } | null
  dom?: {
    ok?: boolean
    reflected?: boolean
    matches?: Array<{ selector: string, mode: string, attribute?: string }>
    url?: string | null
    screenshotCaptured?: boolean
  } | null
  waf?: {
    detected: boolean
    indicators?: { header?: boolean, body?: boolean, status?: boolean, sources?: string[] } | null
  } | null
}

export type QuickVerifyEvidenceSummary = {
  id: string | null
  key: string
  scope: string | null
  tag: string | null
  status: number | null
  timeMs: number | null
  bodyHash: string | null
  bodyLength: number | null
  method: string | null
  url: string | null
  createdAt: string | null
  contentType: string | null
  stored: boolean
}

export type QuickVerifyConsentPreference = {
  userId: string
  storeEvidence: boolean | null
  rememberChoice: boolean
  promptSuppressed: boolean
  promptVersion: number
  lastPromptAt: string | null
  lastDecisionAt: string | null
  updatedAt: string | null
  createdAt: string | null
  source: string | null
}

export type QuickVerifyConsentInput = {
  storeEvidence: boolean
  rememberChoice?: boolean
  promptSuppressed?: boolean
  promptVersion?: number
  lastPromptAt?: string
  source?: string
}

export async function verifyFinding(reportId: string, findingId: string, options: { consent?: QuickVerifyConsentInput, captureRawBodies?: boolean } = {}): Promise<VerifyFindingResult> {
  const payload: Record<string, unknown> = { reportId };
  if (options.consent) payload.consent = options.consent;
  if (options.captureRawBodies !== undefined) payload.captureRawBodies = options.captureRawBodies;
  return apiFetch<VerifyFindingResult>(`/api/findings/${encodeURIComponent(findingId)}/verify`, {
    method: 'POST',
    body: JSON.stringify(payload)
  })
}

export async function getQuickVerifyPreference(): Promise<QuickVerifyConsentPreference> {
  const res = await apiFetch<{ ok: boolean, preference: QuickVerifyConsentPreference }>(`/api/quick-verify/preferences`);
  return res.preference;
}

export async function updateQuickVerifyPreference(preference: Partial<QuickVerifyConsentInput> & { storeEvidence?: boolean | null }): Promise<QuickVerifyConsentPreference> {
  const res = await apiFetch<{ ok: boolean, preference: QuickVerifyConsentPreference }>(`/api/quick-verify/preferences`, {
    method: 'POST',
    body: JSON.stringify(preference)
  });
  return res.preference;
}

export async function clearQuickVerifyPreference(): Promise<void> {
  await apiFetch<{ ok: boolean }>(`/api/quick-verify/preferences`, { method: 'DELETE' });
}

export async function listQuickVerifyEvidence(reportId: string, findingId: string, limit = 50): Promise<QuickVerifyEvidenceSummary[]> {
  const res = await apiFetch<{ ok: boolean, evidence: QuickVerifyEvidenceSummary[] }>(
    `/api/reports/${encodeURIComponent(reportId)}/findings/${encodeURIComponent(findingId)}/quick-verify/evidence?limit=${encodeURIComponent(String(limit))}`
  );
  return res.evidence;
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

export type SafeHostConfigResponse = {
  builtin: string[]
  additional: string[]
  all: string[]
}

export async function getSafeHostnames(): Promise<SafeHostConfigResponse> {
  return apiFetch<SafeHostConfigResponse>(`/api/config/safe-hosts`)
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
