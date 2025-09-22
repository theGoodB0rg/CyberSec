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
  suggestions?: string[]
}

export async function verifyFinding(reportId: string, findingId: string): Promise<VerifyFindingResult> {
  return apiFetch<VerifyFindingResult>(`/api/findings/${encodeURIComponent(findingId)}/verify`, {
    method: 'POST',
    body: JSON.stringify({ reportId })
  })
}
