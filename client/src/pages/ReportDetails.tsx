import type React from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { ArrowLeft, FileText, FileJson, CheckCircle, RefreshCcw, Image as ImageIcon, ExternalLink, Flag, AlertTriangle, XOctagon, HelpCircle, Activity, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import {
  apiFetch,
  getScanEvents,
  getQuickVerifyPreference,
  type ScanEvent,
  verifyFinding as apiVerifyFinding,
  type VerifyFindingResult,
  type QuickVerifyConsentPreference,
  type QuickVerifyConsentInput,
  type QuickVerifyEvidenceSummary,
  listQuickVerifyEvidence
} from '../utils/api';
import { useAppStore, selectRunningScanCount } from '../store/appStore';
import type { ScanVerdictMeta, ScanVerdictOutcome } from '../store/appStore';
import { useScanSocket } from '../hooks/useSocket';
import { wafPreset } from '../utils/sqlmapFlags';

// You might need to create this type based on your actual report structure
type OverallVerdict = {
  level: string;
  rationale?: string;
  affectedParameters?: Array<{ param: string; type: string }>;
};

type SqlmapSummaryEntry = {
  parameter?: string;
  method?: string;
  place?: string;
  type?: string;
  title?: string;
  payload?: string;
  techniqueName?: string;
  raw?: string;
};

type SqlmapSummaryMetadata = {
  verdictLine?: string;
  rawSection?: string;
  confirmed?: SqlmapSummaryEntry[];
  attempted?: Array<{ technique?: string; line?: string }>;
};

type SeverityCriteriaEntry = {
  label?: string;
  summary?: string;
  detail?: string;
  impacts?: string[];
  techniques?: string[];
};

type ReportMetadata = Record<string, any> & {
  overallVerdict?: OverallVerdict;
  sqlmapSummary?: SqlmapSummaryMetadata;
  falsePositives?: Record<string, boolean>;
  severityCriteria?: Record<string, SeverityCriteriaEntry>;
};

const FALLBACK_SEVERITY_CRITERIA: Record<string, SeverityCriteriaEntry> = {
  critical: {
    label: 'Critical',
    summary: 'Stacked (multi-statement) SQL injection confirmed.',
    detail:
      'The scanner proved it can break out of the query and append additional statements (INSERT/UPDATE/DELETE/DDL). Attackers can tamper with or destroy data, and may escalate to file/command execution depending on DB privileges.',
    impacts: [
      'Data tampering or destructive writes',
      'Schema changes such as DROP/ALTER',
      'Potential file read/write or OS command execution'
    ],
    techniques: ['Stacked queries']
  },
  high: {
    label: 'High',
    summary: 'Single-statement SQL injection confirmed with data access.',
    detail:
      'SQLMap demonstrated full control over a query that returns data or metadata (boolean/time-based, error-based, union-based, or classical payloads). Attackers can read sensitive information and pivot further but did not execute multiple statements in one request.',
    impacts: [
      'Sensitive data disclosure and credential theft',
      'Authentication bypass or forced logic changes',
      'Database enumeration that enables follow-on attacks'
    ],
    techniques: [
      'SQL Injection',
      'Boolean-based blind SQL injection',
      'Time-based blind SQL injection',
      'Error-based SQL injection',
      'Union query SQL injection'
    ]
  }
};

type SeverityVisualStyle = {
  card: string;
  badge: string;
};

const DEFAULT_SEVERITY_STYLE: SeverityVisualStyle = {
  card: 'border border-gray-700/70 border-l-4 border-gray-500 bg-gray-800 text-gray-100',
  badge: 'bg-gray-700 text-gray-100 border border-gray-500'
};

const SEVERITY_STYLE_MAP: Record<string, SeverityVisualStyle> = {
  critical: {
    card: 'border border-red-800/60 border-l-4 border-red-500 bg-gradient-to-br from-red-950 via-red-900 to-red-800 text-gray-100',
    badge: 'bg-red-600 text-white border border-red-300'
  },
  high: {
    card: 'border border-orange-800/60 border-l-4 border-orange-500 bg-gradient-to-br from-orange-950 via-orange-900 to-orange-800 text-gray-100',
    badge: 'bg-orange-500 text-white border border-orange-200'
  },
  medium: {
    card: 'border border-amber-700/60 border-l-4 border-amber-500 bg-gradient-to-br from-amber-950 via-amber-900 to-amber-800 text-gray-100',
    badge: 'bg-amber-400 text-gray-900 border border-amber-200'
  },
  low: {
    card: 'border border-sky-800/60 border-l-4 border-sky-500 bg-gradient-to-br from-sky-950 via-sky-900 to-sky-800 text-gray-100',
    badge: 'bg-sky-500 text-white border border-sky-200'
  }
};

const getSeverityStyles = (severity?: string): SeverityVisualStyle => {
  if (!severity) return DEFAULT_SEVERITY_STYLE;
  const key = severity.toLowerCase();
  return SEVERITY_STYLE_MAP[key] || DEFAULT_SEVERITY_STYLE;
};

const VERDICT_OUTCOME_STYLES: Record<ScanVerdictOutcome, { label: string; card: string; badge: string; icon: React.ComponentType<{ className?: string; size?: number }>; description: string }> = {
  vulnerable: {
    label: 'Vulnerable',
    card: 'border border-red-800/70 bg-gradient-to-br from-red-950 via-red-900 to-red-800 text-red-100',
    badge: 'bg-red-600 text-white border border-red-300',
    icon: ShieldAlert,
    description: 'SQLMap confirmed exploitable injection paths for this scan.'
  },
  suspected: {
    label: 'Suspected',
    card: 'border border-amber-700/70 bg-gradient-to-br from-amber-950 via-amber-900 to-amber-800 text-amber-100',
    badge: 'bg-amber-500 text-gray-900 border border-amber-200',
    icon: AlertTriangle,
    description: 'Potential injection indicators detected. Review manually for confirmation.'
  },
  clean: {
    label: 'Clean',
    card: 'border border-emerald-700/60 bg-gradient-to-br from-emerald-950 via-emerald-900 to-emerald-800 text-emerald-100',
    badge: 'bg-emerald-500 text-emerald-950 border border-emerald-200',
    icon: ShieldCheck,
    description: 'No vulnerable parameters survived verification. Heuristics dismissed flagged signals.'
  },
  error: {
    label: 'Scan Error',
    card: 'border border-rose-800/60 bg-gradient-to-br from-rose-950 via-rose-900 to-rose-800 text-rose-100',
    badge: 'bg-rose-600 text-white border border-rose-300',
    icon: XOctagon,
    description: 'Scan exited with an error. See timeline and raw verdict for details.'
  },
  unknown: {
    label: 'Unknown',
    card: 'border border-gray-700/70 bg-gradient-to-br from-gray-950 via-gray-900 to-gray-800 text-gray-100',
    badge: 'bg-gray-600 text-white border border-gray-400',
    icon: HelpCircle,
    description: 'Verdict metadata incomplete. Review raw output or rerun the scan.'
  }
};

const PARAM_STATUS_STYLES: Record<string, string> = {
  confirmed: 'bg-emerald-500/15 text-emerald-200 border border-emerald-500/30',
  dismissed: 'bg-slate-700/70 text-slate-200 border border-slate-500/30',
  suspected: 'bg-amber-500/15 text-amber-200 border border-amber-400/30',
  testing: 'bg-blue-500/15 text-blue-200 border border-blue-400/30',
  unknown: 'bg-gray-700/70 text-gray-200 border border-gray-500/30'
};

const normaliseVerdictMeta = (raw: unknown): ScanVerdictMeta | null => {
  if (!raw) return null;
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw) as ScanVerdictMeta;
    } catch (err) {
      console.warn('Failed to parse verdict_meta JSON string', err);
      return null;
    }
  }
  if (typeof raw === 'object') return raw as ScanVerdictMeta;
  return null;
};

const formatDateTime = (value?: string | null): string | null => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleString();
};

const formatTimelineLabel = (event: { type?: string; detail?: string; parameter?: string; place?: string }): string => {
  const parts: string[] = [];
  if (event.type) parts.push(event.type);
  if (event.parameter) parts.push(`param: ${event.parameter}`);
  if (event.place) parts.push(`place: ${event.place}`);
  if (event.detail) parts.push(event.detail);
  return parts.join(' · ');
};

const formatConfidence = (value: number): string => {
  if (!Number.isFinite(value)) return '';
  if (value <= 1) return `${Math.round(value * 100)}%`;
  if (value <= 100) return `${value.toFixed(1)}%`;
  return value.toFixed(1);
};

const slugifyForFilename = (raw: string | null | undefined, fallback: string): string => {
  if (typeof raw === 'string') {
    const trimmed = raw.trim().toLowerCase();
    if (trimmed.length > 0) {
      const condensed = trimmed
        .replace(/[^a-z0-9]+/gi, '-')
        .replace(/-{2,}/g, '-')
        .replace(/^-+|-+$/g, '');
      if (condensed.length > 0) {
        return condensed.slice(0, 64);
      }
    }
  }
  return fallback;
};

type Report = {
  id: string;
  title: string;
  target: string;
  status: string;
  scanDuration: number;
  createdAt: string;
  command?: string;
  vulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    findings: Array<{
      id: string;
      type: string;
      severity: string;
      parameter?: string;
      httpMethod?: string;
      description: string;
      impact?: string;
      remediation?: string[];
      confidenceLabel?: string;
      confidenceScore?: number;
      signals?: string[];
      status?: string;
      why?: string;
      discoveredAt?: string;
      evidence?: Array<{
        line: number;
        content: string;
        context?: string;
      }>;
      payload?: string;
      techniqueSummary?: string;
      sqlmapMetadata?: {
        place?: string;
        method?: string;
        type?: string;
        title?: string;
        payload?: string;
        raw?: string;
        technique?: string;
        csv?: Record<string, unknown>;
      };
    }>;
  };
  recommendations?: {
    highPriority?: string[];
    general?: string[];
  } | Array<{
    category: string;
    priority?: string;
    title: string;
    description: string;
    implementation?: string[];
    effort?: string;
    impact?: string;
  }>;
  extractedData?: {
    databases?: string[];
    tables?: string[];
    columns?: string[];
    users?: string[];
    systemInfo?: {
      dbms?: string[] | string;
      banner?: string[] | string;
      hostname?: string;
      isDba?: boolean;
      webTechnology?: string[];
      webServerOs?: string;
      dbmsOs?: string;
    };
    csvFiles?: Array<{ name: string; path?: string; size?: number; modified?: string | number }>;
    structuredData?: unknown;
  };
  metadata?: ReportMetadata;
};


const LoadingSpinner = () => (
  <div className="flex justify-center items-center h-full">
    <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-blue-500"></div>
  </div>
);

const ErrorDisplay = ({ message }: { message: string }) => (
  <div className="text-center py-10">
    <p className="text-red-500">{message}</p>
  </div>
);
 

export default function ReportDetails() {
  const applyWafSuggestions = useAppStore(s => s.applyWafSuggestions);
  const runningScanCount = useAppStore(selectRunningScanCount);
  const { startScan, terminateScan } = useScanSocket();
  const navigate = useNavigate();
  const { reportId } = useParams<{ reportId: string }>();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'vulns' | 'recs' | 'command' | 'outputs' | 'activity'>('vulns');
  const [events, setEvents] = useState<ScanEvent[] | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventsLastRefreshed, setEventsLastRefreshed] = useState<number | null>(null);
  const [verifying, setVerifying] = useState<Record<string, boolean>>({});
  const [verifyResult, setVerifyResult] = useState<Record<string, VerifyFindingResult>>({});
  const [verifyMeta, setVerifyMeta] = useState<Record<string, { at: string }>>({});
  const [verifyAllRunning, setVerifyAllRunning] = useState(false);
  const [verifyAllProgress, setVerifyAllProgress] = useState<{ done: number; total: number }>({ done: 0, total: 0 });
  const [verifyOnlyChanged, setVerifyOnlyChanged] = useState<boolean>(false);
  const [globalVerifying, setGlobalVerifying] = useState<boolean>(false);
  const [showFalsePositivesOnly, setShowFalsePositivesOnly] = useState<boolean>(false);
  const [proofModal, setProofModal] = useState<{ open: boolean; src: string; title?: string }>({ open: false, src: '' });
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [panning, setPanning] = useState<boolean>(false);
  const [quickVerifyPreference, setQuickVerifyPreference] = useState<QuickVerifyConsentPreference | null>(null);
  const [pendingConsent, setPendingConsent] = useState<{ findingIds: string[]; mode: 'single' | 'bulk' } | null>(null);
  const [consentDecision, setConsentDecision] = useState<'store' | 'skip'>('store');
  const [consentRemember, setConsentRemember] = useState<boolean>(false);
  const [panStart, setPanStart] = useState<{ x: number; y: number } | null>(null);
  const [evidenceSummaries, setEvidenceSummaries] = useState<Record<string, QuickVerifyEvidenceSummary[]>>({});
  const [evidenceLoading, setEvidenceLoading] = useState<Record<string, boolean>>({});
  const [evidenceErrors, setEvidenceErrors] = useState<Record<string, string | null>>({});
  const shouldShowConsentReminder = quickVerifyPreference?.storeEvidence === false && !!quickVerifyPreference?.promptSuppressed;

  const derivedScanId = useMemo(() => {
    if (!report) return null;
    return (
      (report as any)?.scanId ||
      (report as any)?.scan_id ||
      (report as any)?.scanID ||
      (report as any)?.scan?.id ||
      (report as any)?.metadata?.scanId ||
      null
    );
  }, [report]);

  const verdictSelector = useCallback(
    (state: any) => {
      if (!derivedScanId) return null;
      const match = Array.isArray(state?.scans)
        ? state.scans.find((scan: any) => scan?.id === derivedScanId)
        : null;
      return match?.verdictMeta ?? null;
    },
    [derivedScanId]
  );

  const storeVerdictMeta = useAppStore(verdictSelector);
  const [fetchedVerdictMeta, setFetchedVerdictMeta] = useState<ScanVerdictMeta | null>(null);
  const [verdictFetchState, setVerdictFetchState] = useState<{ scanId: string | null; loading: boolean; error: string | null }>({
    scanId: null,
    loading: false,
    error: null
  });
  const { scanId: verdictFetchScanId, loading: verdictFetchLoading, error: verdictFetchError } = verdictFetchState;

  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        const data = await apiFetch(`/api/reports/${reportId}`);
        setReport(data);
        // Load persisted verification summaries from report.metadata.verifications
        try {
          const persisted = (data as any)?.metadata?.verifications || {};
          if (persisted && typeof persisted === 'object') {
            const results: Record<string, VerifyFindingResult> = {};
            const meta: Record<string, { at: string }> = {};
            for (const [fid, v] of Object.entries<any>(persisted)) {
              results[fid] = {
                ok: true,
                label: v.label,
                score: v.score,
                confirmations: Array.isArray(v.confirmations)
                  ? v.confirmations
                  : typeof v.confirmations === 'string'
                    ? [v.confirmations]
                    : undefined,
                signals: Array.isArray(v.signals)
                  ? v.signals
                  : typeof v.signals === 'string'
                    ? [v.signals]
                    : undefined,
                wafDetected: !!v.wafDetected,
                suggestions: Array.isArray(v.suggestions) ? v.suggestions : undefined,
                why: 'Persisted verification summary',
                seededPayloads: Array.isArray(v.payloadsTested) ? v.payloadsTested.filter((value: any) => typeof value === 'string' && value.trim().length > 0) : undefined,
                payloadConfirmed: typeof v.payloadConfirmed === 'boolean' ? v.payloadConfirmed : undefined,
                baselineConfidence: v.baselineConfidence && typeof v.baselineConfidence === 'object'
                  ? {
                      label: typeof v.baselineConfidence.label === 'string' ? v.baselineConfidence.label : null,
                      score: typeof v.baselineConfidence.score === 'number' ? v.baselineConfidence.score : null
                    }
                  : undefined
              };
              if (v.at) meta[fid] = { at: v.at };
            }
            if (Object.keys(results).length > 0) setVerifyResult(results);
            if (Object.keys(meta).length > 0) setVerifyMeta(meta);
          }
        } catch (_) {}
      } catch (err: any) {
        setError(err.message);
        toast.error(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (reportId) {
      fetchReport();
    }
  }, [reportId]);

  useEffect(() => {
    if (!derivedScanId) {
      if (fetchedVerdictMeta) setFetchedVerdictMeta(null);
      if (verdictFetchScanId || verdictFetchLoading || verdictFetchError) {
        setVerdictFetchState({ scanId: null, loading: false, error: null });
      }
      return;
    }

    if (storeVerdictMeta) {
      if (fetchedVerdictMeta) setFetchedVerdictMeta(null);
      if (verdictFetchScanId !== derivedScanId || verdictFetchLoading || verdictFetchError) {
        setVerdictFetchState({ scanId: derivedScanId, loading: false, error: null });
      }
      return;
    }

    if (fetchedVerdictMeta && verdictFetchScanId === derivedScanId && !verdictFetchLoading) {
      return;
    }

    if (verdictFetchLoading && verdictFetchScanId === derivedScanId) {
      return;
    }

    let cancelled = false;
    setVerdictFetchState({ scanId: derivedScanId, loading: true, error: null });

    apiFetch(`/api/scans/${derivedScanId}`)
      .then((scan) => {
        if (cancelled) return;
        const meta = normaliseVerdictMeta((scan as any)?.verdictMeta ?? (scan as any)?.verdict_meta);
        setFetchedVerdictMeta(meta);
        setVerdictFetchState({ scanId: derivedScanId, loading: false, error: null });
      })
      .catch((err: any) => {
        if (cancelled) return;
        const message = err?.message ? String(err.message) : 'Unable to load latest scan verdict';
        setVerdictFetchState({ scanId: derivedScanId, loading: false, error: message });
      });

    return () => {
      cancelled = true;
    };
  }, [derivedScanId, storeVerdictMeta, verdictFetchScanId, verdictFetchLoading, verdictFetchError, fetchedVerdictMeta]);

  useEffect(() => {
    let cancelled = false;
    const loadPreference = async () => {
      try {
        const pref = await getQuickVerifyPreference();
        if (cancelled) return;
        setQuickVerifyPreference(pref);
        setConsentRemember(!!pref.rememberChoice);
        if (pref.storeEvidence === null) {
          setConsentDecision('store');
        } else {
          setConsentDecision(pref.storeEvidence ? 'store' : 'skip');
        }
      } catch (_) {
        // Preference not yet set; default decision remains optimistic (store) until user chooses.
      }
    };
    loadPreference();
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshEvidenceList = useCallback(async (findingId: string, options: { silent?: boolean } = {}) => {
    const currentReportId = report?.id;
    if (!currentReportId) return;
    const { silent = false } = options;
    setEvidenceLoading((prev) => ({ ...prev, [findingId]: true }));
    try {
      const list = await listQuickVerifyEvidence(currentReportId, findingId);
      setEvidenceSummaries((prev) => ({ ...prev, [findingId]: list }));
      setEvidenceErrors((prev) => ({ ...prev, [findingId]: null }));
      if (!silent && list.length === 0) {
        toast('No stored responses yet for this finding.', { icon: 'ℹ️' });
      }
    } catch (err: any) {
      const message = err?.message || 'Failed to load stored responses';
      setEvidenceErrors((prev) => ({ ...prev, [findingId]: message }));
      if (!silent) toast.error(message);
    } finally {
      setEvidenceLoading((prev) => ({ ...prev, [findingId]: false }));
    }
  }, [report?.id]);

  useEffect(() => {
    if (!report?.id) return;
    for (const [findingId, result] of Object.entries(verifyResult)) {
      if (!findingId) continue;
      if (evidenceSummaries[findingId] !== undefined || evidenceLoading[findingId]) continue;
      if (result && Array.isArray(result.rawEvidence) && result.rawEvidence.length > 0) {
        setEvidenceSummaries((prev) => ({ ...prev, [findingId]: result.rawEvidence as QuickVerifyEvidenceSummary[] }));
        setEvidenceErrors((prev) => ({ ...prev, [findingId]: null }));
        continue;
      }
      refreshEvidenceList(findingId, { silent: true });
    }
  }, [report?.id, verifyResult, evidenceSummaries, evidenceLoading, refreshEvidenceList]);

  const scanId = useMemo(() => {
    // Prefer a direct scanId on the report if available; otherwise try to infer from metadata/extracted data
    // Our server stores scan_id as report.scan_id in the DB, but the client Report type doesn’t have it;
    // fetchReport returns the full row, so we can try (report as any).scan_id safely.
    return (report as any)?.scan_id || (report as any)?.scanId || '';
  }, [report]);

  const overallVerdict = useMemo<OverallVerdict | null>(() => {
    const metaVerdict = (report as any)?.metadata?.overallVerdict;
    if (metaVerdict && typeof metaVerdict === 'object') {
      return metaVerdict as OverallVerdict;
    }
    return null;
  }, [report]);

  const sqlmapSummary = useMemo<SqlmapSummaryMetadata | null>(() => {
    const summary = report?.metadata?.sqlmapSummary;
    if (summary && typeof summary === 'object') {
      return summary as SqlmapSummaryMetadata;
    }
    return null;
  }, [report]);

  const severityCriteria = useMemo<Record<string, SeverityCriteriaEntry>>(() => {
    const metaCriteria = (report?.metadata?.severityCriteria || {}) as Record<string, SeverityCriteriaEntry>;
    const merged: Record<string, SeverityCriteriaEntry> = {};
    const normalizeKey = (key: string) => key.toLowerCase();

    // Seed with fallback values first so core definitions always exist.
    for (const [key, value] of Object.entries(FALLBACK_SEVERITY_CRITERIA)) {
      merged[normalizeKey(key)] = { ...value };
    }

    if (metaCriteria && typeof metaCriteria === 'object') {
      for (const [rawKey, value] of Object.entries(metaCriteria)) {
        if (!value || typeof value !== 'object') continue;
        const key = normalizeKey(rawKey);
        const base = merged[key] || {};
        merged[key] = {
          ...base,
          ...value,
          impacts: Array.isArray(value.impacts) ? value.impacts : base.impacts,
          techniques: Array.isArray(value.techniques) ? value.techniques : base.techniques
        };
      }
    }

    return merged;
  }, [report]);

  const severityLegendEntries = useMemo(() => {
    const order = ['critical', 'high', 'medium', 'low', 'informational'];
    const entries = Object.entries(severityCriteria || {});
    const usable = entries
      .map(([rawKey, info]) => {
        const key = rawKey.toLowerCase();
        const label = info?.label || key.charAt(0).toUpperCase() + key.slice(1);
        const summary = info?.summary?.trim();
        const detail = info?.detail?.trim();
        const impacts = Array.isArray(info?.impacts) ? info!.impacts!.filter(Boolean) : [];
        const techniques = Array.isArray(info?.techniques) ? info!.techniques!.filter(Boolean) : [];
        const hasContent = Boolean(summary || detail || impacts.length || techniques.length);
        if (!hasContent) return null;
        return { key, label, summary, detail, impacts, techniques };
      })
      .filter(Boolean) as Array<{
        key: string;
        label: string;
        summary?: string;
        detail?: string;
        impacts: string[];
        techniques: string[];
      }>;

    usable.sort((a, b) => {
      const ai = order.indexOf(a.key);
      const bi = order.indexOf(b.key);
      const aIndex = ai === -1 ? order.length + a.key.localeCompare(b.key) : ai;
      const bIndex = bi === -1 ? order.length + b.key.localeCompare(a.key) : bi;
      return aIndex - bIndex;
    });

    return usable;
  }, [severityCriteria]);

  const arrayify = (value: unknown): string[] => {
    if (Array.isArray(value)) {
      return value.map((item) => (item == null ? '' : String(item))).filter((item) => item.length > 0);
    }
    if (typeof value === 'string') {
      return value.length > 0 ? [value] : [];
    }
    return [];
  };

  const extractionHighlights = useMemo(() => {
    if (!report?.extractedData) return null;
    const data = report.extractedData;
    const systemInfo = data.systemInfo || {};
    const dbmsList = arrayify(systemInfo.dbms);
    const bannerList = arrayify(systemInfo.banner);
    const webTech = arrayify(systemInfo.webTechnology);
    const databases = Array.isArray(data.databases) ? data.databases.filter(Boolean) : [];
    const users = Array.isArray(data.users) ? data.users.filter(Boolean) : [];
    const hasHighlights =
      dbmsList.length > 0 ||
      bannerList.length > 0 ||
      databases.length > 0 ||
      users.length > 0 ||
      typeof systemInfo.hostname === 'string' ||
      typeof systemInfo.isDba === 'boolean' ||
      typeof systemInfo.webServerOs === 'string' ||
      typeof systemInfo.dbmsOs === 'string' ||
      webTech.length > 0;

    if (!hasHighlights) return null;

    return {
      dbmsList,
      bannerList,
      databases,
      users,
      hostname: typeof systemInfo.hostname === 'string' ? systemInfo.hostname : undefined,
      isDba: typeof systemInfo.isDba === 'boolean' ? systemInfo.isDba : undefined,
      webServerOs: typeof systemInfo.webServerOs === 'string' ? systemInfo.webServerOs : undefined,
      dbmsOs: typeof systemInfo.dbmsOs === 'string' ? systemInfo.dbmsOs : undefined,
      webTechnology: webTech
    };
  }, [report]);

  const overallVerdictChipClass = useMemo(() => {
    const level = (overallVerdict?.level || '').toString().toLowerCase();
    if (level === 'exploited') return 'bg-red-900 text-red-200 border border-red-700';
    if (level === 'confirmed') return 'bg-green-900 text-green-200 border border-green-700';
    if (level === 'suspected') return 'bg-yellow-900 text-yellow-200 border border-yellow-700';
    if (level === 'tested') return 'bg-gray-700 text-gray-200 border border-gray-600';
    if (level) return 'bg-blue-900 text-blue-200 border border-blue-700';
    return 'bg-gray-700 text-gray-200 border border-gray-600';
  }, [overallVerdict]);

  const fetchEvents = () => {
    if (!scanId) {
      setEvents([]);
      return;
    }
    setEventsLoading(true);
    setEventsError(null);
    getScanEvents(scanId)
      .then((data) => {
        setEvents(data);
        setEventsLastRefreshed(Date.now());
      })
      .catch((e) => {
        setEventsError(e.message || 'Failed to load events');
      })
      .finally(() => setEventsLoading(false));
  };

  useEffect(() => {
    if (activeTab !== 'activity') return;
    fetchEvents();
  }, [activeTab, scanId]);

  const formatConfidence = (score?: number) => {
    if (typeof score !== 'number') return '—';
    return `${Math.round(Math.min(1, Math.max(0, score)) * 100)}%`;
  };

  const formatStatus = (status?: string) => {
    if (!status) return 'Tested';
    const cleaned = status.replace(/[_\-]+/g, ' ').trim();
    return cleaned.replace(/\b\w/g, (c) => c.toUpperCase());
  };

  const composeConfidenceText = (label?: string | null, scoreText?: string | null) => {
    if (!label && !scoreText) return 'Unknown';
    if (!label) return scoreText || 'Unknown';
    return scoreText ? `${label} (${scoreText})` : label;
  };

  const getVerificationChipClass = (label?: string | null) => {
    const lowered = String(label || '').toLowerCase();
    if (lowered === 'confirmed') return 'bg-emerald-600 text-white border border-emerald-400';
    if (lowered === 'likely') return 'bg-amber-500 text-gray-900 border border-amber-300';
    if (lowered === 'inconclusive') return 'bg-orange-500 text-white border border-orange-300';
    if (lowered === 'suspected') return 'bg-rose-500 text-white border border-rose-300';
    return 'bg-slate-600 text-white border border-slate-400';
  };

  const isFalsePositive = (findingId: string) => {
    const fp = report?.metadata?.falsePositives || {};
    return !!fp[findingId];
  };

  const toggleFalsePositive = async (findingId: string) => {
    if (!report?.id) return;
    const next = !isFalsePositive(findingId);
    try {
      await apiFetch(`/api/reports/${report.id}/findings/${findingId}/false-positive`, {
        method: 'POST',
        body: JSON.stringify({ value: next })
      });
      // Refresh report to get updated metadata
      const nr = await apiFetch(`/api/reports/${reportId}`);
      setReport(nr);
      toast.success(next ? 'Marked as false positive' : 'False positive removed');
    } catch (e: any) {
      toast.error(e.message || 'Failed to update');
    }
  }

  const copyToClipboard = async (value: string, successMessage = 'Copied to clipboard') => {
    if (!value) return;
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const textArea = document.createElement('textarea');
        textArea.value = value;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
      toast.success(successMessage);
    } catch (err: any) {
      toast.error(err?.message || 'Failed to copy to clipboard');
    }
  };

  const snapshotPreference = (decision: 'store' | 'skip', remember: boolean) => {
    const nowIso = new Date().toISOString();
    setQuickVerifyPreference((prev) => ({
      userId: prev?.userId || 'self',
      storeEvidence: decision === 'store',
      rememberChoice: remember,
      promptSuppressed: false,
      promptVersion: prev?.promptVersion ?? 1,
      lastPromptAt: nowIso,
      lastDecisionAt: nowIso,
      updatedAt: nowIso,
      createdAt: prev?.createdAt ?? nowIso,
      source: 'report-details'
    }));
  };

  const runSingleVerification = async (
    findingId: string,
    options: { consent?: QuickVerifyConsentInput; manageGlobal?: boolean } = {}
  ) => {
    if (!report?.id) return;
    if (options.manageGlobal !== false) setGlobalVerifying(true);
    setVerifying((prev) => ({ ...prev, [findingId]: true }));
    try {
      const res = await apiVerifyFinding(
        report.id,
        findingId,
        options.consent ? { consent: { ...options.consent } } : undefined
      );
      if (res.consent?.preference) {
        setQuickVerifyPreference(res.consent.preference);
      }
      if (Array.isArray(res.rawEvidence) && res.rawEvidence.length > 0) {
        setEvidenceSummaries((prev) => ({ ...prev, [findingId]: res.rawEvidence as QuickVerifyEvidenceSummary[] }));
        setEvidenceErrors((prev) => ({ ...prev, [findingId]: null }));
      }
      setVerifyResult((prev) => ({ ...prev, [findingId]: res }));
      setVerifyMeta((prev) => ({ ...prev, [findingId]: { at: new Date().toISOString() } }));
      await refreshEvidenceList(findingId, { silent: true });
      try {
        const nr = await apiFetch(`/api/reports/${report.id}`);
        setReport(nr);
      } catch {
        /* non-fatal */
      }
      if (res.ok) {
        toast.success(`Verification: ${res.label} (${formatConfidence(res.score)})`);
      } else {
        toast.error('Verification failed');
      }
    } catch (e: any) {
      toast.error(e.message || 'Verification error');
    } finally {
      setVerifying((prev) => ({ ...prev, [findingId]: false }));
      if (options.manageGlobal !== false) setGlobalVerifying(false);
    }
  };

  const onVerify = async (findingId: string, consentOverride?: QuickVerifyConsentInput) => {
    if (!report?.id) return;
    const needsPrompt = !consentOverride && (!quickVerifyPreference || !quickVerifyPreference.rememberChoice);
    if (needsPrompt) {
      setConsentDecision(
        quickVerifyPreference?.storeEvidence === false ? 'skip' : 'store'
      );
      setConsentRemember(!!quickVerifyPreference?.rememberChoice);
      setPendingConsent({ findingIds: [findingId], mode: 'single' });
      return;
    }
    await runSingleVerification(findingId, consentOverride ? { consent: consentOverride } : {});
  };

  const shouldReverify = (findingId: string) => {
    const res = verifyResult[findingId];
    if (!res) return true; // never verified
    if (res.wafDetected) return true; // inconclusive due to WAF
    const label = res.label || '';
    if (label === 'Inconclusive' || label === 'Suspected') return true; // lower confidence
    return false;
  }

  const runBulkVerification = async (ids: string[], consentOverride?: QuickVerifyConsentInput) => {
    if (!report?.id || ids.length === 0) return;
    setGlobalVerifying(true);
    setVerifyAllRunning(true);
    setVerifyAllProgress({ done: 0, total: ids.length });
    let success = 0;
    let failed = 0;
    const concurrency = 3;
    const startDelayMs = 150;
    let index = 0;
    const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const worker = async () => {
      while (true) {
        const i = index++;
        if (i >= ids.length) break;
        const id = ids[i];
        await delay(startDelayMs);
        setVerifying((prev) => ({ ...prev, [id]: true }));
        try {
          const res = await apiVerifyFinding(
            report.id!,
            id,
            consentOverride ? { consent: { ...consentOverride } } : undefined
          );
          if (res.consent?.preference) {
            setQuickVerifyPreference(res.consent.preference);
          }
          if (Array.isArray(res.rawEvidence) && res.rawEvidence.length > 0) {
            setEvidenceSummaries((prev) => ({ ...prev, [id]: res.rawEvidence as QuickVerifyEvidenceSummary[] }));
            setEvidenceErrors((prev) => ({ ...prev, [id]: null }));
          }
          setVerifyResult((prev) => ({ ...prev, [id]: res }));
          setVerifyMeta((prev) => ({ ...prev, [id]: { at: new Date().toISOString() } }));
          await refreshEvidenceList(id, { silent: true });
          if (res.ok) success++;
          else failed++;
        } catch (_) {
          failed++;
        } finally {
          setVerifying((prev) => ({ ...prev, [id]: false }));
          setVerifyAllProgress((prev) => ({ ...prev, done: prev.done + 1, total: prev.total }));
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, () => worker()));
    setVerifyAllRunning(false);
    setGlobalVerifying(false);
    try {
      const nr = await apiFetch(`/api/reports/${report.id}`);
      setReport(nr);
    } catch {
      /* non-fatal */
    }
    if (failed === 0) {
      toast.success(`Verified all ${success} findings.`);
    } else if (success === 0) {
      toast.error(`All ${failed} verifications failed.`);
    } else {
      toast(`Verified ${success}, failed ${failed}.`, { icon: '⚠️' });
    }
  };

  const onVerifyAll = async (consentOverride?: QuickVerifyConsentInput) => {
    if (!report?.id) return;
    let ids = (report.vulnerabilities?.findings || []).map((f) => f.id).filter(Boolean);
    if (verifyOnlyChanged) {
      ids = ids.filter(shouldReverify);
    }
    if (ids.length === 0) return;
    const needsPrompt = !consentOverride && (!quickVerifyPreference || !quickVerifyPreference.rememberChoice);
    if (needsPrompt) {
      setConsentDecision(
        quickVerifyPreference?.storeEvidence === false ? 'skip' : 'store'
      );
      setConsentRemember(!!quickVerifyPreference?.rememberChoice);
      setPendingConsent({ findingIds: ids, mode: 'bulk' });
      return;
    }
    await runBulkVerification(ids, consentOverride);
  };

  const handleConsentConfirm = async () => {
    if (!pendingConsent) return;
    const targets = pendingConsent.findingIds;
    if (targets.length === 0) {
      setPendingConsent(null);
      return;
    }
    const nowIso = new Date().toISOString();
    const consent: QuickVerifyConsentInput = {
      storeEvidence: consentDecision === 'store',
      rememberChoice: consentRemember,
      promptVersion: (quickVerifyPreference?.promptVersion ?? 1),
      lastPromptAt: nowIso,
      source: 'report-details'
    };
    snapshotPreference(consentDecision, consentRemember);
    const mode = pendingConsent.mode;
    setPendingConsent(null);
    setConsentRemember(false);
    try {
      if (mode === 'single') {
        await runSingleVerification(targets[0], { consent });
      } else {
        await runBulkVerification(targets, consent);
      }
    } catch {
      // runSingleVerification/runBulkVerification already emit user-facing errors
    }
  };

  const handleConsentCancel = () => {
    setPendingConsent(null);
    setConsentRemember(false);
  };

  // Modal controls
  const openProofModal = async (src: string, title?: string) => {
    try {
      const blob = await fetchBlobWithAuth(src);
      const url = URL.createObjectURL(blob);
      setProofModal({ open: true, src: url, title });
    } catch (e: any) {
      toast.error(e.message || 'Failed to load proof');
      return;
    }
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };
  const closeProofModal = () => setProofModal({ open: false, src: '' });
  const onWheelZoom: React.WheelEventHandler<HTMLDivElement> = (e) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.1 : -0.1;
    setZoom((z) => Math.max(0.2, Math.min(4, z + delta)));
  };
  const startPanDrag: React.MouseEventHandler<HTMLDivElement> = (e) => {
    setPanning(true);
    setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };
  const onPanMove: React.MouseEventHandler<HTMLDivElement> = (e) => {
    if (!panning || !panStart) return;
    setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y });
  };
  const endPanDrag = () => {
    setPanning(false);
    setPanStart(null);
  };
  const resetZoomPan = () => { setZoom(1); setPan({ x: 0, y: 0 }); };

  const formatBytes = (value?: number | null): string => {
    if (value == null || Number.isNaN(value)) return 'n/a';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = Math.max(0, Number(value));
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit++;
    }
    return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
  };

  const formatDuration = (value?: number | null): string => {
    if (value == null || Number.isNaN(value)) return 'n/a';
    if (value < 1000) return `${Math.round(value)} ms`;
    return `${(value / 1000).toFixed(2)} s`;
  };

  const formatTimestamp = (value?: string | null): string => {
    if (!value) return 'Just now';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value;
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  };

  // Helper to fetch a protected URL with Authorization and return a blob
  const fetchWithAuth = async (path: string): Promise<Response> => {
    const token = localStorage.getItem('authToken') || '';
    let res: Response;
    try {
      res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : undefined });
    } catch (err: any) {
      // Provide a friendlier hint when the browser/extension blocks the request
      const msg = (err?.message || '').toLowerCase();
      if (msg.includes('failed to fetch') || msg.includes('blocked')) {
        throw new Error('Download was blocked by the browser or an extension. Please temporarily disable download managers (e.g., IDM) or ad blockers for this site and try again.');
      }
      throw err;
    }
    if (!res.ok) {
      let detail = '';
      try { detail = (await res.text()).slice(0, 200); } catch {}
      throw new Error(`Request failed (${res.status})${detail ? `: ${detail}` : ''}`);
    }
    return res;
  };

  const handleRawEvidenceDownload = async (evidenceId: string, preferredName?: string) => {
    if (!evidenceId) return;
    try {
      const res = await fetchWithAuth(`/api/quick-verify/evidence/${encodeURIComponent(evidenceId)}/download`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${preferredName || `quick-verify-${evidenceId}`}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success('Raw response downloaded.');
    } catch (err: any) {
      toast.error(err?.message || 'Failed to download raw response');
    }
  };

  // Convenience: get a Blob with auth
  const fetchBlobWithAuth = async (path: string): Promise<Blob> => {
    const res = await fetchWithAuth(path);
    return await res.blob();
  };

  const handleDownload = async (format: 'pdf' | 'json' | 'html') => {
    try {
      const res = await fetchWithAuth(`/api/reports/${reportId}/export/${format}`);
      const isPdfFallback = res.headers.get('x-pdf-fallback') === 'true';
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = isPdfFallback ? 'html' : format;
      a.download = `report-${reportId}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Report downloaded as ${ext.toUpperCase()}`);
    } catch (e: any) {
      const msg = String(e?.message || 'Failed to download');
      // Fallback: some extensions block fetch/XHR downloads; let the browser navigate to the URL instead
      const apiUrl = `/api/reports/${reportId}/export/${format}`;
      if (msg.toLowerCase().includes('failed to fetch') || msg.toLowerCase().includes('blocked')) {
        // Open in a new tab to avoid replacing the SPA; browser will handle Content-Disposition
        const link = document.createElement('a');
        link.href = apiUrl;
        link.target = '_blank';
        link.rel = 'noopener';
        // Attach auth header via token param if needed? Not safe; instead rely on cookie or bearer not possible.
        // As a compromise for blocked fetch, we try same-origin with bearer via a temporary window.fetch is not available.
        // If your backend requires Authorization header (Bearer), consider enabling cookie-based auth or creating a short-lived download token.
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        toast('Opening download in a new tab (if blocked by an extension, allow it).', { icon: '⬇️' });
      } else {
        toast.error(msg);
      }
    }
  };

  const verdictMeta = storeVerdictMeta ?? fetchedVerdictMeta;
  const verdictLoading = !storeVerdictMeta && verdictFetchLoading;
  const verdictError = verdictMeta ? null : verdictFetchError;
  const verdictOutcomeKey = (verdictMeta?.summary?.outcome ?? 'unknown') as ScanVerdictOutcome;
  const verdictOutcomeConfig = VERDICT_OUTCOME_STYLES[verdictOutcomeKey] ?? VERDICT_OUTCOME_STYLES.unknown;
  const VerdictIcon = verdictOutcomeConfig.icon;
  const handleDownloadVerdictMeta = useCallback(() => {
    if (!verdictMeta) {
      toast.error('No verdict data is available to download yet.');
      return;
    }
    try {
      const baseName = slugifyForFilename(
        report?.title ?? report?.id ?? derivedScanId,
        'scan'
      );
      const fileName = `${baseName}-verdict.json`;
      const blob = new Blob([JSON.stringify(verdictMeta, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to export verdict metadata';
      toast.error(message);
    }
  }, [derivedScanId, report, verdictMeta]);

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return <ErrorDisplay message={error} />;
  }

  if (!report) {
    return <ErrorDisplay message="Report not found." />;
  }

  return (
    <div className="container mx-auto p-6 bg-gray-900 text-white">
      {globalVerifying && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50" aria-busy="true" aria-live="polite">
          <div className="bg-gray-800 border border-gray-700 rounded-lg px-6 py-5 shadow-xl flex items-center gap-3">
            <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-blue-400"></div>
            <div className="text-gray-200 text-sm">
              {verifyAllRunning
                ? `Verifying ${verifyAllProgress.done}/${verifyAllProgress.total} findings…`
                : 'Verifying…'}
            </div>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <Link to="/reports" className="flex items-center text-blue-400 hover:text-blue-300 transition-colors">
          <ArrowLeft size={20} className="mr-2" />
          Back to Reports
        </Link>
        <div className="flex items-center gap-4">
          <button onClick={() => handleDownload('html')} className="btn-secondary flex items-center gap-2">
            <FileText size={18} />
            Download HTML
          </button>
          <button onClick={() => handleDownload('json')} className="btn-secondary flex items-center gap-2">
            <FileJson size={18} />
            Download JSON
          </button>
          {/* PDF export is behind a feature flag. To enable, set VITE_ENABLE_PDF_EXPORT=true and ENABLE_PDF_EXPORT=true on the server. */}
          {String(import.meta.env.VITE_ENABLE_PDF_EXPORT || 'false').toLowerCase() === 'true' && (
            <button onClick={() => handleDownload('pdf')} className="btn-primary flex items-center gap-2">
              <FileText size={18} />
              Download PDF
            </button>
          )}
        </div>
      </div>

      {/* Report Title */}
      <h1 className="text-4xl font-bold mb-2 text-blue-300">{report.title}</h1>
      <p className="text-gray-400 mb-8">Report ID: {report.id}</p>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-gray-400 text-sm font-bold uppercase">Target</h3>
          <p className="text-2xl font-semibold truncate" title={report.target}>{report.target}</p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-gray-400 text-sm font-bold uppercase">Status</h3>
          <p className="text-2xl font-semibold">{report.status}</p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-gray-400 text-sm font-bold uppercase">Scan Duration</h3>
          <p className="text-2xl font-semibold">
            {report.scanDuration != null && !isNaN(report.scanDuration) 
              ? `${(report.scanDuration / 1000).toFixed(2)}s` 
              : 'Unknown'}
          </p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-gray-400 text-sm font-bold uppercase">Date</h3>
          <p className="text-2xl font-semibold">
            {report.createdAt && !isNaN(new Date(report.createdAt).getTime())
              ? new Date(report.createdAt).toLocaleDateString()
              : 'Unknown'}
          </p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-gray-400 text-sm font-bold uppercase">Auth Mode</h3>
          <p className="text-2xl font-semibold">
            {(() => {
              const meta = (report as any)?.metadata || {};
              const mode = meta?.auth?.mode || meta?.auth?.type || 'none';
              const label = String(mode).toLowerCase();
              if (label === 'login') return 'Login Session';
              if (label === 'cookie') return 'Cookie/Header';
              if (label === 'none') return 'None';
              return mode;
            })()}
          </p>
        </div>
      </div>

      {(verdictMeta || verdictLoading || verdictError) && (
        <section className="mb-10 space-y-4" aria-live="polite">
          <div className="flex flex-wrap items-center gap-2">
            <VerdictIcon size={20} className="text-blue-300" />
            <h2 className="text-2xl font-semibold text-blue-100">Scan verdict intelligence</h2>
            <div className="ml-auto flex items-center gap-2">
              {verdictLoading && <span className="text-xs uppercase tracking-wide text-gray-400">Refreshing…</span>}
              {verdictMeta && (
                <button
                  type="button"
                  onClick={handleDownloadVerdictMeta}
                  className="inline-flex items-center gap-2 rounded border border-blue-400/40 bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-100 transition hover:bg-blue-500/20"
                >
                  <FileJson size={14} className="text-blue-200" />
                  Download JSON
                </button>
              )}
            </div>
          </div>
          {verdictError && !verdictMeta && (
            <div className="rounded-lg border border-red-700 bg-red-950/50 px-4 py-3 text-sm text-red-200">
              {verdictError}
            </div>
          )}
          {verdictMeta && (
            <div className="space-y-6">
              <div className={`rounded-lg p-6 shadow-lg shadow-black/40 ${verdictOutcomeConfig.card}`}>
                <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                  <div className="space-y-3">
                    <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${verdictOutcomeConfig.badge}`}>
                      <VerdictIcon size={16} className="shrink-0" />
                      {verdictOutcomeConfig.label}
                    </span>
                    {(verdictMeta.summary?.reason || verdictOutcomeConfig.description) && (
                      <p className="max-w-3xl text-sm leading-relaxed text-white/90 md:text-base">
                        {verdictMeta.summary?.reason ?? verdictOutcomeConfig.description}
                      </p>
                    )}
                    {verdictMeta.summary?.rawVerdictLine && (
                      <p className="max-w-3xl break-words rounded border border-white/10 bg-black/30 px-3 py-2 text-xs font-mono text-white/70">
                        Raw verdict: {verdictMeta.summary.rawVerdictLine}
                      </p>
                    )}
                  </div>
                  <dl className="grid grid-cols-2 gap-4 text-xs text-white/80 sm:text-sm md:text-right">
                    {typeof verdictMeta.summary?.exitCode === 'number' && (
                      <div>
                        <dt className="uppercase tracking-wide text-white/60">Exit Code</dt>
                        <dd className="text-lg font-semibold text-white">{verdictMeta.summary.exitCode}</dd>
                      </div>
                    )}
                    {typeof verdictMeta.summary?.evidenceCount === 'number' && (
                      <div>
                        <dt className="uppercase tracking-wide text-white/60">Evidence</dt>
                        <dd className="text-lg font-semibold text-white">{verdictMeta.summary.evidenceCount}</dd>
                      </div>
                    )}
                    {formatDateTime(verdictMeta.summary?.completedAt) && (
                      <div className="col-span-2">
                        <dt className="uppercase tracking-wide text-white/60">Completed</dt>
                        <dd className="font-semibold text-white">{formatDateTime(verdictMeta.summary?.completedAt)}</dd>
                      </div>
                    )}
                    {formatDateTime(verdictMeta.generatedAt) && (
                      <div className="col-span-2">
                        <dt className="uppercase tracking-wide text-white/60">Generated</dt>
                        <dd className="font-semibold text-white">{formatDateTime(verdictMeta.generatedAt)}</dd>
                      </div>
                    )}
                  </dl>
                </div>
                {(Array.isArray(verdictMeta.heuristics?.flaggedParameters) && verdictMeta.heuristics?.flaggedParameters?.length > 0) ||
                (Array.isArray(verdictMeta.heuristics?.dismissedParameters) && verdictMeta.heuristics?.dismissedParameters?.length > 0) ? (
                  <div className="mt-5 flex flex-wrap gap-3 text-xs text-white/80">
                    {Array.isArray(verdictMeta.heuristics?.flaggedParameters) && verdictMeta.heuristics?.flaggedParameters?.length > 0 && (
                      <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-black/30 px-3 py-1">
                        <Flag size={14} className="text-amber-300" />
                        {verdictMeta.heuristics?.flaggedParameters?.length} flagged
                      </span>
                    )}
                    {Array.isArray(verdictMeta.heuristics?.dismissedParameters) && verdictMeta.heuristics?.dismissedParameters?.length > 0 && (
                      <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-black/30 px-3 py-1">
                        <CheckCircle size={14} className="text-emerald-300" />
                        {verdictMeta.heuristics?.dismissedParameters?.length} auto-dismissed
                      </span>
                    )}
                  </div>
                ) : null}
                {verdictMeta.stats && (
                  <div className="mt-6 grid grid-cols-2 gap-4 text-xs text-white/80 sm:grid-cols-4 sm:text-sm">
                    <div>
                      <span className="block uppercase tracking-wide text-white/60">Confirmed</span>
                      <span className="text-lg font-semibold text-white">{verdictMeta.stats.confirmed}</span>
                    </div>
                    <div>
                      <span className="block uppercase tracking-wide text-white/60">Suspected</span>
                      <span className="text-lg font-semibold text-white">{verdictMeta.stats.suspected}</span>
                    </div>
                    <div>
                      <span className="block uppercase tracking-wide text-white/60">Dismissed</span>
                      <span className="text-lg font-semibold text-white">{verdictMeta.stats.dismissed}</span>
                    </div>
                    <div>
                      <span className="block uppercase tracking-wide text-white/60">Total Tested</span>
                      <span className="text-lg font-semibold text-white">{verdictMeta.stats.totalTested}</span>
                    </div>
                  </div>
                )}
              </div>
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="rounded-lg border border-gray-800 bg-gray-900/70 p-5">
                  <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white">
                    <Flag size={18} className="text-blue-300" />
                    Parameter outcomes
                  </h3>
                  {Array.isArray(verdictMeta.parameters) && verdictMeta.parameters.length > 0 ? (
                    <div className="space-y-4">
                      {verdictMeta.parameters.map((param, index) => {
                        const finalStatusKey = typeof param.finalStatus === 'string' ? param.finalStatus.toLowerCase() : 'unknown';
                        const badgeClass = PARAM_STATUS_STYLES[finalStatusKey] ?? PARAM_STATUS_STYLES.unknown;
                        const statusLabel = typeof param.finalStatus === 'string'
                          ? param.finalStatus.charAt(0).toUpperCase() + param.finalStatus.slice(1)
                          : 'Unknown';
                        const parameterKey = `${param.place || 'unknown'}-${param.name || index}`;
                        return (
                          <div key={parameterKey} className="rounded-md border border-gray-700/70 bg-black/30 p-4">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <div>
                                <p className="text-base font-semibold text-white">{param.name || 'Unnamed parameter'}</p>
                                <p className="text-xs uppercase tracking-wide text-gray-400">{param.place || 'Unknown location'}</p>
                              </div>
                              <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold capitalize ${badgeClass}`}>
                                {statusLabel}
                              </span>
                            </div>
                            {typeof param.confidence === 'number' && Number.isFinite(param.confidence) && (
                              <p className="mt-3 text-sm text-gray-300">
                                Confidence score: <span className="font-semibold text-white">{formatConfidence(param.confidence)}</span>
                              </p>
                            )}
                            {(param.heuristics?.flagged || param.heuristics?.dismissed) && (
                              <div className="mt-3 flex flex-wrap gap-2 text-[11px] uppercase tracking-wide">
                                {param.heuristics?.flagged && (
                                  <span className="rounded-full border border-amber-400/40 bg-amber-500/10 px-2 py-1 text-amber-200">Flagged heuristics</span>
                                )}
                                {param.heuristics?.dismissed && (
                                  <span className="rounded-full border border-emerald-400/40 bg-emerald-500/10 px-2 py-1 text-emerald-200">Dismissed heuristics</span>
                                )}
                              </div>
                            )}
                            {Array.isArray(param.techniques) && param.techniques.length > 0 && (
                              <div className="mt-3 flex flex-wrap gap-2 text-[11px] uppercase tracking-wide text-blue-200">
                                {param.techniques.slice(0, 6).map((tech, idx) => (
                                  <span key={`${parameterKey}-tech-${idx}`} className="rounded-full border border-blue-400/40 bg-blue-500/10 px-2 py-1">
                                    {tech}
                                  </span>
                                ))}
                                {param.techniques.length > 6 && (
                                  <span className="rounded-full border border-blue-400/40 bg-blue-500/10 px-2 py-1">+{param.techniques.length - 6} more</span>
                                )}
                              </div>
                            )}
                            {Array.isArray(param.payloads) && param.payloads.length > 0 && (
                              <div className="mt-3">
                                <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Payloads</h4>
                                <ul className="mt-1 space-y-1 text-xs font-mono text-gray-300">
                                  {param.payloads.slice(0, 3).map((payload, idx) => (
                                    <li key={`${parameterKey}-payload-${idx}`} className="break-all">{payload}</li>
                                  ))}
                                  {param.payloads.length > 3 && (
                                    <li className="text-gray-500">+{param.payloads.length - 3} more</li>
                                  )}
                                </ul>
                              </div>
                            )}
                            {Array.isArray(param.statuses) && param.statuses.length > 0 && (
                              <ul className="mt-3 space-y-2 text-xs text-gray-300">
                                {param.statuses.map((status, idx) => (
                                  <li key={`${parameterKey}-status-${idx}`} className="rounded border border-gray-700/60 bg-black/20 p-3">
                                    <div className="flex flex-wrap items-center justify-between gap-2">
                                      <span className="font-semibold text-white">{status.status || 'Status update'}</span>
                                      {formatDateTime(status.at ?? null) && (
                                        <span className="text-gray-400">{formatDateTime(status.at ?? null)}</span>
                                      )}
                                    </div>
                                    {status.detail && <p className="mt-1 leading-relaxed text-gray-400">{status.detail}</p>}
                                    {status.source && (
                                      <p className="mt-1 text-[10px] uppercase tracking-wide text-gray-500">Source: {status.source}</p>
                                    )}
                                  </li>
                                ))}
                              </ul>
                            )}
                            {Array.isArray(param.notes) && param.notes.length > 0 && (
                              <ul className="mt-3 space-y-1 text-xs text-gray-400">
                                {param.notes.map((note, idx) => (
                                  <li key={`${parameterKey}-note-${idx}`} className="flex gap-2">
                                    <span className="text-gray-600">•</span>
                                    <span>{note}</span>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-400">No parameter-level verdict details were captured for this scan.</p>
                  )}
                </div>
                <div className="rounded-lg border border-gray-800 bg-gray-900/70 p-5">
                  <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white">
                    <Activity size={18} className="text-blue-300" />
                    Timeline
                  </h3>
                  {Array.isArray(verdictMeta.timeline) && verdictMeta.timeline.length > 0 ? (
                    <ol className="space-y-3 text-sm text-gray-200">
                      {verdictMeta.timeline.map((event, idx) => (
                        <li key={`${event.type || 'event'}-${idx}`} className="rounded border border-gray-700/60 bg-black/20 p-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span>{formatTimelineLabel(event)}</span>
                            {formatDateTime(event.at ?? null) && (
                              <span className="text-xs text-gray-400">{formatDateTime(event.at ?? null)}</span>
                            )}
                          </div>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p className="text-sm text-gray-400">Timeline not available. This may be a legacy scan.</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-700 mb-4">
        <button
          className={`px-4 py-2 ${activeTab==='vulns' ? 'text-white border-b-2 border-blue-500' : 'text-gray-400'}`}
          onClick={() => setActiveTab('vulns')}
        >
          Vulnerabilities
        </button>
        <button
          className={`px-4 py-2 ${activeTab==='recs' ? 'text-white border-b-2 border-blue-500' : 'text-gray-400'}`}
          onClick={() => setActiveTab('recs')}
        >
          Recommendations
        </button>
        <button
          className={`px-4 py-2 ${activeTab==='command' ? 'text-white border-b-2 border-blue-500' : 'text-gray-400'}`}
          onClick={() => setActiveTab('command')}
        >
          Command
        </button>
        <button
          className={`px-4 py-2 ${activeTab==='outputs' ? 'text-white border-b-2 border-blue-500' : 'text-gray-400'}`}
          onClick={() => setActiveTab('outputs')}
        >
          Outputs
        </button>
        <button
          className={`px-4 py-2 ${activeTab==='activity' ? 'text-white border-b-2 border-blue-500' : 'text-gray-400'}`}
          onClick={() => setActiveTab('activity')}
        >
          Activity
        </button>
      </div>

      {activeTab === 'vulns' && (
      <div className="bg-gray-800 p-6 rounded-lg mb-8">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold flex items-center">
            <ExclamationTriangleIcon className="h-7 w-7 mr-3 text-red-400" />
            Vulnerabilities ({report.vulnerabilities?.total ?? 0})
          </h2>
          {report.vulnerabilities?.total > 0 && (
            <div className="flex items-center gap-3">
              {verifyAllRunning && (
                <span className="text-sm text-gray-300">Verifying {verifyAllProgress.done}/{verifyAllProgress.total}…</span>
              )}
              <label className="flex items-center gap-2 text-xs text-gray-300">
                <input
                  type="checkbox"
                  className="form-checkbox rounded border-gray-600 bg-gray-800"
                  checked={verifyOnlyChanged}
                  onChange={(e) => setVerifyOnlyChanged(e.target.checked)}
                />
                Re-verify changed since last run
              </label>
              <button
                className="btn-secondary text-sm px-3 py-1 disabled:opacity-60"
                onClick={() => {
                  void onVerifyAll();
                }}
                disabled={verifyAllRunning || (report.vulnerabilities?.findings || []).length === 0}
                title="Run verification for all findings"
              >
                {verifyAllRunning ? 'Verifying All…' : 'Verify All'}
              </button>
            </div>
          )}
        </div>
        
        {/* Vulnerability Summary */}
          {report.vulnerabilities?.total > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-red-900/20 border border-red-800 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-red-400">{report.vulnerabilities.critical || 0}</div>
              <div className="text-sm text-gray-400">Critical</div>
            </div>
            <div className="bg-orange-900/20 border border-orange-800 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-orange-400">{report.vulnerabilities.high || 0}</div>
              <div className="text-sm text-gray-400">High</div>
            </div>
            <div className="bg-yellow-900/20 border border-yellow-800 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-yellow-400">{report.vulnerabilities.medium || 0}</div>
              <div className="text-sm text-gray-400">Medium</div>
            </div>
            <div className="bg-blue-900/20 border border-blue-800 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-blue-400">{report.vulnerabilities.low || 0}</div>
              <div className="text-sm text-gray-400">Low</div>
            </div>
          </div>
          )}

        {severityLegendEntries.length > 0 && (
          <div className="mb-6 rounded-lg border border-gray-700 bg-gray-900/70 p-4">
            <div className="flex items-start gap-3 mb-3">
              <Flag className="h-5 w-5 text-orange-300 mt-1" />
              <div>
                <h3 className="text-base font-semibold text-white">How we grade severity</h3>
                <p className="text-xs text-gray-400 mt-1 max-w-3xl">
                  Critical findings mean SQLMap stacked multiple statements in a single request (data tampering risk). High findings confirm controllable single-statement injection that exposes sensitive data or logic. Medium and Low levels appear only when custom rules downgrade impact.
                </p>
              </div>
            </div>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {severityLegendEntries.map((entry) => (
                <div key={entry.key} className="rounded-md border border-gray-700 bg-gray-950/60 p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-semibold text-white uppercase tracking-wide">{entry.label}</span>
                    <span
                      className={`h-2 w-2 rounded-full ${
                        entry.key === 'critical'
                          ? 'bg-red-500'
                          : entry.key === 'high'
                          ? 'bg-orange-400'
                          : entry.key === 'medium'
                          ? 'bg-yellow-400'
                          : entry.key === 'low'
                          ? 'bg-blue-400'
                          : 'bg-gray-400'
                      }`}
                      aria-hidden="true"
                    ></span>
                  </div>
                  {entry.summary && <p className="text-sm text-gray-200 mb-2">{entry.summary}</p>}
                  {entry.detail && <p className="text-xs text-gray-400 mb-3 leading-relaxed">{entry.detail}</p>}
                  {entry.impacts.length > 0 && (
                    <div className="mb-3">
                      <p className="text-xs font-semibold text-gray-300 uppercase tracking-wide mb-1">Impact if exploited</p>
                      <ul className="list-disc list-inside text-xs text-gray-400 space-y-1">
                        {entry.impacts.map((impact, idx) => (
                          <li key={`${entry.key}-impact-${idx}`}>{impact}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {entry.techniques.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-gray-300 uppercase tracking-wide mb-1">Includes techniques</p>
                      <p className="text-xs text-gray-400">{entry.techniques.join(', ')}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {overallVerdict && (
          <div className="mb-6 rounded-lg border border-gray-700 bg-gray-900/70 p-5 flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div className="flex items-start gap-3">
              <span className={`px-3 py-1 rounded-full text-sm font-semibold uppercase ${overallVerdictChipClass}`}>
                {overallVerdict.level}
              </span>
              <div>
                <h3 className="text-lg font-semibold text-white">Overall Verdict</h3>
                <p className="text-sm text-gray-300 mt-1 max-w-2xl">
                  {overallVerdict.rationale || 'Summary not provided.'}
                </p>
              </div>
            </div>
            {Array.isArray(overallVerdict.affectedParameters) && overallVerdict.affectedParameters.length > 0 && (
              <div className="text-sm text-gray-300 md:text-right">
                <div className="uppercase text-xs text-gray-500 mb-1">Most impacted inputs</div>
                <ul className="space-y-1">
                  {overallVerdict.affectedParameters.map((item, index) => (
                    <li key={`${item.param}-${item.type}-${index}`} className="flex md:justify-end gap-2">
                      <code className="bg-gray-800 px-2 py-1 rounded text-green-400">{item.param}</code>
                      <span className="text-gray-400">({item.type})</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        <div className="space-y-6">
          {/* FP-only filter */}
          <div className="flex items-center justify-between mb-2">
            <div />
            <label className="flex items-center gap-2 text-xs text-gray-300">
              <input
                type="checkbox"
                className="form-checkbox rounded border-gray-600 bg-gray-800"
                checked={showFalsePositivesOnly}
                onChange={(e) => setShowFalsePositivesOnly(e.target.checked)}
              />
              Show false positives only
            </label>
          </div>

          {report.vulnerabilities?.findings?.length > 0 ? (
            <>
              <div className="bg-gray-900/70 border border-gray-700 rounded-lg p-4 text-xs text-gray-300 leading-relaxed">
                <p className="font-semibold text-gray-200 mb-1">How to read the confidence badges</p>
                <p>
                  <span className="text-gray-100">SQLMap</span> shows the confidence recorded during the full automated scan.
                  The <span className="text-gray-100">Quick verify</span> badge replays lightweight boolean / time / error probes
                  and, when possible, the strongest SQLMap payload. Use it as a fast sanity check: it adds confidence but never
                  lowers the original SQLMap score. Read both values together when deciding remediation.
                </p>
              </div>

              {shouldShowConsentReminder && (
                <div className="bg-amber-500/10 border border-amber-500/40 rounded-lg p-3 text-xs text-amber-100 flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                  <div>
                    Raw quick-verify responses aren’t being stored because prompts are suppressed. Re-enable evidence retention from Settings.
                  </div>
                  <Link
                    to="/settings"
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400 text-amber-100"
                  >
                    Open Settings
                  </Link>
                </div>
              )}

              {(showFalsePositivesOnly
                ? report.vulnerabilities.findings.filter((f) => isFalsePositive(f.id))
                : report.vulnerabilities.findings
              ).map((vuln) => {
                const sqlmapLabel = vuln.confidenceLabel || 'Unknown';
                const sqlmapScoreText = typeof vuln.confidenceScore === 'number' ? formatConfidence(vuln.confidenceScore) : null;
                const sqlmapConfidenceText = composeConfidenceText(sqlmapLabel, sqlmapScoreText);
                const verifyDetails = verifyResult[vuln.id];
                const verificationLabel = verifyDetails?.label;
                const verificationScoreText = typeof verifyDetails?.score === 'number' ? formatConfidence(verifyDetails.score) : null;
                const verificationConfidenceText = composeConfidenceText(verificationLabel, verificationScoreText);
                const verifyDom = verifyDetails?.dom;
                const verifySuggestions = verifyDetails?.suggestions ?? [];
                const verifyConfirmations = verifyDetails?.confirmations ?? [];
                const verifyPocEntries = verifyDetails?.poc ?? [];
                const wafIndicators = verifyDetails?.wafIndicators;
                const wafIndicatorList = [
                  wafIndicators?.header ? 'header' : undefined,
                  wafIndicators?.body ? 'body' : undefined,
                  wafIndicators?.status ? 'status' : undefined
                ].filter((value): value is string => typeof value === 'string');
                const seededPayloads = Array.isArray(verifyDetails?.seededPayloads)
                  ? verifyDetails.seededPayloads.filter((value) => typeof value === 'string' && value.trim().length > 0)
                  : [];
                const payloadAttempts = Array.isArray(verifyDetails?.payloadAttempts) ? verifyDetails.payloadAttempts : [];
                const payloadHit = Array.isArray(verifyDetails?.confirmations)
                  ? verifyDetails.confirmations.includes('payload')
                  : !!verifyDetails?.payloadConfirmed;
                const remediationSuspected = !!verifyDetails?.remediationSuspected;
                const extraSignals = Array.isArray(verifyDetails?.extraSignals) ? verifyDetails.extraSignals : [];
                const driftCheck = verifyDetails?.driftCheck || null;
                const bestPayload = typeof verifyDetails?.bestPayload === 'string' && verifyDetails.bestPayload.trim().length > 0
                  ? verifyDetails.bestPayload
                  : null;
                const verificationDuration = typeof verifyDetails?.verificationDurationMs === 'number' && Number.isFinite(verifyDetails.verificationDurationMs)
                  ? `${Math.max(verifyDetails.verificationDurationMs / 1000, 0).toFixed(1)}s`
                  : null;
                const verificationStartedAt = typeof verifyDetails?.verificationStartedAt === 'number' && Number.isFinite(verifyDetails.verificationStartedAt)
                  ? new Date(verifyDetails.verificationStartedAt).toLocaleString()
                  : null;
                const verificationCompletedAt = typeof verifyDetails?.verificationCompletedAt === 'number' && Number.isFinite(verifyDetails.verificationCompletedAt)
                  ? new Date(verifyDetails.verificationCompletedAt).toLocaleString()
                  : null;
                const storedEvidence = (() => {
                  const cached = evidenceSummaries[vuln.id];
                  if (Array.isArray(cached) && cached.length > 0) return cached;
                  if (Array.isArray(verifyDetails?.rawEvidence) && verifyDetails.rawEvidence.length > 0) return verifyDetails.rawEvidence;
                  return [] as QuickVerifyEvidenceSummary[];
                })();
                const evidenceIsLoading = !!evidenceLoading[vuln.id];
                const evidenceError = evidenceErrors[vuln.id] || null;
                const shouldShowEvidencePanel = !!verifyDetails;
                const quickVerifyTitle = verifyDetails
                  ? payloadHit
                    ? 'Quick verifier replayed the strongest SQLMap payload and detected a response delta'
                    : seededPayloads.length > 0
                      ? 'Quick verifier replayed SQLMap payloads but did not observe meaningful variance'
                      : 'Quick verifier runs lightweight boolean/time/error probes based on a safe baseline'
                  : 'Quick verifier has not been run yet';
                const baselineConfidence = verifyDetails?.baselineConfidence;
                const baselineConfidenceText = baselineConfidence
                  ? composeConfidenceText(
                      baselineConfidence.label ?? undefined,
                      typeof baselineConfidence.score === 'number' ? formatConfidence(baselineConfidence.score) : null
                    )
                  : null;
                const statusKey = (() => {
                  const base = (vuln.status || sqlmapLabel || 'tested').toString().toLowerCase() || 'tested';
                  if (verifyDetails?.ok && verificationLabel) {
                    const lowered = verificationLabel.toLowerCase();
                    if (lowered === 'confirmed') return 'confirmed';
                    if (lowered === 'likely' && base !== 'confirmed') return 'likely';
                    if (lowered === 'suspected' && !['confirmed', 'likely'].includes(base)) return 'suspected';
                    if (lowered === 'inconclusive') return base;
                  }
                  return base;
                })();
                const statusToneKey = statusKey === 'likely' ? 'suspected' : statusKey;
                const statusChipClass =
                  statusToneKey === 'confirmed'
                    ? 'bg-emerald-600 text-white border border-emerald-400'
                    : statusToneKey === 'suspected'
                      ? 'bg-amber-500 text-gray-900 border border-amber-300'
                      : 'bg-slate-600 text-white border border-slate-400';
                const httpMethod = vuln.httpMethod || (vuln as any).http_method || (vuln as any).method || null;
                const signals = Array.isArray(vuln.signals)
                  ? vuln.signals
                  : Array.isArray((vuln as any).signals)
                    ? (vuln as any).signals
                    : [];
                const whyShown = verifyResult[vuln.id]?.why || vuln.why;
                const discoveredAt = vuln.discoveredAt || (vuln as any).discovered_at;
                const parameterName = vuln.parameter || (vuln as any).parameter || 'Unknown';
                const severityStyle = getSeverityStyles(vuln.severity);
                const reportSlug = slugifyForFilename(report?.id, 'report');
                const vulnSlug = slugifyForFilename(vuln.id, 'finding');

                return (
                  <div key={vuln.id} className={`${severityStyle.card} p-6 rounded-lg shadow-lg`}>
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h3 className="text-xl font-semibold text-white">{vuln.type}</h3>
                        <div className="mt-1 flex flex-wrap gap-2 text-xs text-gray-300">
                          <span className={`px-2 py-0.5 rounded ${statusChipClass}`}>Status: {formatStatus(statusKey)}</span>
                          <span className="px-2 py-0.5 rounded bg-gray-700" title="Confidence recorded by SQLMap during the original scan">
                            SQLMap: {sqlmapConfidenceText}
                          </span>
                          {verifyDetails
                            ? (
                              <span
                                className={`px-2 py-0.5 rounded ${getVerificationChipClass(verificationLabel)}`}
                                title={quickVerifyTitle}
                              >
                                Quick verify: {verifyDetails.ok ? verificationConfidenceText : 'Failed'}
                                {payloadHit && (
                                  <span className="ml-2 inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-emerald-100">
                                    <CheckCircle size={12} /> payload
                                  </span>
                                )}
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300" title="No manual verification has been run yet">
                                Quick verify: Not run
                              </span>
                            )}
                          {httpMethod && (
                            <span className="px-2 py-0.5 rounded bg-gray-700 uppercase tracking-wide">Method: {httpMethod}</span>
                          )}
                          {signals.length > 0 && (
                            <span className="px-2 py-0.5 rounded bg-gray-700">Signals: {signals.join(', ')}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-sm font-bold uppercase px-3 py-1 rounded-full ${severityStyle.badge}`}>
                          {vuln.severity}
                        </span>
                        {verificationLabel && (
                          <span
                            className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                              verificationLabel === 'Confirmed'
                                ? 'bg-emerald-600 text-white border border-emerald-400'
                                : verificationLabel === 'Likely'
                                  ? 'bg-amber-500 text-gray-900 border border-amber-300'
                                  : verificationLabel === 'Inconclusive'
                                    ? 'bg-orange-500 text-white border border-orange-300'
                                    : 'bg-slate-600 text-white border border-slate-400'
                            }`}
                            title={`Verification: ${verificationLabel}`}
                          >
                            {verificationLabel}
                          </span>
                        )}
                        {verifyMeta[vuln.id]?.at && (
                          <span
                            className="text-xs text-gray-300 bg-gray-700 px-2 py-0.5 rounded"
                            title={new Date(verifyMeta[vuln.id].at).toLocaleString()}
                          >
                            Last verified: {new Date(verifyMeta[vuln.id].at).toLocaleDateString()}{' '}
                            {new Date(verifyMeta[vuln.id].at).toLocaleTimeString()}
                          </span>
                        )}
                        <button
                          className="ml-2 px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm disabled:opacity-60"
                          onClick={() => onVerify(vuln.id)}
                          disabled={!!verifying[vuln.id]}
                          title="Re-run minimal PoCs to verify"
                        >
                          {verifying[vuln.id] ? 'Verifying…' : 'Verify'}
                        </button>
                        <button
                          className={`ml-2 px-2 py-1 rounded text-xs border transition-colors ${
                            isFalsePositive(vuln.id)
                              ? 'bg-red-700/40 border-red-400 text-white'
                              : 'bg-gray-700 border-gray-600 text-gray-200'
                          }`}
                          onClick={() => toggleFalsePositive(vuln.id)}
                          title={isFalsePositive(vuln.id) ? 'Unmark False Positive' : 'Mark False Positive'}
                        >
                          <span className="inline-flex items-center gap-1">
                            <Flag size={12} /> {isFalsePositive(vuln.id) ? 'False Positive' : 'Mark FP'}
                          </span>
                        </button>
                      </div>
                    </div>

                    <div className="space-y-6">
                      {sqlmapSummary && (
                        <div className="bg-gray-800 p-5 rounded-lg border border-gray-700 shadow-lg">
                          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                              <FileText size={18} className="text-blue-300" /> SQLMap verdict
                            </h3>
                            {sqlmapSummary.verdictLine && (
                              <span className="text-sm text-gray-300">{sqlmapSummary.verdictLine}</span>
                            )}
                          </div>

                          {Array.isArray(sqlmapSummary.confirmed) && sqlmapSummary.confirmed.length > 0 && (
                            <div className="mt-4 space-y-3">
                              <div className="text-xs uppercase text-gray-400 tracking-wide">Confirmed injection points</div>
                              <div className="grid gap-3 md:grid-cols-2">
                                {sqlmapSummary.confirmed.map((entry, idx) => (
                                  <div key={`${entry.parameter || 'confirmed'}-${idx}`} className="bg-gray-900 border border-gray-700 rounded p-3">
                                    <div className="flex items-center justify-between text-sm text-gray-200 mb-2">
                                      <span className="font-semibold break-all">{entry.parameter || 'Unknown parameter'}</span>
                                      {entry.method && (
                                        <span className="px-2 py-0.5 bg-gray-800 rounded uppercase text-xs border border-gray-700">
                                          {entry.method}
                                        </span>
                                      )}
                                    </div>
                                    {entry.title && <div className="text-xs text-gray-400 mb-1 break-words">{entry.title}</div>}
                                    {entry.payload && (
                                      <div className="mt-2">
                                        <div className="text-xs text-gray-500 uppercase mb-1">Payload</div>
                                        <div className="bg-black/50 border border-gray-700 rounded p-2 text-xs text-green-300 font-mono break-all">
                                          {entry.payload}
                                        </div>
                                      </div>
                                    )}
                                    {entry.raw && (
                                      <details className="mt-2 text-xs text-gray-400">
                                        <summary className="cursor-pointer text-gray-500 hover:text-gray-300">View raw block</summary>
                                        <pre className="mt-1 whitespace-pre-wrap break-words bg-gray-950 border border-gray-800 rounded p-2 text-[11px] text-gray-300">
                                          {entry.raw}
                                        </pre>
                                      </details>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {sqlmapSummary.attempted && sqlmapSummary.attempted.length > 0 && (
                            <details className="mt-4 text-xs text-gray-400">
                              <summary className="cursor-pointer text-gray-500 hover:text-gray-300">
                                {sqlmapSummary.attempted.length} additional technique checks
                              </summary>
                              <ul className="mt-2 space-y-1 list-disc list-inside text-gray-400">
                                {sqlmapSummary.attempted.slice(0, 8).map((attempt, idx) => (
                                  <li key={idx}>{attempt.technique || attempt.line || 'Unknown technique'}</li>
                                ))}
                                {sqlmapSummary.attempted.length > 8 && (
                                  <li>+ {sqlmapSummary.attempted.length - 8} more</li>
                                )}
                              </ul>
                            </details>
                          )}

                          {sqlmapSummary.rawSection && (
                            <details className="mt-4 text-xs text-gray-400">
                              <summary className="cursor-pointer text-gray-500 hover:text-gray-300">Raw SQLMap summary</summary>
                              <pre className="mt-2 whitespace-pre-wrap break-words bg-gray-950 border border-gray-800 rounded p-3 text-[11px] text-gray-300">
                                {sqlmapSummary.rawSection}
                              </pre>
                            </details>
                          )}
                        </div>
                      )}

                      {extractionHighlights && (
                        <div className="bg-gray-800 p-5 rounded-lg border border-gray-700 shadow-lg">
                          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                            <ExternalLink size={18} className="text-emerald-300" /> Data extracted during exploitation
                          </h3>
                          <div className="mt-4 grid md:grid-cols-2 gap-4 text-sm text-gray-200">
                            {extractionHighlights.dbmsList.length > 0 && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">DBMS</div>
                                <ul className="space-y-1">
                                  {extractionHighlights.dbmsList.map((value, idx) => (
                                    <li key={`dbms-${idx}`} className="break-words">{value}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {extractionHighlights.bannerList.length > 0 && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">Banner</div>
                                <ul className="space-y-1">
                                  {extractionHighlights.bannerList.map((value, idx) => (
                                    <li key={`banner-${idx}`} className="break-words">{value}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {extractionHighlights.databases.length > 0 && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">Databases</div>
                                <ul className="space-y-1">
                                  {extractionHighlights.databases.map((db, idx) => (
                                    <li key={`database-${idx}`} className="break-all font-mono text-green-300">{db}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {extractionHighlights.users.length > 0 && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">Users</div>
                                <ul className="space-y-1">
                                  {extractionHighlights.users.map((user, idx) => (
                                    <li key={`user-${idx}`} className="break-all">{user}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {extractionHighlights.hostname && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">Database host</div>
                                <div className="break-all">{extractionHighlights.hostname}</div>
                              </div>
                            )}

                            {typeof extractionHighlights.isDba === 'boolean' && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">DBA privileges</div>
                                <div
                                  className={`inline-flex items-center px-2 py-1 rounded ${extractionHighlights.isDba ? 'bg-red-900/40 text-red-200 border border-red-600' : 'bg-gray-900 text-gray-300 border border-gray-700'}`}
                                >
                                  {extractionHighlights.isDba ? 'Yes (high risk)' : 'No'}
                                </div>
                              </div>
                            )}

                            {extractionHighlights.webTechnology.length > 0 && (
                              <div className="md:col-span-2">
                                <div className="text-xs uppercase text-gray-500 mb-1">Web technology stack</div>
                                <div className="flex flex-wrap gap-2">
                                  {extractionHighlights.webTechnology.map((tech, idx) => (
                                    <span key={`tech-${idx}`} className="px-2 py-1 rounded bg-gray-900 border border-gray-700 text-xs">{tech}</span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {extractionHighlights.webServerOs && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">Web server OS</div>
                                <div>{extractionHighlights.webServerOs}</div>
                              </div>
                            )}

                            {extractionHighlights.dbmsOs && (
                              <div>
                                <div className="text-xs uppercase text-gray-500 mb-1">DBMS OS</div>
                                <div>{extractionHighlights.dbmsOs}</div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                      <div>
                        <h4 className="text-sm font-semibold text-gray-300 mb-1">Description</h4>
                        <p className="text-gray-200">{vuln.description}</p>
                      </div>

                      {(parameterName || httpMethod) && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-1">Input Tested</h4>
                          <div className="flex items-center gap-2">
                            {httpMethod && (
                              <span className="px-2 py-1 rounded-full bg-gray-800 uppercase text-xs border border-gray-600">
                                {httpMethod}
                              </span>
                            )}
                            <code className="bg-gray-900 px-2 py-1 rounded text-green-400">{parameterName}</code>
                          </div>
                        </div>
                      )}

                      {vuln.payload && typeof vuln.payload === 'string' && vuln.payload.trim().length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-1">Confirmed Payload</h4>
                          <div className="bg-gray-900 border border-gray-700 rounded p-3 text-xs md:text-sm text-green-300 font-mono break-all relative">
                            <button
                              type="button"
                              onClick={() => copyToClipboard(vuln.payload!, 'Payload copied to clipboard')}
                              className="absolute top-2 right-2 text-xs px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 hover:bg-gray-700"
                            >
                              Copy
                            </button>
                            {vuln.payload}
                          </div>
                        </div>
                      )}

                      {vuln.sqlmapMetadata && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-1">SQLMap Context</h4>
                          <div className="grid gap-2 text-xs md:text-sm text-gray-200">
                            {(vuln.sqlmapMetadata.type || vuln.techniqueSummary) && (
                              <div>
                                <span className="text-gray-500 uppercase text-[11px] mr-1">Technique</span>
                                <span className="text-gray-200">{vuln.sqlmapMetadata.type || vuln.techniqueSummary}</span>
                              </div>
                            )}
                            {vuln.sqlmapMetadata.title && (
                              <div>
                                <span className="text-gray-500 uppercase text-[11px] mr-1">Title</span>
                                <span className="text-gray-200 break-words">{vuln.sqlmapMetadata.title}</span>
                              </div>
                            )}
                            {vuln.sqlmapMetadata.payload && !vuln.payload && (
                              <div className="text-gray-200">
                                <span className="text-gray-500 uppercase text-[11px] mr-1">Payload</span>
                                <span className="font-mono text-green-300 break-all">{vuln.sqlmapMetadata.payload}</span>
                              </div>
                            )}
                          </div>
                          {vuln.sqlmapMetadata.raw && (
                            <details className="mt-2 text-xs text-gray-400">
                              <summary className="cursor-pointer text-gray-500 hover:text-gray-300">View raw SQLMap block</summary>
                              <pre className="mt-2 whitespace-pre-wrap break-words bg-gray-950 border border-gray-800 rounded p-3 text-[11px] text-gray-300">
                                {vuln.sqlmapMetadata.raw}
                              </pre>
                            </details>
                          )}
                        </div>
                      )}

                      <div>
                        <h4 className="text-sm font-semibold text-gray-300 mb-1">Confidence</h4>
                        <div className="text-sm text-gray-200 space-y-1">
                          <div>
                            <span className="text-[11px] uppercase text-gray-500 mr-1">SQLMap</span>
                            <span className="font-medium text-white">{sqlmapConfidenceText}</span>
                          </div>
                          <div>
                            <span className="text-[11px] uppercase text-gray-500 mr-1">Quick verify</span>
                            <span
                              className={verifyDetails?.ok ? 'font-medium text-white' : verifyDetails ? 'font-medium text-amber-300' : 'text-gray-300'}
                            >
                              {verifyDetails
                                ? verifyDetails.ok
                                  ? verificationConfidenceText || 'Completed'
                                  : verifyDetails.label || 'Failed'
                                : 'Not run'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {whyShown && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-1">Why this is shown</h4>
                          <p className="text-gray-200">{whyShown}</p>
                        </div>
                      )}

                      {discoveredAt && (
                        <div className="text-xs text-gray-500">
                          First seen: {new Date(discoveredAt).toLocaleString()}
                        </div>
                      )}

                      {vuln.impact && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-1">Impact</h4>
                          <p className="text-gray-200">{vuln.impact}</p>
                        </div>
                      )}

                      {vuln.remediation && vuln.remediation.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-2">Remediation</h4>
                          <ul className="list-disc list-inside space-y-1 text-gray-200">
                            {vuln.remediation.map((rec, index) => (
                              <li key={index}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {vuln.evidence && vuln.evidence.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold text-gray-300 mb-2">Evidence</h4>
                          <div className="bg-gray-900 p-3 rounded max-h-32 overflow-y-auto">
                            {vuln.evidence.slice(0, 3).map((evidence, index) => (
                              <div key={index} className="text-sm text-gray-400 font-mono">
                                <span className="text-gray-500">Line {evidence.line}:</span> {evidence.content}
                              </div>
                            ))}
                            {vuln.evidence.length > 3 && (
                              <div className="text-xs text-gray-500 mt-2">
                                ...and {vuln.evidence.length - 3} more lines
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {verifyDetails && (
                        <div className="mt-4 p-3 rounded bg-gray-800 border border-gray-700">
                          <h4 className="text-sm font-semibold text-gray-200 mb-2">Verification Result</h4>
                          {verifyDetails.ok ? (
                            <div className="text-sm text-gray-200 space-y-3">
                              <div className="flex flex-wrap gap-6 text-xs uppercase tracking-wide text-gray-300">
                                <span className="px-2 py-1 rounded bg-gray-900 border border-gray-700">
                                  Label: <span className="font-semibold text-white normal-case">{verifyDetails.label ?? 'Unknown'}</span>
                                </span>
                                <span className="px-2 py-1 rounded bg-gray-900 border border-gray-700">
                                  Score: <span className="font-semibold text-white normal-case">{formatConfidence(verifyDetails.score)}</span>
                                </span>
                                {Array.isArray(verifyDetails.signals) && verifyDetails.signals.length > 0 && (
                                  <span className="px-2 py-1 rounded bg-gray-900 border border-gray-700 normal-case text-gray-200">
                                    Signals: {verifyDetails.signals.join(', ')}
                                  </span>
                                )}
                              </div>

                              {(verificationDuration || verificationStartedAt || verificationCompletedAt) && (
                                <div className="text-[11px] text-gray-400 mt-1 flex flex-wrap gap-3 normal-case">
                                  {verificationDuration && <span>Runtime: {verificationDuration}</span>}
                                  {verificationStartedAt && <span>Started: {verificationStartedAt}</span>}
                                  {verificationCompletedAt && <span>Finished: {verificationCompletedAt}</span>}
                                </div>
                              )}

                              {baselineConfidenceText && (
                                <div className="text-xs text-gray-400 mt-2 normal-case">
                                  SQLMap baseline: <span className="text-gray-200">{baselineConfidenceText}</span>
                                </div>
                              )}

                              {seededPayloads.length > 0 && (
                                <div className="mt-3 text-xs text-gray-300 space-y-2 normal-case">
                                  <div className={payloadHit ? 'text-emerald-300 font-medium' : 'text-gray-300 font-medium'}>
                                    {payloadHit ? 'Seeded payload replay detected a change.' : 'Seeded payload replay did not observe a change.'}
                                  </div>
                                  {bestPayload && (
                                    <div className="flex items-center gap-2 text-emerald-200">
                                      <CheckCircle size={12} className="text-emerald-300" />
                                      <span className="text-xs">
                                        Payload reused: <code className="bg-gray-900 border border-gray-700 rounded px-1.5 py-0.5 text-[11px] text-green-300">{bestPayload}</code>
                                      </span>
                                    </div>
                                  )}
                                  <div className="text-[11px] uppercase text-gray-500">Payloads replayed</div>
                                  <div className="space-y-1">
                                    {seededPayloads.slice(0, 3).map((payload, idx) => (
                                      <div key={`payload-${idx}`} className="flex items-start gap-2">
                                        <code className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-[11px] text-green-300 break-all flex-1">{payload}</code>
                                        <button
                                          type="button"
                                          className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 hover:bg-gray-700 border border-gray-600 text-gray-200"
                                          onClick={() => copyToClipboard(payload, 'Payload copied to clipboard')}
                                        >
                                          Copy
                                        </button>
                                      </div>
                                    ))}
                                  </div>
                                  {seededPayloads.length > 3 && (
                                    <div className="text-[11px] text-gray-500">…and {seededPayloads.length - 3} more</div>
                                  )}
                                </div>
                              )}

                              {payloadAttempts.length > 0 && (
                                <details className="mt-3 text-xs text-gray-400">
                                  <summary className="cursor-pointer text-gray-500 hover:text-gray-300">Replay responses</summary>
                                  <div className="mt-2 space-y-2">
                                    {payloadAttempts.slice(0, 3).map((attempt, idx) => {
                                      const diff = attempt.diff || {};
                                      const hasDiff = diff && diff.identical === false;
                                      const diffSummary = hasDiff
                                        ? `Δ +${diff.added ?? 0} / -${diff.removed ?? 0} / ≠ ${diff.changed ?? 0}`
                                        : 'No significant body diff';
                                      return (
                                        <div key={`attempt-${idx}`} className="bg-gray-900 border border-gray-700 rounded p-2 space-y-1">
                                          <div className="flex items-center justify-between gap-2">
                                            <code className="text-[11px] text-green-300 break-all">{attempt.payload}</code>
                                            <span className="text-[11px] text-gray-400">{attempt.status} • {attempt.timeMs}ms</span>
                                          </div>
                                          <div className="text-[11px] text-gray-400">{diffSummary}</div>
                                          {attempt.fingerprintDiff && (
                                            <div className="text-[11px] text-gray-500">
                                              Δ status: {attempt.fingerprintDiff.statusChanged ? 'yes' : 'no'}; Δ length: {attempt.fingerprintDiff.lengthDelta ?? 0}
                                              {(() => {
                                                const headers = attempt.fingerprintDiff?.headers;
                                                if (!headers) return null;
                                                const added = headers.added?.length || 0;
                                                const removed = headers.removed?.length || 0;
                                                const changed = headers.changed?.length || 0;
                                                if (added + removed + changed === 0) return null;
                                                return <span> • headers ± {added + removed + changed}</span>;
                                              })()}
                                            </div>
                                          )}
                                          <code className="text-[11px] text-blue-300 break-all" title={attempt.url}>{attempt.url}</code>
                                        </div>
                                      );
                                    })}
                                    {payloadAttempts.length > 3 && (
                                      <div className="text-[11px] text-gray-500">…{payloadAttempts.length - 3} more attempts captured.</div>
                                    )}
                                  </div>
                                </details>
                              )}

                              {remediationSuspected ? (
                                <div className="mt-3 p-3 rounded border border-amber-600 bg-amber-500/10 text-xs text-amber-100 space-y-1">
                                  <div className="flex items-center gap-2 font-semibold text-amber-100">
                                    <ExclamationTriangleIcon className="h-4 w-4" />
                                    <span>Baseline drift detected</span>
                                  </div>
                                  <p className="text-amber-200/90 normal-case">
                                    Quick verify observed a notable change in the clean baseline after replaying payloads. Treat the original finding with caution and consider re-running a full scan.
                                  </p>
                                  {driftCheck && (
                                    <div className="text-[11px] text-amber-200/80 space-y-1">
                                      <div>Replay baseline status: {driftCheck.status ?? 'n/a'} • {driftCheck.timeMs ?? '—'}ms</div>
                                      {driftCheck.fingerprintDiff && (
                                        <div>
                                          Δ status: {driftCheck.fingerprintDiff.statusChanged ? 'yes' : 'no'}; Δ length: {driftCheck.fingerprintDiff.lengthDelta ?? 0}
                                          {(() => {
                                            const headers = driftCheck.fingerprintDiff?.headers;
                                            if (!headers) return null;
                                            const added = headers.added?.length || 0;
                                            const removed = headers.removed?.length || 0;
                                            const changed = headers.changed?.length || 0;
                                            if (added + removed + changed === 0) return null;
                                            return <span> • headers ± {added + removed + changed}</span>;
                                          })()}
                                        </div>
                                      )}
                                      {driftCheck.contentDiff && driftCheck.contentDiff.identical === false && (
                                        <div>Body diff: +{driftCheck.contentDiff.added ?? 0} / -{driftCheck.contentDiff.removed ?? 0} / ≠ {driftCheck.contentDiff.changed ?? 0}</div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              ) : driftCheck ? (
                                <div className="mt-3 p-3 rounded border border-gray-700 bg-gray-900 text-xs text-gray-300 space-y-1">
                                  <div className="font-semibold text-gray-200">Baseline stable</div>
                                  <div className="normal-case text-gray-300">
                                    Baseline replay matched the earlier response fingerprint. No remediation drift detected.
                                  </div>
                                  <div className="text-[11px] text-gray-500">
                                    Status {driftCheck.status ?? 'n/a'} • {driftCheck.timeMs ?? '—'}ms
                                  </div>
                                </div>
                              ) : null}

                              {extraSignals.length > 0 && (
                                <details className="mt-3 text-xs text-gray-300">
                                  <summary className="cursor-pointer text-gray-400 hover:text-gray-200">
                                    Extra signals ({extraSignals.length})
                                  </summary>
                                  <div className="mt-2 space-y-2">
                                    {extraSignals.slice(0, 6).map((signal, idx) => (
                                      <div key={`extra-signal-${idx}`} className="bg-gray-900 border border-gray-700 rounded p-2 space-y-1">
                                        <div className="text-[11px] uppercase text-gray-500">{signal.type}</div>
                                        <div className="text-xs text-gray-200 normal-case">{signal.description}</div>
                                        {signal.payload && (
                                          <code className="block bg-gray-950 border border-gray-800 rounded px-2 py-1 text-[11px] text-green-300 break-all">{signal.payload}</code>
                                        )}
                                        {signal.fingerprintDiff && (
                                          <div className="text-[11px] text-gray-500">
                                            Δ status: {signal.fingerprintDiff.statusChanged ? 'yes' : 'no'}; Δ length: {signal.fingerprintDiff.lengthDelta ?? 0}
                                            {(() => {
                                              const headers = signal.fingerprintDiff?.headers;
                                              if (!headers) return null;
                                              const added = headers.added?.length || 0;
                                              const removed = headers.removed?.length || 0;
                                              const changed = headers.changed?.length || 0;
                                              if (added + removed + changed === 0) return null;
                                              return <span> • headers ± {added + removed + changed}</span>;
                                            })()}
                                          </div>
                                        )}
                                        {signal.contentDiff && signal.contentDiff.identical === false && (
                                          <div className="text-[11px] text-gray-500">
                                            Body diff: +{signal.contentDiff.added ?? 0} / -{signal.contentDiff.removed ?? 0} / ≠ {signal.contentDiff.changed ?? 0}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                    {extraSignals.length > 6 && (
                                      <div className="text-[11px] text-gray-500">…+{extraSignals.length - 6} additional signals stored in the activity log.</div>
                                    )}
                                  </div>
                                </details>
                              )}

                              {verifyDetails.why && (
                                <div className="text-gray-300 normal-case">Why: {verifyDetails.why}</div>
                              )}

                              {verifyConfirmations.length > 0 && (
                                <div className="text-xs text-green-300">
                                  Signals confirmed: {verifyConfirmations.join(', ')}
                                </div>
                              )}

                              {verifySuggestions.length > 0 && (
                                <div className="text-gray-300">
                                  Suggestions:
                                  <ul className="list-disc list-inside pl-4 mt-1 space-y-1 text-gray-200 normal-case">
                                    {verifySuggestions.map((s, i) => (
                                      <li key={i}>{s}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}

                              {verifyDom?.checked ? (
                                <div className="mt-2 p-2 rounded bg-gray-900 border border-gray-700 space-y-2">
                                  <div className="flex items-center gap-2 text-xs text-gray-300">
                                    <ImageIcon size={14} className="text-blue-300" />
                                    <span>DOM validation:</span>
                                    <span className={verifyDom.reflected ? 'text-green-300' : 'text-red-300'}>
                                      {verifyDom.reflected ? 'Reflected' : 'Not reflected'}
                                    </span>
                                    {verifyDom.url && <span className="text-gray-400 truncate">• {verifyDom.url}</span>}
                                  </div>
                                  {Array.isArray(verifyDom.matches) && verifyDom.matches.length > 0 && (
                                    <div className="text-xs text-gray-400 space-y-1">
                                      <div className="font-medium text-gray-300">Matches:</div>
                                      <ul className="list-disc pl-5 space-y-1">
                                        {verifyDom.matches.slice(0, 3).map((m, i) => {
                                          const selectorText = `${m.selector}${m.mode === 'attribute' && m.attribute ? ` [@${m.attribute}]` : ''}`;
                                          return (
                                            <li key={i} className="flex items-center gap-2">
                                              <code className="bg-gray-800 px-1 py-0.5 rounded">{selectorText}</code>
                                              <button
                                                type="button"
                                                className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700 hover:bg-gray-600 border border-gray-600"
                                                onClick={async () => {
                                                  try {
                                                    await navigator.clipboard.writeText(selectorText);
                                                    toast.success('Selector copied');
                                                  } catch {
                                                    toast.error('Copy failed');
                                                  }
                                                }}
                                                title="Copy selector"
                                              >
                                                Copy
                                              </button>
                                            </li>
                                          );
                                        })}
                                        {verifyDom.matches.length > 3 && (
                                          <li className="text-gray-500">…and {verifyDom.matches.length - 3} more</li>
                                        )}
                                      </ul>
                                    </div>
                                  )}
                                  {verifyDom.proof?.filename && (
                                    <div className="pt-2 border-t border-gray-800">
                                      <div className="flex items-center gap-3 mb-2">
                                        <button
                                          type="button"
                                          className="text-xs text-blue-300 hover:text-blue-200 flex items-center gap-1"
                                          title="Open proof image in a new tab"
                                          onClick={async () => {
                                            try {
                                              const blob = await fetchBlobWithAuth(`/api/reports/${encodeURIComponent(report.id)}/proof/${encodeURIComponent(verifyDom.proof!.filename)}`);
                                              const url = URL.createObjectURL(blob);
                                              window.open(url, '_blank');
                                              setTimeout(() => URL.revokeObjectURL(url), 60_000);
                                            } catch (e: any) {
                                              toast.error(e.message || 'Failed to open proof');
                                            }
                                          }}
                                        >
                                          Open in new tab <ExternalLink size={12} />
                                        </button>
                                        <button
                                          type="button"
                                          className="text-xs px-2 py-1 rounded bg-gray-700 hover:bg-gray-600 border border-gray-600"
                                          onClick={() => openProofModal(`/api/reports/${encodeURIComponent(report.id)}/proof/${encodeURIComponent(verifyDom.proof!.filename)}`, `Proof for ${vuln.type}`)}
                                          title="View full proof"
                                        >
                                          View full proof
                                        </button>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <div className="mt-2 p-2 rounded bg-gray-900 border border-gray-800 text-xs text-gray-400">
                                  {verifyDetails.wafDetected
                                    ? 'DOM validation skipped due to WAF indicators.'
                                    : 'DOM validation not attempted (method may not be GET or unsupported).'}
                                </div>
                              )}

                              {verifyDetails.wafDetected && (
                                <div className="mt-2 p-3 rounded bg-yellow-900/30 border border-yellow-800 space-y-2 text-xs">
                                  <div className="text-yellow-300 font-medium">WAF indicators detected. Result may be inconclusive.</div>
                                  <div className="flex flex-wrap items-center gap-2">
                                    <button
                                      type="button"
                                      className="px-2 py-1 text-xs bg-gray-700 border border-gray-600 rounded hover:bg-gray-600"
                                      onClick={() => {
                                        applyWafSuggestions(wafPreset('standard'));
                                        toast.success('WAF-friendly flags loaded in Terminal (Custom profile).');
                                      }}
                                      title="Load recommended WAF-friendly flags into Terminal"
                                    >
                                      Apply WAF suggestions
                                    </button>
                                    <button
                                      type="button"
                                      className="px-2 py-1 text-xs bg-green-700 border border-green-600 rounded hover:bg-green-600"
                                      onClick={() => {
                                        if (!report?.target) {
                                          toast.error('Report target unavailable');
                                          return;
                                        }
                                        const flags = wafPreset('standard');
                                        applyWafSuggestions(flags);
                                        const doStart = () => {
                                          try {
                                            startScan(report.target, { target: report.target, profile: 'custom', customFlags: flags }, 'custom');
                                            toast.success('Starting new scan with WAF-friendly settings…');
                                            navigate('/terminal');
                                          } catch (e: any) {
                                            toast.error(e?.message || 'Failed to start scan');
                                          }
                                        };
                                        if (runningScanCount > 0) {
                                          const confirmStop = window.confirm('A scan appears to be running. Terminate the current scan and start a new one with WAF-friendly settings?');
                                          if (confirmStop) {
                                            terminateScan();
                                            toast('Terminating current scan…', { icon: '🛑' });
                                            setTimeout(doStart, 800);
                                          } else {
                                            doStart();
                                          }
                                        } else {
                                          doStart();
                                        }
                                      }}
                                      title="Apply flags and start a new scan on this report's target"
                                    >
                                      Apply & Start New Scan
                                    </button>
                                    <Link
                                      to="/terminal"
                                      className="text-xs text-blue-300 hover:text-blue-200"
                                      title="Open Terminal to start a new scan"
                                    >
                                      Open Terminal
                                    </Link>
                                  </div>
                                  {(wafIndicatorList.length > 0 || (wafIndicators?.sources?.length ?? 0) > 0) && (
                                    <div className="text-yellow-200">
                                      Indicators: {wafIndicatorList.length > 0 ? wafIndicatorList.join(', ') : 'generic'}
                                      {(wafIndicators?.sources?.length ?? 0) > 0 && (
                                        <> · Sources: {wafIndicators?.sources?.join(', ')}</>
                                      )}
                                    </div>
                                  )}
                                </div>
                              )}

                              {verifyDetails.consent && (
                                <div className={`mt-3 p-3 rounded border text-xs ${
                                  verifyDetails.consent.decision
                                    ? 'border-emerald-500/40 bg-emerald-900/20 text-emerald-100'
                                    : 'border-slate-600/40 bg-slate-900/40 text-gray-200'
                                }`}>
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <span className="font-semibold">
                                      {verifyDetails.consent.decision
                                        ? 'Raw responses were stored for this verification.'
                                        : 'Raw responses were not stored for this verification.'}
                                    </span>
                                    {verifyDetails.consent.preference?.rememberChoice && (
                                      <span className="text-[11px] uppercase tracking-wide opacity-80">Preference remembered</span>
                                    )}
                                  </div>
                                  {verifyDetails.consent.preference?.lastDecisionAt && (
                                    <div className="mt-1 text-[11px] opacity-80">
                                      Last decision:{' '}
                                      {formatTimestamp(verifyDetails.consent.preference.lastDecisionAt)}
                                    </div>
                                  )}
                                  {!verifyDetails.consent.decision && (
                                    <div className="mt-2 text-[11px] opacity-90">
                                      You can re-run verification and allow storage to capture raw response bodies for forensic review.
                                    </div>
                                  )}
                                </div>
                              )}

                              {shouldShowEvidencePanel && (
                                <div className="mt-3 bg-gray-900 border border-gray-800 rounded p-3 text-xs text-gray-200">
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="uppercase text-[11px] tracking-wide text-gray-400">
                                      Stored raw responses
                                      {storedEvidence.length > 0 && ` (${storedEvidence.length})`}
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <button
                                        type="button"
                                        className="px-2 py-0.5 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 disabled:opacity-60"
                                        onClick={() => refreshEvidenceList(vuln.id)}
                                        disabled={evidenceIsLoading}
                                      >
                                        {evidenceIsLoading ? 'Refreshing…' : 'Refresh'}
                                      </button>
                                    </div>
                                  </div>
                                  {evidenceError && (
                                    <div className="mt-2 text-red-300 text-[11px]">{evidenceError}</div>
                                  )}
                                  {!evidenceError && evidenceIsLoading && storedEvidence.length === 0 && (
                                    <div className="mt-2 text-gray-400 text-[11px]">Loading stored responses…</div>
                                  )}
                                  {!evidenceError && !evidenceIsLoading && storedEvidence.length === 0 && (
                                    <div className="mt-2 text-gray-400 text-[11px]">No stored responses yet for this finding.</div>
                                  )}
                                  {storedEvidence.length > 0 && (
                                    <ul className="mt-2 space-y-2">
                                      {storedEvidence.slice(0, 5).map((item) => (
                                        <li key={item.id || item.key} className="bg-gray-950 border border-gray-800 rounded p-2 space-y-1">
                                          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                                            <span className="font-mono text-blue-200 break-all">{item.tag || item.scope || item.key}</span>
                                            <span className="text-gray-400">{formatTimestamp(item.createdAt)}</span>
                                          </div>
                                          <div className="flex flex-wrap items-center gap-3 text-[11px] text-gray-400">
                                            {item.status != null && <span>HTTP {item.status}</span>}
                                            {item.timeMs != null && <span>{formatDuration(item.timeMs)}</span>}
                                            {item.bodyLength != null && <span>{formatBytes(item.bodyLength)}</span>}
                                            {item.bodyHash && (
                                              <span className="font-mono text-gray-500">hash {item.bodyHash.slice(0, 12)}…</span>
                                            )}
                                          </div>
                                          {item.url && (
                                            <div className="text-[11px] text-gray-500 break-all">{item.url}</div>
                                          )}
                                          <div className="flex items-center justify-between gap-2 text-[11px] text-gray-400">
                                            <span className="opacity-80">Key: {item.key}</span>
                                            {item.id ? (
                                              <button
                                                type="button"
                                                className="px-2 py-0.5 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200"
                                                onClick={() => handleRawEvidenceDownload(item.id as string, `${report.id}-${vuln.id}-${item.tag || item.scope || item.key}`)}
                                              >
                                                Download JSON
                                              </button>
                                            ) : (
                                              <span className="text-gray-500">Transient (not retained)</span>
                                            )}
                                          </div>
                                        </li>
                                      ))}
                                    </ul>
                                  )}
                                  {storedEvidence.length > 5 && (
                                    <div className="mt-2 text-[11px] text-gray-500">Showing first 5 of {storedEvidence.length} entries.</div>
                                  )}
                                </div>
                              )}

                              {verifyPocEntries.length > 0 && (
                                <div className="mt-2">
                                  <div className="text-xs text-gray-400 mb-1">Proof-of-Concept (cURL):</div>
                                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                                    {verifyPocEntries.map((p, i) => {
                                      const matchingStoredEvidence = p.rawEvidenceId
                                        ? storedEvidence.find((item) => item.id === p.rawEvidenceId)
                                        : undefined;
                                      const pocSlug = slugifyForFilename(p.name, `poc-${i + 1}`);
                                      const baselineFilename = `${reportSlug}-${vulnSlug}-${pocSlug}-baseline.json`;
                                      const currentFilename = `${reportSlug}-${vulnSlug}-${pocSlug}-current.json`;
                                      const showDiffGuidance = !!p.rawEvidenceId;

                                      return (
                                        <div key={i} className="bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono whitespace-pre-wrap break-words">
                                          <div className="flex items-center justify-between mb-1 text-[11px] text-gray-400">
                                            <span className="uppercase tracking-wide">#{p.name}</span>
                                            <button
                                              type="button"
                                              className="px-2 py-0.5 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200"
                                              onClick={() => copyToClipboard(p.curl, 'cURL copied to clipboard')}
                                            >
                                              Copy
                                            </button>
                                          </div>
                                          <pre className="m-0 whitespace-pre-wrap text-[11px] text-gray-200 select-text">
                                            {p.curl}
                                          </pre>
                                          {p.expectedSignal && (
                                            <div className="mt-2 bg-blue-900/20 border border-blue-800 rounded p-2 text-[11px] text-blue-100 space-y-1">
                                              <div className="uppercase tracking-wide text-blue-300/80">Expected signal</div>
                                              {p.expectedSignal.summary && (
                                                <div className="text-[11px] text-blue-100/90">{p.expectedSignal.summary}</div>
                                              )}
                                              {p.expectedSignal.metrics && Object.keys(p.expectedSignal.metrics).length > 0 && (
                                                <div className="grid grid-cols-2 gap-2 text-[11px] text-blue-100">
                                                  {Object.entries(p.expectedSignal.metrics).map(([key, value]) => (
                                                    <div key={key} className="flex items-center justify-between gap-2">
                                                      <span className="text-blue-300/80">{key}</span>
                                                      <span>{String(value ?? 'n/a')}</span>
                                                    </div>
                                                  ))}
                                                </div>
                                              )}
                                            </div>
                                          )}
                                          {p.evidencePreview && (
                                            <div className="mt-2 bg-gray-950 border border-gray-800 rounded p-2 text-[11px] text-gray-200 space-y-2">
                                              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                                                <span className="text-gray-400 uppercase tracking-wide">Response snapshot</span>
                                                {typeof p.evidencePreview.status === 'number' && (
                                                  <span className="text-emerald-300">HTTP {p.evidencePreview.status}</span>
                                                )}
                                                {p.evidencePreview.length != null && (
                                                  <span className="text-gray-400">Size {formatBytes(p.evidencePreview.length)}</span>
                                                )}
                                                {p.evidencePreview.timeMs != null && (
                                                  <span className="text-gray-400">Latency {formatDuration(p.evidencePreview.timeMs)}</span>
                                                )}
                                                {p.evidencePreview.hash && (
                                                  <span className="font-mono text-gray-500">hash {p.evidencePreview.hash.slice(0, 12)}…</span>
                                                )}
                                              </div>
                                              {p.evidencePreview.url && (
                                                <div className="text-gray-400 break-all">URL: {p.evidencePreview.url}</div>
                                              )}
                                              {p.evidencePreview.excerpt && (
                                                <pre className="bg-black/60 border border-gray-900 rounded p-2 text-[11px] text-gray-300 whitespace-pre-wrap max-h-32 overflow-y-auto">
                                                  {p.evidencePreview.excerpt}
                                                </pre>
                                              )}
                                            </div>
                                          )}
                                          {(p.rawEvidenceHash || p.rawEvidenceLength != null || p.rawEvidenceId) && (
                                            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-gray-400">
                                              <div className="flex flex-wrap items-center gap-2">
                                                {p.rawEvidenceHash && (
                                                  <span className="font-mono text-gray-500">hash {p.rawEvidenceHash.slice(0, 12)}…</span>
                                                )}
                                                {p.rawEvidenceLength != null && (
                                                  <span>~{formatBytes(p.rawEvidenceLength)}</span>
                                                )}
                                              </div>
                                              {p.rawEvidenceId ? (
                                                <button
                                                  type="button"
                                                  className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200"
                                                  onClick={() => handleRawEvidenceDownload(p.rawEvidenceId as string, `${report.id}-${vuln.id}-${p.name}`)}
                                                >
                                                  Download response
                                                </button>
                                              ) : (
                                                <span className="text-gray-500">Raw body not stored (consent withheld)</span>
                                              )}
                                            </div>
                                          )}
                                          {showDiffGuidance && (
                                            <div className="mt-2 bg-indigo-950/40 border border-indigo-900/60 rounded p-2 text-[11px] text-indigo-100 space-y-2">
                                              <div className="flex flex-wrap items-center justify-between gap-2">
                                                <span className="uppercase tracking-wide text-indigo-300">Diff guidance</span>
                                                {matchingStoredEvidence?.bodyHash && (
                                                  <span className="font-mono text-indigo-200/80">hash {matchingStoredEvidence.bodyHash.slice(0, 12)}…</span>
                                                )}
                                              </div>
                                              <p className="text-indigo-100/80">
                                                Download the stored baseline (rename to{' '}
                                                <span className="font-mono text-indigo-200">{baselineFilename}</span>) and re-run the PoC into{' '}
                                                <span className="font-mono text-indigo-200">{currentFilename}</span>, then compare the two files locally.
                                              </p>
                                              <div className="grid gap-2 md:grid-cols-2">
                                                <div className="bg-black/40 border border-indigo-900 rounded p-2">
                                                  <div className="text-[10px] uppercase tracking-wide text-indigo-300/80">PowerShell</div>
                                                  <pre className="mt-1 whitespace-pre-wrap text-indigo-100/90 break-words">{`# Capture new response
${p.curl} | Set-Content -Encoding utf8 "${currentFilename}"
# Diff vs stored baseline
fc /N "${baselineFilename}" "${currentFilename}"`}</pre>
                                                </div>
                                                <div className="bg-black/40 border border-indigo-900 rounded p-2">
                                                  <div className="text-[10px] uppercase tracking-wide text-indigo-300/80">Bash</div>
                                                  <pre className="mt-1 whitespace-pre-wrap text-indigo-100/90 break-words">{`# Capture new response
${p.curl} | tee "${currentFilename}"
# Diff vs stored baseline
diff --strip-trailing-cr "${baselineFilename}" "${currentFilename}"`}</pre>
                                                </div>
                                              </div>
                                              <p className="text-indigo-100/70">
                                                Tip: keep the baseline file in a secure workspace and repeat these steps after remediation to prove the response has changed.
                                              </p>
                                            </div>
                                          )}
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="text-sm text-red-300">Verification failed.</div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </>
          ) : (
            <div className="text-center py-8">
              <CheckCircle className="h-16 w-16 text-green-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No Vulnerabilities Found</h3>
              <p className="text-gray-400">This scan did not identify any security vulnerabilities.</p>
            </div>
          )}
        </div>
      </div>
      )}

      {activeTab === 'recs' && (
      <div className="bg-gray-800 p-6 rounded-lg">
        <h2 className="text-2xl font-bold mb-4">Recommendations</h2>
        <div className="prose prose-invert max-w-none">
          {/* Handle both object format and array format */}
          {Array.isArray(report.recommendations) ? (
            // New format: array of recommendation objects
            report.recommendations.length > 0 ? (
              report.recommendations.map((rec, index) => (
                <div key={index} className="mb-6 p-4 bg-gray-700 rounded-lg">
                  <h3 className="text-lg font-semibold text-blue-300 mb-2">{rec.title}</h3>
                  <p className="text-gray-300 mb-3">{rec.description}</p>
                  {rec.implementation && rec.implementation.length > 0 && (
                    <>
                      <h4 className="text-md font-medium text-gray-200 mb-2">Implementation:</h4>
                      <ul className="list-disc list-inside space-y-1">
                        {rec.implementation.map((impl, idx) => (
                          <li key={idx} className="text-gray-300">{impl}</li>
                        ))}
                      </ul>
                    </>
                  )}
                  <div className="mt-3 flex gap-4 text-sm">
                    {rec.priority && (
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        rec.priority === 'High' ? 'bg-red-900 text-red-200' : 
                        rec.priority === 'Medium' ? 'bg-yellow-900 text-yellow-200' : 
                        'bg-blue-900 text-blue-200'
                      }`}>
                        Priority: {rec.priority}
                      </span>
                    )}
                    {rec.effort && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-gray-600 text-gray-200">
                        Effort: {rec.effort}
                      </span>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <p>No specific recommendations available.</p>
            )
          ) : (
            // Legacy format: object with highPriority and general arrays
            <>
              {(() => { const hp = (report.recommendations as any)?.highPriority as string[] || []; return hp.length > 0 })() && (
                <>
                  <h3 className="text-lg font-semibold">High Priority</h3>
                  <ul>
                    {(((report.recommendations as any)?.highPriority as string[]) || []).map((rec, index) => <li key={index}>{rec}</li>)}
                  </ul>
                </>
              )}
              {(() => { const g = (report.recommendations as any)?.general as string[] || []; return g.length > 0 })() && (
                <>
                  <h3 className="text-lg font-semibold">General</h3>
                  <ul>
                    {(((report.recommendations as any)?.general as string[]) || []).map((rec, index) => <li key={index}>{rec}</li>)}
                  </ul>
                </>
              )}
              {(() => { const hp = (report.recommendations as any)?.highPriority as string[] || []; const g = (report.recommendations as any)?.general as string[] || []; return hp.length === 0 && g.length === 0 })() && (
                <p>No specific recommendations.</p>
              )}
            </>
          )}
        </div>
      </div>
      )}

      {activeTab === 'command' && (
       <div className="bg-gray-800 p-6 rounded-lg mt-8">
        <h2 className="text-2xl font-bold mb-4">Scan Command</h2>
        <code className="bg-gray-900 p-4 rounded-md block text-sm text-gray-300 overflow-x-auto">
          {report.command}
        </code>
      </div>
      )}

      {activeTab === 'outputs' && (
        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-2xl font-bold mb-4">Outputs</h2>
          {(() => {
            const dumps = (report as any)?.extractedData?.outputFiles?.dumps as Array<{ name: string }>|undefined;
            if (!dumps || dumps.length === 0) {
              return <div className="text-gray-400">No downloadable outputs available.</div>;
            }
            return (
              <ul className="divide-y divide-gray-700">
                {dumps.map((f) => (
                  <li key={f.name} className="py-2 flex items-center justify-between">
                    <span className="text-gray-200 break-all">{f.name}</span>
                    <button
                      type="button"
                      className="text-blue-400 hover:text-blue-300 text-sm"
                      onClick={async () => {
                        try {
                          const blob = await fetchBlobWithAuth(`/api/reports/${report.id}/files/${encodeURIComponent(f.name)}`);
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = f.name;
                          document.body.appendChild(a);
                          a.click();
                          document.body.removeChild(a);
                          setTimeout(() => URL.revokeObjectURL(url), 60_000);
                        } catch (e: any) {
                          toast.error(e.message || 'Failed to download file');
                        }
                      }}
                    >
                      Download
                    </button>
                  </li>
                ))}
              </ul>
            );
          })()}
        </div>
      )}

      {activeTab === 'activity' && (
        <div className="bg-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold">Scan Activity</h2>
            <div className="flex items-center gap-3">
              {eventsLastRefreshed && (
                <span className="text-xs text-gray-400">
                  Last refreshed: {new Date(eventsLastRefreshed).toLocaleTimeString()}
                </span>
              )}
              <button
                onClick={fetchEvents}
                disabled={eventsLoading || !scanId}
                className={`btn-secondary flex items-center gap-2 ${eventsLoading ? 'opacity-60 cursor-not-allowed' : ''}`}
                title={scanId ? 'Refresh activity' : 'No scan ID to refresh'}
              >
                <RefreshCcw size={16} className={eventsLoading ? 'animate-spin' : ''} />
                Refresh
              </button>
            </div>
          </div>
          {eventsLoading && <div className="text-gray-400">Loading events…</div>}
          {eventsError && <div className="text-red-400">Error: {eventsError}</div>}
          {!eventsLoading && !eventsError && (!events || events.length === 0) && (
            <div className="text-gray-400">No activity recorded for this scan.</div>
          )}
          <ul className="divide-y divide-gray-700">
            {events?.map((e) => (
              <li key={e.id} className="py-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-gray-200 font-medium capitalize">{e.event_type.replace('-', ' ')}</div>
                    {e.event_type === 'output' && e.metadata?.chunk && (
                      <pre className="mt-1 text-xs text-gray-300 bg-gray-900 border border-gray-700 rounded p-2 overflow-x-auto max-h-40">
                        {e.metadata.chunk}
                      </pre>
                    )}
                    {e.event_type !== 'output' && e.metadata && Object.keys(e.metadata).length > 0 && (
                      <details className="mt-1">
                        <summary className="text-xs text-gray-400 cursor-pointer">Details</summary>
                        <pre className="mt-1 text-xs text-gray-300 bg-gray-900 border border-gray-700 rounded p-2 overflow-x-auto">
                          {JSON.stringify(e.metadata, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                  <span className="text-xs text-gray-400 ml-4 whitespace-nowrap">{new Date(e.at).toLocaleString()}</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {pendingConsent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
          <div className="w-full max-w-lg bg-gray-900 border border-gray-700 rounded-lg shadow-xl p-6 space-y-5">
            <div className="flex items-start gap-3">
              <ExclamationTriangleIcon className="h-6 w-6 text-amber-400 mt-1" />
              <div className="space-y-1">
                <h2 className="text-lg font-semibold text-white">Store raw responses for Quick Verify?</h2>
                <p className="text-sm text-gray-300">
                  We can save the HTTP headers and body captured during Quick Verify. These artifacts help explain why a finding was confirmed, but they may include sensitive data. Choose how you want to proceed.
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <label className={`block border rounded-lg p-3 cursor-pointer transition ${
                consentDecision === 'store' ? 'border-emerald-500/60 bg-emerald-900/20' : 'border-gray-700 hover:border-emerald-600/40'
              }`}>
                <div className="flex items-start gap-3">
                  <input
                    type="radio"
                    name="quick-verify-consent"
                    value="store"
                    checked={consentDecision === 'store'}
                    onChange={() => setConsentDecision('store')}
                    className="mt-1"
                  />
                  <div className="space-y-1">
                    <div className="text-sm font-semibold text-emerald-200">Store responses (recommended)</div>
                    <p className="text-xs text-emerald-100/80">
                      Saves hashed headers + body to the encrypted evidence vault so you can download the JSON later, compare payloads, and share proof with stakeholders.
                    </p>
                  </div>
                </div>
              </label>

              <label className={`block border rounded-lg p-3 cursor-pointer transition ${
                consentDecision === 'skip' ? 'border-slate-400/60 bg-slate-900/40' : 'border-gray-700 hover:border-slate-500/40'
              }`}>
                <div className="flex items-start gap-3">
                  <input
                    type="radio"
                    name="quick-verify-consent"
                    value="skip"
                    checked={consentDecision === 'skip'}
                    onChange={() => setConsentDecision('skip')}
                    className="mt-1"
                  />
                  <div className="space-y-1">
                    <div className="text-sm font-semibold text-gray-200">Skip storing responses</div>
                    <p className="text-xs text-gray-300/80">
                      Runs the same verification but discards raw content after computing scores. No new evidence will appear in the report history.
                    </p>
                  </div>
                </div>
              </label>
            </div>

            <label className="flex items-center gap-2 text-sm text-gray-200">
              <input
                type="checkbox"
                className="form-checkbox h-4 w-4 rounded border-gray-600 bg-gray-800"
                checked={consentRemember}
                onChange={(e) => setConsentRemember(e.target.checked)}
              />
              Remember my choice for future verifications
            </label>

            <div className="flex items-center justify-between text-[11px] text-gray-500">
              <span>Impacted findings: {pendingConsent.findingIds.length}</span>
              {quickVerifyPreference?.updatedAt && (
                <span>Last preference update: {formatTimestamp(quickVerifyPreference.updatedAt)}</span>
              )}
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                className="px-3 py-1.5 rounded border border-gray-600 text-gray-300 bg-gray-800 hover:bg-gray-700"
                onClick={handleConsentCancel}
              >
                Cancel
              </button>
              <button
                type="button"
                className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold"
                onClick={handleConsentConfirm}
              >
                {pendingConsent.mode === 'bulk' ? 'Verify all findings' : 'Verify now'}
              </button>
            </div>
          </div>
        </div>
      )}

      {proofModal.open && (
        <ProofModal
          open={proofModal.open}
          src={proofModal.src}
          title={proofModal.title}
          onClose={closeProofModal}
          zoom={zoom}
          onWheelZoom={onWheelZoom}
          pan={pan}
          onMouseDown={startPanDrag}
          onMouseMove={onPanMove}
          onMouseUp={endPanDrag}
          onReset={resetZoomPan}
        />
      )}
    </div>
  );
}

// Modal overlay for proof image with zoom/pan
export function ProofModal({ open, src, title, onClose, zoom, onWheelZoom, pan, onMouseDown, onMouseMove, onMouseUp, onReset }: {
  open: boolean,
  src: string,
  title?: string,
  onClose: () => void,
  zoom: number,
  onWheelZoom: React.WheelEventHandler<HTMLDivElement>,
  pan: { x: number, y: number },
  onMouseDown: React.MouseEventHandler<HTMLDivElement>,
  onMouseMove: React.MouseEventHandler<HTMLDivElement>,
  onMouseUp: React.MouseEventHandler<HTMLDivElement>,
  onReset: () => void
}) {
  if (!open) return null;
  const refObj = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (refObj.current) {
      refObj.current.style.transform = `translate(-50%, -50%) translate(${pan.x}px, ${pan.y}px) scale(${zoom})`;
      refObj.current.style.willChange = 'transform';
    }
  }, [pan.x, pan.y, zoom]);
  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700 bg-gray-900">
        <div className="text-sm text-gray-300 truncate">{title || 'Proof image'}</div>
        <div className="flex items-center gap-2 text-xs">
          <button className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded border border-gray-600" onClick={onReset} title="Reset zoom/pan">Reset</button>
          <button className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded border border-gray-600" onClick={() => onClose()} title="Close">Close</button>
        </div>
      </div>
      <div
        className="flex-1 overflow-hidden relative cursor-grab active:cursor-grabbing"
        onWheel={onWheelZoom}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
      >
        <div className="absolute top-1/2 left-1/2" ref={refObj}>
          <img src={src} alt={title || 'Proof image'} className="max-w-none select-none" draggable={false} />
        </div>
      </div>
      <div className="px-4 py-2 border-t border-gray-700 bg-gray-900 text-xs text-gray-400">
        Zoom: {Math.round(zoom * 100)}%
      </div>
    </div>
  );
}