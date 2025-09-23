import type React from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { ArrowLeft, FileText, FileJson, CheckCircle, RefreshCcw, Image as ImageIcon, ExternalLink, Flag } from 'lucide-react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { apiFetch, getScanEvents, type ScanEvent, verifyFinding as apiVerifyFinding, type VerifyFindingResult } from '../utils/api';
import { useAppStore } from '../store/appStore';
import { useScanSocket } from '../hooks/useSocket';
import { wafPreset } from '../utils/sqlmapFlags';

// You might need to create this type based on your actual report structure
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
      parameter: string;
      description: string;
      impact?: string;
      remediation?: string[];
      evidence?: Array<{
        line: number;
        content: string;
        context?: string;
      }>;
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
  const runningScans = useAppStore(s => s.runningScans);
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
  const [panStart, setPanStart] = useState<{ x: number; y: number } | null>(null);

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
                confirmations: v.confirmations,
                signals: v.signals,
                wafDetected: !!v.wafDetected,
                suggestions: Array.isArray(v.suggestions) ? v.suggestions : undefined,
                why: 'Persisted verification summary'
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

  const scanId = useMemo(() => {
    // Prefer a direct scanId on the report if available; otherwise try to infer from metadata/extracted data
    // Our server stores scan_id as report.scan_id in the DB, but the client Report type doesn’t have it;
    // fetchReport returns the full row, so we can try (report as any).scan_id safely.
    return (report as any)?.scan_id || (report as any)?.scanId || '';
  }, [report]);

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

  const getSeverityClass = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-800 text-red-100 border-red-600';
      case 'high':
        return 'bg-orange-800 text-orange-100 border-orange-600';
      case 'medium':
        return 'bg-yellow-800 text-yellow-100 border-yellow-600';
      case 'low':
        return 'bg-blue-800 text-blue-100 border-blue-600';
      default:
        return 'bg-gray-700 text-gray-200 border-gray-600';
    }
  };
  
  const formatConfidence = (score?: number) => {
    if (typeof score !== 'number') return '—';
    return `${Math.round(Math.min(1, Math.max(0, score)) * 100)}%`;
  };

  const isFalsePositive = (findingId: string) => {
    const fp = (report as any)?.metadata?.falsePositives || {};
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
  
  const onVerify = async (findingId: string) => {
    if (!report?.id) return;
    setGlobalVerifying(true);
    setVerifying(prev => ({ ...prev, [findingId]: true }));
    try {
      const res = await apiVerifyFinding(report.id, findingId);
      setVerifyResult(prev => ({ ...prev, [findingId]: res }));
      setVerifyMeta(prev => ({ ...prev, [findingId]: { at: new Date().toISOString() } }));
      // Refresh report to pull persisted verification metadata
      try {
        const nr = await apiFetch(`/api/reports/${report.id}`);
        setReport(nr);
      } catch { /* non-fatal */ }
      if (res.ok) {
        toast.success(`Verification: ${res.label} (${formatConfidence(res.score)})`);
      } else {
        toast.error('Verification failed');
      }
    } catch (e: any) {
      toast.error(e.message || 'Verification error');
    } finally {
      setVerifying(prev => ({ ...prev, [findingId]: false }));
      setGlobalVerifying(false);
    }
  }

  const shouldReverify = (findingId: string) => {
    const res = verifyResult[findingId];
    if (!res) return true; // never verified
    if (res.wafDetected) return true; // inconclusive due to WAF
    const label = res.label || '';
    if (label === 'Inconclusive' || label === 'Suspected') return true; // lower confidence
    return false;
  }

  const onVerifyAll = async () => {
    if (!report?.id) return;
    let ids = (report.vulnerabilities?.findings || []).map(f => f.id).filter(Boolean);
    if (verifyOnlyChanged) {
      ids = ids.filter(shouldReverify);
    }
    if (ids.length === 0) return;
    setGlobalVerifying(true);
    setVerifyAllRunning(true);
    setVerifyAllProgress({ done: 0, total: ids.length });
    let success = 0;
    let failed = 0;
    const concurrency = 3;
    const startDelayMs = 150;
    let index = 0;
    const delay = (ms: number) => new Promise(r => setTimeout(r, ms));
    const worker = async () => {
      while (true) {
        const i = index++;
        if (i >= ids.length) break;
        const id = ids[i];
        await delay(startDelayMs);
        setVerifying(prev => ({ ...prev, [id]: true }));
        try {
          const res = await apiVerifyFinding(report.id!, id);
          setVerifyResult(prev => ({ ...prev, [id]: res }));
          setVerifyMeta(prev => ({ ...prev, [id]: { at: new Date().toISOString() } }));
          if (res.ok) success++; else failed++;
        } catch (_) {
          failed++;
        } finally {
          setVerifying(prev => ({ ...prev, [id]: false }));
          setVerifyAllProgress(prev => ({ ...prev, done: prev.done + 1, total: prev.total }));
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, () => worker()));
    setVerifyAllRunning(false);
    setGlobalVerifying(false);
    // Refresh report after batch verifications to reflect persisted summaries
    try {
      const nr = await apiFetch(`/api/reports/${report.id}`);
      setReport(nr);
    } catch { /* non-fatal */ }
    if (failed === 0) {
      toast.success(`Verified all ${success} findings.`);
    } else if (success === 0) {
      toast.error(`All ${failed} verifications failed.`);
    } else {
      toast(`Verified ${success}, failed ${failed}.`, { icon: '⚠️' });
    }
  }

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
                onClick={onVerifyAll}
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
            (showFalsePositivesOnly
              ? report.vulnerabilities.findings.filter((f) => isFalsePositive(f.id))
              : report.vulnerabilities.findings
            ).map((vuln) => (
              <div key={vuln.id} className={`bg-gray-750 p-6 rounded-lg border-l-4 ${getSeverityClass(vuln.severity)} shadow-lg`}>
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-xl font-semibold text-white">{vuln.type}</h3>
                    <div className="mt-1 flex flex-wrap gap-2 text-xs text-gray-300">
                      { (vuln as any).confidenceLabel && (
                        <span className="px-2 py-0.5 rounded bg-gray-700">Confidence: {(vuln as any).confidenceLabel} ({formatConfidence((vuln as any).confidenceScore)})</span>
                      )}
                      { Array.isArray((vuln as any).signals) && (vuln as any).signals.length > 0 && (
                        <span className="px-2 py-0.5 rounded bg-gray-700">Signals: {(vuln as any).signals.join(', ')}</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-bold uppercase px-3 py-1 rounded-full ${getSeverityClass(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                    {/* Compact persisted label badge */}
                    {verifyResult[vuln.id]?.label && (
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                          verifyResult[vuln.id]?.label === 'Confirmed' ? 'bg-green-900 text-green-200 border border-green-700' :
                          verifyResult[vuln.id]?.label === 'Likely' ? 'bg-yellow-900 text-yellow-200 border border-yellow-700' :
                          verifyResult[vuln.id]?.label === 'Inconclusive' ? 'bg-orange-900 text-orange-200 border border-orange-700' :
                          'bg-gray-700 text-gray-200 border border-gray-600'
                        }`}
                        title={`Verification: ${verifyResult[vuln.id]?.label}`}
                      >
                        {verifyResult[vuln.id]?.label}
                      </span>
                    )}
                    {verifyMeta[vuln.id]?.at && (
                      <span className="text-xs text-gray-300 bg-gray-700 px-2 py-0.5 rounded" title={new Date(verifyMeta[vuln.id].at).toLocaleString()}>
                        Last verified: {new Date(verifyMeta[vuln.id].at).toLocaleDateString()} {new Date(verifyMeta[vuln.id].at).toLocaleTimeString()}
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
                      className={`ml-2 px-2 py-1 rounded text-xs border ${isFalsePositive(vuln.id) ? 'bg-red-900/40 border-red-700 text-red-200' : 'bg-gray-700 border-gray-600 text-gray-200'}`}
                      onClick={() => toggleFalsePositive(vuln.id)}
                      title={isFalsePositive(vuln.id) ? 'Unmark False Positive' : 'Mark False Positive'}
                    >
                      <span className="inline-flex items-center gap-1">
                        <Flag size={12} /> {isFalsePositive(vuln.id) ? 'False Positive' : 'Mark FP'}
                      </span>
                    </button>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <h4 className="text-sm font-semibold text-gray-300 mb-1">Description</h4>
                    <p className="text-gray-200">{vuln.description}</p>
                  </div>
                  
                  {vuln.parameter && (
                    <div>
                      <h4 className="text-sm font-semibold text-gray-300 mb-1">Affected Parameter</h4>
                      <code className="bg-gray-900 px-2 py-1 rounded text-green-400">{vuln.parameter}</code>
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

                      {verifyResult[vuln.id] && (
                    <div className="mt-4 p-3 rounded bg-gray-800 border border-gray-700">
                      <h4 className="text-sm font-semibold text-gray-200 mb-2">Verification Result</h4>
                      {verifyResult[vuln.id].ok ? (
                        <div className="text-sm text-gray-200 space-y-1">
                          <div>Label: <span className="font-medium">{verifyResult[vuln.id].label}</span></div>
                          <div>Score: <span className="font-medium">{formatConfidence(verifyResult[vuln.id].score)}</span></div>
                          {verifyResult[vuln.id].why && (
                            <div className="text-gray-300">Why: {verifyResult[vuln.id].why}</div>
                          )}
                          {/* DOM-based validation proof (if available) */}
                          {verifyResult[vuln.id]?.dom?.checked && (
                            <div className="mt-2 p-2 rounded bg-gray-900 border border-gray-700">
                              <div className="flex items-center gap-2 text-xs text-gray-300">
                                <ImageIcon size={14} className="text-blue-300" />
                                <span>DOM validation:</span>
                                <span className={verifyResult[vuln.id].dom?.reflected ? 'text-green-300' : 'text-red-300'}>
                                  {verifyResult[vuln.id].dom?.reflected ? 'Reflected' : 'Not reflected'}
                                </span>
                                {verifyResult[vuln.id].dom?.url && (
                                  <span className="text-gray-400 truncate">• {verifyResult[vuln.id].dom?.url}</span>
                                )}
                              </div>
                              {Array.isArray(verifyResult[vuln.id].dom?.matches) && verifyResult[vuln.id].dom!.matches.length > 0 && (
                                <div className="mt-2 text-xs text-gray-400">
                                  <div className="mb-1">Matches:</div>
                                  <ul className="list-disc pl-5 space-y-1">
                                    {verifyResult[vuln.id].dom!.matches.slice(0, 3).map((m, i) => {
                                      const selText = `${m.selector}${m.mode === 'attribute' && m.attribute ? ` [@${m.attribute}]` : ''}`;
                                      return (
                                        <li key={i} className="flex items-center gap-2">
                                          <code className="bg-gray-800 px-1 py-0.5 rounded">{selText}</code>
                                          <button
                                            type="button"
                                            className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700 hover:bg-gray-600 border border-gray-600"
                                            onClick={async () => { try { await navigator.clipboard.writeText(selText); toast.success('Selector copied'); } catch { toast.error('Copy failed'); } }}
                                            title="Copy selector"
                                          >Copy</button>
                                        </li>
                                      );
                                    })}
                                    {verifyResult[vuln.id].dom!.matches.length > 3 && (
                                      <li className="text-gray-500">…and {verifyResult[vuln.id].dom!.matches.length - 3} more</li>
                                    )}
                                  </ul>
                                </div>
                              )}
                              {verifyResult[vuln.id].dom?.proof?.filename && (
                                <div className="mt-2">
                                  <div className="flex items-center gap-3 mb-2">
                                    <button
                                      type="button"
                                      className="text-xs text-blue-300 hover:text-blue-200 flex items-center gap-1"
                                      title="Open proof image in a new tab"
                                      onClick={async () => {
                                        try {
                                          const blob = await fetchBlobWithAuth(`/api/reports/${encodeURIComponent(report.id)}/proof/${encodeURIComponent(verifyResult[vuln.id].dom!.proof!.filename)}`);
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
                                      onClick={() => openProofModal(`/api/reports/${encodeURIComponent(report.id)}/proof/${encodeURIComponent(verifyResult[vuln.id].dom!.proof!.filename)}`, `Proof for ${vuln.type}`)}
                                      title="View full proof"
                                    >
                                      View full proof
                                    </button>
                                  </div>
                                  <img
                                    src={proofModal.src}
                                    alt="DOM Proof"
                                    className="max-h-64 rounded border border-gray-700"
                                    onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }}
                                  />
                                </div>
                              )}
                            </div>
                          )}
                          {(!verifyResult[vuln.id]?.dom || verifyResult[vuln.id]?.dom?.checked === false) && (
                            <div className="mt-2 p-2 rounded bg-gray-900 border border-gray-800 text-xs text-gray-400">
                              {verifyResult[vuln.id]?.wafDetected
                                ? 'DOM validation skipped due to WAF indicators.'
                                : 'DOM validation not attempted (method may not be GET or unsupported).'}
                            </div>
                          )}
                              {/* WAF-aware inconclusive mode */}
                              {verifyResult[vuln.id].wafDetected && (
                                <div className="mt-2 p-2 rounded bg-yellow-900/30 border border-yellow-800">
                                  <div className="text-yellow-300 font-medium">WAF indicators detected. Result may be inconclusive.</div>
                                  <div className="mt-2 flex flex-wrap items-center gap-2">
                                    <button
                                      type="button"
                                      className="px-2 py-1 text-xs bg-gray-700 border border-gray-600 rounded hover:bg-gray-600"
                                      onClick={() => { applyWafSuggestions(wafPreset('standard')); toast.success('WAF-friendly flags loaded in Terminal (Custom profile).'); }}
                                      title="Load recommended WAF-friendly flags into Terminal"
                                    >
                                      Apply WAF suggestions
                                    </button>
                                    <button
                                      type="button"
                                      className="px-2 py-1 text-xs bg-green-700 border border-green-600 rounded hover:bg-green-600"
                                      onClick={() => {
                                        if (!report?.target) { toast.error('Report target unavailable'); return; }
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
                                        const running = Array.isArray(runningScans) ? runningScans.length : 0;
                                        if (running > 0) {
                                          const confirmStop = window.confirm('A scan appears to be running. Terminate the current scan and start a new one with WAF-friendly settings?');
                                          if (confirmStop) {
                                            terminateScan();
                                            toast('Terminating current scan…', { icon: '🛑' });
                                            setTimeout(doStart, 800);
                                          } else {
                                            doStart(); // May be rejected by server if limits reached
                                          }
                                        } else {
                                          doStart();
                                        }
                                      }}
                                      title="Apply flags and start a new scan on this report's target"
                                    >
                                      Apply & Start New Scan
                                    </button>
                                    <Link to="/terminal" className="text-xs text-blue-300 hover:text-blue-200" title="Open Terminal to start a new scan">Open Terminal</Link>
                                  </div>
                                  {verifyResult[vuln.id].wafIndicators && (
                                    <div className="text-xs text-yellow-200 mt-1">
                                      Indicators: {[
                                        verifyResult[vuln.id].wafIndicators?.header ? 'header' : null,
                                        verifyResult[vuln.id].wafIndicators?.body ? 'body' : null,
                                        verifyResult[vuln.id].wafIndicators?.status ? 'status' : null
                                      ].filter(Boolean).join(', ') || 'generic'}
                                      {Array.isArray(verifyResult[vuln.id].wafIndicators?.sources) && (verifyResult[vuln.id].wafIndicators?.sources?.length || 0) > 0 && (
                                        <> · Sources: {verifyResult[vuln.id].wafIndicators?.sources?.join(', ')}</>
                                      )}
                                    </div>
                                  )}
                                  {Array.isArray(verifyResult[vuln.id].suggestions) && verifyResult[vuln.id].suggestions!.length > 0 && (
                                    <ul className="list-disc list-inside text-xs text-yellow-200 mt-1 space-y-0.5">
                                      {verifyResult[vuln.id].suggestions!.map((s, i) => (
                                        <li key={i}>{s}</li>
                                      ))}
                                    </ul>
                                  )}
                                </div>
                              )}
                          {verifyResult[vuln.id]?.confirmations && verifyResult[vuln.id]?.confirmations!.length > 0 && (
                            <div>Signals confirmed: {verifyResult[vuln.id]?.confirmations!.join(', ')}</div>
                          )}
                          {verifyResult[vuln.id]?.poc && verifyResult[vuln.id]?.poc!.length > 0 && (
                            <div className="mt-2">
                              <div className="text-xs text-gray-400 mb-1">Proof-of-Concept (cURL):</div>
                              <div className="bg-gray-900 p-2 rounded max-h-40 overflow-y-auto text-xs font-mono whitespace-pre-wrap select-all">
                                {(verifyResult[vuln.id]?.poc ?? []).map((p, i) => (
                                  <div key={i} className="mb-1">
                                    # {p.name}\n{p.curl}
                                  </div>
                                ))}
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
            ))
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