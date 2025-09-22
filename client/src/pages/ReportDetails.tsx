import { useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { ArrowLeft, FileText, FileJson, CheckCircle, RefreshCcw } from 'lucide-react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { getScanEvents, type ScanEvent, verifyFinding as apiVerifyFinding, type VerifyFindingResult } from '../utils/api';

// You might need to create this type based on your actual report structure
type Report = {
  id: string;
  title: string;
  target: string;
  status: string;
  scanDuration: number;
  createdAt: string;
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
  recommendations: {
    highPriority: string[];
    general: string[];
  } | Array<{
    category: string;
    priority: string;
    title: string;
    description: string;
    implementation: string[];
    effort: string;
    impact: string;
  }>;
  command: string;
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

  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        const response = await fetch(`/api/reports/${reportId}`);
        if (!response.ok) {
          throw new Error('Failed to fetch report data.');
        }
        const data = await response.json();
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
  
  const onVerify = async (findingId: string) => {
    if (!report?.id) return;
    setVerifying(prev => ({ ...prev, [findingId]: true }));
    try {
      const res = await apiVerifyFinding(report.id, findingId);
      setVerifyResult(prev => ({ ...prev, [findingId]: res }));
      setVerifyMeta(prev => ({ ...prev, [findingId]: { at: new Date().toISOString() } }));
      if (res.ok) {
        toast.success(`Verification: ${res.label} (${formatConfidence(res.score)})`);
      } else {
        toast.error('Verification failed');
      }
    } catch (e: any) {
      toast.error(e.message || 'Verification error');
    } finally {
      setVerifying(prev => ({ ...prev, [findingId]: false }));
    }
  }

  const onVerifyAll = async () => {
    if (!report?.id) return;
    const ids = (report.vulnerabilities?.findings || []).map(f => f.id).filter(Boolean);
    if (ids.length === 0) return;
    setVerifyAllRunning(true);
    setVerifyAllProgress({ done: 0, total: ids.length });
    let success = 0;
    let failed = 0;
    for (const id of ids) {
      setVerifying(prev => ({ ...prev, [id]: true }));
      try {
        const res = await apiVerifyFinding(report.id, id);
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
    setVerifyAllRunning(false);
    if (failed === 0) {
      toast.success(`Verified all ${success} findings.`);
    } else if (success === 0) {
      toast.error(`All ${failed} verifications failed.`);
    } else {
      toast(`Verified ${success}, failed ${failed}.`, { icon: '⚠️' });
    }
  }
  
  const handleDownload = (format: 'pdf' | 'json' | 'html') => {
    window.open(`/api/reports/${reportId}/export/${format}`, '_blank');
    toast.success(`Downloading report as ${format.toUpperCase()}`);
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
          <button onClick={() => handleDownload('pdf')} className="btn-primary flex items-center gap-2">
            <FileText size={18} />
            Download PDF
          </button>
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
          {report.vulnerabilities?.findings?.length > 0 ? (
            report.vulnerabilities.findings.map((vuln) => (
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
                              {/* WAF-aware inconclusive mode */}
                              {verifyResult[vuln.id].wafDetected && (
                                <div className="mt-2 p-2 rounded bg-yellow-900/30 border border-yellow-800">
                                  <div className="text-yellow-300 font-medium">WAF indicators detected. Result may be inconclusive.</div>
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
              {report.recommendations?.highPriority?.length > 0 && (
                <>
                  <h3 className="text-lg font-semibold">High Priority</h3>
                  <ul>
                    {report.recommendations.highPriority.map((rec, index) => <li key={index}>{rec}</li>)}
                  </ul>
                </>
              )}
              {report.recommendations?.general?.length > 0 && (
                <>
                  <h3 className="text-lg font-semibold">General</h3>
                  <ul>
                    {report.recommendations.general.map((rec, index) => <li key={index}>{rec}</li>)}
                  </ul>
                </>
              )}
              {(!report.recommendations?.highPriority?.length && !report.recommendations?.general?.length) && (
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
                    <a
                      className="text-blue-400 hover:text-blue-300 text-sm"
                      href={`/api/reports/${report.id}/files/${encodeURIComponent(f.name)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Download
                    </a>
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
    </div>
  );
}