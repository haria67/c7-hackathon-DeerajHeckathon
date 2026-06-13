import { useEffect, useState } from 'react';
import AgentFeed from './components/AgentFeed';
import EvalsTab from './components/EvalsTab';
import IncidentReport from './components/IncidentReport';
import LogSourceSelector from './components/LogSourceSelector';
import MetricCard from './components/MetricCard';
import { useSSE } from './hooks/useSSE';
import ThreatFindingsPanel from './components/ThreatFindingsPanel';
import { API_BASE } from './config';
import type { AnalyzeMeta, SecurityReport } from './types';

const API = API_BASE;

type Tab = 'dashboard' | 'evals';

export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [analyzeMeta, setAnalyzeMeta] = useState<AnalyzeMeta | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evalsRefreshKey, setEvalsRefreshKey] = useState(0);
  const { events, done } = useSSE(sessionId);

  function resetRunState() {
    setReport(null);
    setAnalyzeMeta(null);
    setError(null);
    setSessionId(null);
  }

  async function handleRunAnalysis(
    source: string,
    file?: File,
    githubUrl?: string,
    includeLogs?: boolean,
    slackWebhookUrl?: string,
  ) {
    setLoading(true);
    resetRunState();

    try {
      let payload: AnalyzeMeta & { session_id: string };
      const slack = slackWebhookUrl?.trim() ?? '';
      if (source === 'github' && githubUrl) {
        const res = await fetch(`${API}/analyze/github`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repo_url: githubUrl,
            include_logs: includeLogs ?? false,
            log_source: 'synthetic',
            slack_webhook_url: slack,
          }),
        });
        if (!res.ok) throw new Error(await res.text());
        payload = await res.json();
      } else if (source === 'upload' && file) {
        const form = new FormData();
        form.append('file', file);
        if (slack) form.append('slack_webhook_url', slack);
        const res = await fetch(`${API}/analyze/upload`, { method: 'POST', body: form });
        if (!res.ok) throw new Error(await res.text());
        payload = await res.json();
      } else {
        const res = await fetch(`${API}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ source, slack_webhook_url: slack }),
        });
        if (!res.ok) throw new Error(await res.text());
        payload = await res.json();
      }

      const { session_id, ...meta } = payload;
      setAnalyzeMeta(meta);
      setSessionId(session_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed to start');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!done || !sessionId) return;

    let cancelled = false;
    fetch(`${API}/report/${sessionId}`)
      .then((res) => {
        if (!res.ok) throw new Error('Report not ready');
        return res.json();
      })
      .then((data) => {
        if (!cancelled) {
          setReport(data);
          setEvalsRefreshKey((k) => k + 1);
        }
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load report');
      });

    return () => {
      cancelled = true;
    };
  }, [done, sessionId]);

  const isGithubRun =
    analyzeMeta?.log_source === 'github' || report?.log_source === 'github';

  const codeFindings = report?.code_findings ?? [];

  const criticalCount = isGithubRun
    ? codeFindings.filter((f) => f.severity === 'CRITICAL').length
    : report?.anomalies.filter((a) => a.severity === 'CRITICAL').length ?? 0;

  const warningCount = isGithubRun
    ? codeFindings.filter((f) => f.severity === 'HIGH').length
    : report?.anomalies.filter((a) => a.severity === 'HIGH').length ?? 0;

  const agentsDone = events.filter(
    (e) => e.agent !== 'pipeline' && e.status === 'done',
  ).length;

  const sourceLabel =
    analyzeMeta?.log_source === 'synthetic'
      ? 'Synthetic demo logs'
      : analyzeMeta?.log_source === 'system'
        ? analyzeMeta.used_fallback
          ? 'System logs (fallback — no readable host logs found)'
          : `System logs (${analyzeMeta.line_count} lines from ${analyzeMeta.paths?.join(', ') ?? 'host'})`
        : analyzeMeta?.log_source === 'github'
          ? analyzeMeta.github_repo
            ? `GitHub code scan: ${analyzeMeta.github_repo}${
                (analyzeMeta.line_count ?? 0) > 0 ? ' + log analysis' : ''
              }`
            : 'GitHub code scan'
          : analyzeMeta?.log_source === 'upload'
            ? `Uploaded file (${analyzeMeta.line_count} lines)`
            : null;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
      <nav className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
        <span className="text-blue-400 font-bold text-lg">🛡️ CyberSentinel AI</span>
        <div className="flex gap-2 text-sm">
          {(['dashboard', 'evals'] as Tab[]).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`px-3 py-1 rounded-md capitalize transition-colors ${
                tab === t
                  ? 'bg-blue-900 text-blue-300 border border-blue-700'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              {t === 'evals' ? 'Evals' : 'Dashboard'}
            </button>
          ))}
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        {tab === 'dashboard' && (
          <>
            <LogSourceSelector
              onRun={handleRunAnalysis}
              onSourceChange={resetRunState}
              loading={loading}
            />

            {sourceLabel && (
              <p className="text-sm text-gray-400">
                Active run: <span className="text-gray-200">{sourceLabel}</span>
              </p>
            )}

            {error && (
              <p className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded-lg px-4 py-2">
                {error}
              </p>
            )}

            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {isGithubRun ? (
                <>
                  <MetricCard
                    label="Critical Code Issues"
                    value={criticalCount}
                    color="red"
                  />
                  <MetricCard label="High Severity" value={warningCount} color="yellow" />
                  <MetricCard
                    label="Files Scanned"
                    value={report?.files_scanned ?? '—'}
                    color="green"
                  />
                  <MetricCard
                    label="Primary Language"
                    value={report?.primary_language ?? '—'}
                    color="blue"
                  />
                  <MetricCard
                    label="Risk Level"
                    value={report?.risk_level.toUpperCase() ?? '—'}
                    color="purple"
                  />
                </>
              ) : (
                <>
                  <MetricCard label="Critical Threats" value={criticalCount} color="red" />
                  <MetricCard label="Warnings" value={warningCount} color="yellow" />
                  <MetricCard label="Agents Active" value={`${agentsDone}/6`} color="green" />
                  <MetricCard
                    label="Compliance Score"
                    value={report ? `${report.compliance_score}%` : '—'}
                    color="blue"
                  />
                  <MetricCard
                    label="Risk Level"
                    value={report?.risk_level.toUpperCase() ?? '—'}
                    color="purple"
                  />
                </>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <AgentFeed events={events} active={!!sessionId} />
              <IncidentReport report={report} />
            </div>

            <ThreatFindingsPanel report={report} />
          </>
        )}

        {tab === 'evals' && <EvalsTab refreshKey={evalsRefreshKey} />}
      </main>
    </div>
  );
}
