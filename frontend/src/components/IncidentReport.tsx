import type { SecurityReport } from '../types';

interface Props {
  report: SecurityReport | null;
}

export default function IncidentReport({ report }: Props) {
  function downloadReport() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cybersentinel-report-${report.session_id}.json`;
    a.click();
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-gray-400 text-xs uppercase tracking-widest">
          Incident Report
        </h3>
        {report && (
          <button
            type="button"
            onClick={downloadReport}
            className="text-xs bg-blue-900 text-blue-300 px-3 py-1 rounded-md hover:bg-blue-800"
          >
            ⬇ Download
          </button>
        )}
      </div>

      {!report && (
        <p className="text-gray-600 text-sm">
          Report will appear after analysis completes.
        </p>
      )}

      {report && (
        <div className="space-y-4">
          {(report.action_plan.length > 0 ||
            (report.anomalies?.length ?? 0) > 0 ||
            (report.code_findings?.length ?? 0) > 0 ||
            (report.vulnerabilities?.length ?? 0) > 0) && (
            <div>
              <h4 className="text-yellow-400 font-semibold text-sm mb-2">
                🚨 Action Plan
              </h4>
              {report.action_plan.length > 0 ? (
                <ol className="space-y-1 text-sm text-gray-300">
                  {report.action_plan.map((step, i) => (
                    <li key={i}>
                      {i + 1}. {step}
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm text-gray-500">
                  See detected threats below for issue details and fix recommendations.
                </p>
              )}
            </div>
          )}

          <div className="pt-3 border-t border-gray-800">
            <h4 className="text-cyan-400 font-semibold text-sm mb-2">
              📜 Compliance Gaps
            </h4>
            <div className="text-xs text-gray-400 space-y-1">
              {report.compliance_gaps.slice(0, 6).map((g, i) => (
                <div key={i}>
                  {g.framework} · {g.control_id} — {g.description}
                </div>
              ))}
            </div>
          </div>

          {!report.slack_skipped && (
            <div className="pt-3 border-t border-gray-800">
              <h4 className="text-purple-400 font-semibold text-sm mb-2">
                💬 Slack Notification
              </h4>
              {report.slack_sent ? (
                <p className="text-sm text-green-400">
                  Incident summary and resolution steps were posted to Slack.
                </p>
              ) : (
                <p className="text-sm text-red-400">
                  {report.slack_error || 'Failed to send Slack notification.'}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
