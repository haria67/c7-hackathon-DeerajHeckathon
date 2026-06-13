import type { AgentEvent } from '../types';

const AGENT_IDS = [
  'log_monitor',
  'threat_intel',
  'vuln_scanner',
  'incident_response',
  'policy_checker',
  'slack_notifier',
] as const;

const AGENT_LABELS: Record<(typeof AGENT_IDS)[number], string> = {
  log_monitor: 'LogMonitor',
  threat_intel: 'ThreatIntel',
  vuln_scanner: 'VulnScanner',
  incident_response: 'IncidentResponse',
  policy_checker: 'PolicyChecker',
  slack_notifier: 'SlackNotifier',
};

type AgentStatus = 'idle' | 'running' | 'done' | 'error';

const STATUS_CONFIG: Record<
  AgentStatus,
  { box: string; badge: string; dot: string; label: string }
> = {
  idle: {
    box: 'border-gray-700/80 bg-gray-950/60',
    badge: 'bg-gray-800 text-gray-500',
    dot: 'bg-gray-600',
    label: 'Pending',
  },
  running: {
    box: 'border-blue-500 bg-blue-950/50 agent-box-running',
    badge: 'bg-blue-900/80 text-blue-300',
    dot: 'bg-blue-400 agent-dot-running',
    label: 'Running',
  },
  done: {
    box: 'border-green-500 bg-green-950/40 agent-box-success',
    badge: 'bg-green-900/80 text-green-300',
    dot: 'bg-green-400',
    label: 'Complete',
  },
  error: {
    box: 'border-red-500 bg-red-950/40 agent-box-error',
    badge: 'bg-red-900/80 text-red-300',
    dot: 'bg-red-400',
    label: 'Failed',
  },
};

function deriveAgentStatuses(events: AgentEvent[]): Record<string, AgentStatus> {
  const statuses: Record<string, AgentStatus> = Object.fromEntries(
    AGENT_IDS.map((id) => [id, 'idle' as AgentStatus]),
  );

  for (const event of events) {
    if (event.agent === 'pipeline' || !(event.agent in statuses)) continue;
    if (event.status === 'running') statuses[event.agent] = 'running';
    else if (event.status === 'done') statuses[event.agent] = 'done';
    else if (event.status === 'error') statuses[event.agent] = 'error';
  }

  return statuses;
}

interface Props {
  events: AgentEvent[];
  active?: boolean;
}

export default function AgentFeed({ events, active = false }: Props) {
  const statuses = deriveAgentStatuses(events);
  const hasActivity = active || events.some((e) => e.agent !== 'pipeline');

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <h3 className="text-gray-400 text-xs uppercase tracking-widest mb-3">
        Agent Pipeline
      </h3>

      {!hasActivity && (
        <p className="text-gray-600 text-sm mb-3">Waiting for analysis to start...</p>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {AGENT_IDS.map((id) => {
          const status = statuses[id];
          const config = STATUS_CONFIG[status];

          return (
            <div
              key={id}
              className={`relative rounded-lg border-2 px-3 py-3 transition-all duration-500 ease-out ${config.box}`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-gray-100 truncate">
                    {AGENT_LABELS[id]}
                  </p>
                  <p className="text-xs text-gray-500 mt-0.5 font-mono">{id}</p>
                </div>
                <span
                  className={`shrink-0 inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-semibold px-2 py-1 rounded-full transition-colors duration-500 ${config.badge}`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full transition-colors duration-500 ${config.dot}`}
                  />
                  {config.label}
                </span>
              </div>

              {status === 'running' && (
                <div className="mt-3 h-1 rounded-full bg-blue-900/60 overflow-hidden">
                  <div className="h-full w-1/3 rounded-full bg-blue-400 agent-progress-bar" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
