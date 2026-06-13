import { useCallback, useEffect, useState } from 'react';
import { API_BASE } from '../config';
import type { EvalAgent, EvalRun, EvalsResponse, EvalSessionDetail } from '../types/evals';

const API = API_BASE;

const AGENT_COLORS: Record<string, string> = {
  log_monitor: 'border-green-800 bg-green-950/50',
  threat_intel: 'border-red-800 bg-red-950/50',
  vuln_scanner: 'border-purple-800 bg-purple-950/50',
  incident_response: 'border-yellow-800 bg-yellow-950/50',
  policy_checker: 'border-cyan-800 bg-cyan-950/50',
  slack_notifier: 'border-pink-800 bg-pink-950/50',
};

const TYPE_LABELS: Record<string, string> = {
  deterministic: 'Deterministic',
  external_api: 'External API',
  llm: 'LLM + Cache',
};

function fmtCost(n: number) {
  return n === 0 ? '$0.00' : `$${n.toFixed(5)}`;
}

function fmtPct(n: number) {
  return `${(n * 100).toFixed(1)}%`;
}

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString();
}

interface Props {
  refreshKey: number;
}

export default function EvalsTab({ refreshKey }: Props) {
  const [data, setData] = useState<EvalsResponse | null>(null);
  const [selectedRun, setSelectedRun] = useState<EvalRun | null>(null);
  const [runDetail, setRunDetail] = useState<EvalSessionDetail | null>(null);
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadEvals = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/evals`);
      if (!res.ok) throw new Error('Failed to load evals');
      const json: EvalsResponse = await res.json();
      setData(json);
      if (json.runs.length > 0) {
        const latest = json.runs[0];
        setSelectedRun((prev) => prev ?? latest);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load evals');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEvals();
  }, [loadEvals, refreshKey]);

  useEffect(() => {
    if (!selectedRun) {
      setRunDetail(null);
      return;
    }
    let cancelled = false;
    fetch(`${API}/evals/${selectedRun.session_id}`)
      .then((res) => {
        if (!res.ok) throw new Error('Run detail not found');
        return res.json();
      })
      .then((detail: EvalSessionDetail) => {
        if (!cancelled) {
          setRunDetail(detail);
          setExpandedAgent(null);
        }
      })
      .catch(() => {
        if (!cancelled) setRunDetail(null);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedRun]);

  if (loading && !data) {
    return <p className="text-gray-500 text-sm">Loading eval metrics…</p>;
  }

  if (error && !data) {
    return <p className="text-red-400 text-sm">{error}</p>;
  }

  const overall = data?.overall;
  const cacheLayers = runDetail?.summary.cache_layers ?? data?.runs[0]?.summary.cache_layers ?? [];

  return (
    <div className="space-y-6">
      {/* Overall summary */}
      <section>
        <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">
          Overall Summary
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <SummaryCard label="Total Runs" value={String(overall?.total_runs ?? 0)} />
          <SummaryCard label="Total Cost" value={fmtCost(overall?.total_cost_usd ?? 0)} />
          <SummaryCard
            label="Cost Saved"
            value={fmtCost(overall?.total_cost_saved_usd ?? 0)}
            accent="text-green-400"
          />
          <SummaryCard
            label="Total Tokens"
            value={(overall?.total_tokens ?? 0).toLocaleString()}
          />
          <SummaryCard
            label="LLM Cache Hit Rate"
            value={fmtPct(overall?.llm_cache_hit_rate ?? 0)}
          />
          <SummaryCard
            label="Global Cache Size"
            value={String(overall?.global_cache_size ?? 0)}
          />
        </div>
      </section>

      {/* Cache layers */}
      <section>
        <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">
          Caching Layers
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {cacheLayers.map((layer) => (
            <div
              key={layer.name}
              className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-sm"
            >
              <div className="font-medium text-gray-200 mb-1">{layer.name}</div>
              <div className="text-xs text-gray-500 mb-2">{layer.scope ?? layer.type}</div>
              {layer.type === 'lru_memory' && (
                <div className="space-y-1 text-xs text-gray-400">
                  <div>
                    Run: {layer.hits ?? 0} hits / {layer.misses ?? 0} misses (
                    {fmtPct(layer.hit_rate ?? 0)})
                  </div>
                  <div>
                    Global: {layer.global_hits ?? 0} hits / {layer.global_misses ?? 0}{' '}
                    misses ({fmtPct(layer.global_hit_rate ?? 0)})
                  </div>
                  <div>Entries in cache: {layer.global_size ?? 0}</div>
                </div>
              )}
              {layer.type === 'deterministic' && (
                <p className="text-xs text-gray-400">
                  {layer.agents} agents · $0 LLM cost
                </p>
              )}
              {layer.type === 'external_api' && (
                <p className="text-xs text-gray-400">{layer.note}</p>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Run history + agent details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <section className="lg:col-span-1">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">
            Analysis Runs
          </h2>
          {!data?.runs.length ? (
            <p className="text-gray-600 text-sm">
              No analyses yet. Run one from the Dashboard tab.
            </p>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {data.runs.map((run) => (
                <button
                  key={run.session_id}
                  type="button"
                  onClick={() => setSelectedRun(run)}
                  className={`w-full text-left rounded-lg border px-3 py-2 text-sm transition-colors ${
                    selectedRun?.session_id === run.session_id
                      ? 'border-blue-600 bg-blue-950/40'
                      : 'border-gray-800 bg-gray-900 hover:bg-gray-800'
                  }`}
                >
                  <div className="flex justify-between gap-2">
                    <span className="text-gray-200 capitalize">{run.log_source}</span>
                    <span className="text-gray-500 text-xs">
                      {fmtCost(run.summary.total_cost_usd)}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {fmtTime(run.started_at)} · {run.line_count} lines
                  </div>
                  <div className="text-xs text-gray-500">
                    Saved {fmtCost(run.summary.cost_saved_usd)} ·{' '}
                    {run.summary.llm_cache_hits}/{run.summary.llm_cache_hits + run.summary.llm_cache_misses || 0}{' '}
                    cache hits
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="lg:col-span-2">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">
            Agent Breakdown
            {selectedRun && (
              <span className="normal-case text-gray-600 ml-2">
                — {selectedRun.log_source} run
              </span>
            )}
          </h2>

          {!runDetail ? (
            <p className="text-gray-600 text-sm">Select a run to view agent metrics.</p>
          ) : (
            <div className="space-y-2">
              {runDetail.agents.map((agent) => (
                <AgentRow
                  key={agent.agent}
                  agent={agent}
                  expanded={expandedAgent === agent.agent}
                  onToggle={() =>
                    setExpandedAgent((prev) =>
                      prev === agent.agent ? null : agent.agent,
                    )
                  }
                />
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-3">
      <div className={`text-lg font-bold ${accent ?? 'text-gray-100'}`}>{value}</div>
      <div className="text-gray-500 text-xs mt-0.5">{label}</div>
    </div>
  );
}

function AgentRow({
  agent,
  expanded,
  onToggle,
}: {
  agent: EvalAgent;
  expanded: boolean;
  onToggle: () => void;
}) {
  const color = AGENT_COLORS[agent.agent] ?? 'border-gray-800 bg-gray-900';
  const cacheHitLabel =
    agent.type === 'llm'
      ? agent.cache.hit
        ? '✓ Cache HIT'
        : agent.calls.length
          ? 'Cache MISS'
          : 'No LLM call'
      : agent.cache.strategy === 'none'
        ? 'No cache'
        : agent.cache.strategy;

  return (
    <div className={`border rounded-xl overflow-hidden ${color}`}>
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
      >
        <div>
          <div className="font-medium text-gray-100">{agent.label}</div>
          <div className="text-xs text-gray-500 mt-0.5">
            {TYPE_LABELS[agent.type] ?? agent.type} · {agent.latency_ms.toFixed(0)} ms
          </div>
        </div>
        <div className="text-right text-sm shrink-0">
          <div className="text-gray-300">{fmtCost(agent.cost_usd)}</div>
          <div className="text-xs text-gray-500">
            {agent.tokens.total.toLocaleString()} tok · {cacheHitLabel}
          </div>
        </div>
        <span className="text-gray-500 text-xs">{expanded ? '▲' : '▼'}</span>
      </button>

      {expanded && (
        <div className="border-t border-gray-800/80 px-4 py-3 bg-black/20 text-sm space-y-3">
          <DetailGrid agent={agent} />
          {agent.calls.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-widest text-gray-500 mb-2">
                LLM Calls
              </div>
              {agent.calls.map((call, i) => (
                <div
                  key={i}
                  className="bg-gray-950/60 rounded-lg p-3 text-xs space-y-1 mb-2 last:mb-0"
                >
                  <div className="flex justify-between">
                    <span className="text-gray-300">{call.model}</span>
                    <span
                      className={
                        call.cache_hit ? 'text-green-400' : 'text-orange-400'
                      }
                    >
                      {call.cache_hit ? 'LRU Cache HIT' : 'LRU Cache MISS'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-gray-400">
                    <span>Input tokens</span>
                    <span>{call.input_tokens.toLocaleString()}</span>
                    <span>Output tokens</span>
                    <span>{call.output_tokens.toLocaleString()}</span>
                    <span>Latency</span>
                    <span>{call.latency_ms.toFixed(1)} ms</span>
                    <span>Cost</span>
                    <span>{fmtCost(call.cost_usd)}</span>
                    <span>If uncached</span>
                    <span>{fmtCost(call.cost_if_uncached_usd)}</span>
                    <span>Saved</span>
                    <span className="text-green-400">
                      {fmtCost(call.cost_saved_usd)}
                    </span>
                    <span>Cache strategy</span>
                    <span>{call.cache_strategy}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DetailGrid({ agent }: { agent: EvalAgent }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
      <DetailItem label="Agent type" value={TYPE_LABELS[agent.type] ?? agent.type} />
      <DetailItem label="Latency" value={`${agent.latency_ms.toFixed(1)} ms`} />
      <DetailItem label="Cache strategy" value={agent.cache.strategy} />
      <DetailItem
        label="Cache detail"
        value={agent.cache.reason ?? (agent.cache.hit ? 'Hit' : 'Miss')}
      />
      <DetailItem label="Input tokens" value={agent.tokens.input.toLocaleString()} />
      <DetailItem label="Output tokens" value={agent.tokens.output.toLocaleString()} />
      <DetailItem label="Cost" value={fmtCost(agent.cost_usd)} />
      <DetailItem
        label="Cost if uncached"
        value={fmtCost(agent.cost_if_uncached_usd)}
      />
      <DetailItem
        label="Cost saved"
        value={fmtCost(agent.cost_saved_usd)}
        accent="text-green-400"
      />
      {agent.model && <DetailItem label="Model" value={agent.model} />}
    </div>
  );
}

function DetailItem({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div>
      <div className="text-gray-500">{label}</div>
      <div className={`text-gray-200 ${accent ?? ''}`}>{value}</div>
    </div>
  );
}
