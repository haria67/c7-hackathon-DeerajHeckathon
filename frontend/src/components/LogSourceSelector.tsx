import { useRef, useState } from 'react';

interface Props {
  onRun: (
    source: string,
    file?: File,
    githubUrl?: string,
    includeLogs?: boolean,
    slackWebhookUrl?: string,
  ) => void;
  onSourceChange?: (source: string) => void;
  loading: boolean;
}

export default function LogSourceSelector({ onRun, onSourceChange, loading }: Props) {
  const [source, setSource] = useState('synthetic');
  const [file, setFile] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState('');
  const [includeLogs, setIncludeLogs] = useState(false);
  const [slackWebhookUrl, setSlackWebhookUrl] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  function selectSource(next: string) {
    setSource(next);
    if (next !== 'upload') {
      setFile(null);
      if (inputRef.current) inputRef.current.value = '';
    }
    onSourceChange?.(next);
    if (next === 'upload') inputRef.current?.click();
  }

  const canRun =
    source === 'github'
      ? githubUrl.trim().length > 0
      : source !== 'upload' || !!file;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-gray-400 text-xs uppercase tracking-widest">Log Source</span>
        {['synthetic', 'system', 'upload', 'github'].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => selectSource(s)}
            className={`px-4 py-1.5 rounded-md text-sm transition-colors ${
              source === s
                ? 'bg-blue-900 border border-blue-500 text-blue-300'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {s === 'synthetic'
              ? '⚡ Synthetic'
              : s === 'system'
                ? '🖥️ System Logs'
                : s === 'upload'
                  ? '📁 Upload File'
                  : '🐙 GitHub Repo'}
          </button>
        ))}
        <input
          ref={inputRef}
          type="file"
          accept=".log,.txt"
          className="hidden"
          onChange={(e) => {
            const picked = e.target.files?.[0] ?? null;
            setFile(picked);
            if (picked) {
              setSource('upload');
              onSourceChange?.('upload');
            }
          }}
        />
        {file && source === 'upload' && (
          <span className="text-xs text-gray-400">{file.name}</span>
        )}
        <button
          type="button"
          onClick={() => {
            const slack = slackWebhookUrl.trim();
            if (source === 'github') {
              onRun('github', undefined, githubUrl.trim(), includeLogs, slack);
            } else {
              onRun(source, source === 'upload' ? file ?? undefined : undefined, undefined, undefined, slack);
            }
          }}
          disabled={loading || !canRun}
          className="ml-auto px-5 py-1.5 bg-red-600 hover:bg-red-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-bold rounded-md transition-colors"
        >
          {loading ? '⏳ Analyzing...' : '▶ Run Analysis'}
        </button>
      </div>

      {source === 'github' && (
        <div className="space-y-2">
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="url"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/owner/repo or owner/repo"
              className="flex-1 bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none focus:border-blue-600"
            />
            <p className="text-xs text-gray-500 sm:self-center">
              Scans code only by default · languages · OWASP patterns
            </p>
          </div>
          <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={includeLogs}
              onChange={(e) => setIncludeLogs(e.target.checked)}
              className="rounded border-gray-600"
            />
            Also run synthetic log analysis (combines log + code results)
          </label>
        </div>
      )}

      <div className="pt-2 border-t border-gray-800">
        <label className="block text-xs uppercase tracking-widest text-gray-500 mb-2">
          Slack notification (optional)
        </label>
        <input
          type="url"
          value={slackWebhookUrl}
          onChange={(e) => setSlackWebhookUrl(e.target.value)}
          placeholder="https://hooks.slack.com/services/T.../B.../..."
          className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none focus:border-blue-600"
        />
        <p className="text-xs text-gray-500 mt-1">
          Posts incidents and remediation steps to your channel when analysis completes.
        </p>
      </div>
    </div>
  );
}
