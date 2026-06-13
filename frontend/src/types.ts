export interface Anomaly {
  type: string;
  source_ip?: string;
  severity: string;
  attempt_count?: number;
  detail?: string;
  title?: string;
  recommendation?: string;
}

export interface CVEMatch {
  id: string;
  description: string;
  cvss_score: number;
  linked_anomaly: string;
}

export interface Vulnerability {
  category?: string;
  name?: string;
  header?: string;
  severity: string;
  recommendation?: string;
  file?: string;
  line?: number;
  language?: string;
  snippet?: string;
  source?: string;
}

export interface CodeFinding {
  category: string;
  name: string;
  severity: string;
  recommendation: string;
  file: string;
  line: number;
  language: string;
  snippet: string;
  source: string;
}

export interface ComplianceGap {
  framework: string;
  control_id: string;
  description: string;
  severity: string;
}

export interface AnalyzeMeta {
  log_source: string;
  line_count?: number;
  used_fallback?: boolean;
  paths?: string[];
  fallback_reason?: string;
  github_repo?: string;
  repo_url?: string;
}

export interface SecurityReport {
  session_id: string;
  log_source?: string;
  anomalies: Anomaly[];
  cve_matches: CVEMatch[];
  vulnerabilities: Vulnerability[];
  risk_level: string;
  threat_score: number;
  action_plan: string[];
  runbook_md: string;
  compliance_gaps: ComplianceGap[];
  compliance_score: number;
  github_repo?: string;
  repo_languages?: Record<string, number>;
  primary_language?: string;
  files_scanned?: number;
  code_findings?: CodeFinding[];
  scan_error?: string;
  slack_sent?: boolean;
  slack_error?: string;
  slack_skipped?: boolean;
}

export interface AgentEvent {
  agent: string;
  status: 'running' | 'done' | 'error';
  findings?: unknown[];
  timestamp: string;
}
