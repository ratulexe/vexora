// The shared report format. Keep this in sync with backend/app/schemas.py.

export type Classification =
  | "Low Risk"
  | "Suspicious"
  | "High Risk"
  | "Confirmed Malicious"
  | "Inconclusive";

export type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";

export interface Indicator {
  title: string;
  severity: Severity;
  evidence: string;
  source: string;
}

export interface SecurityFinding {
  issue: string;
  severity: Severity;
  evidence: string;
  impact: string;
  remediation: string;
}

export interface SecurityAssessment {
  url: string;
  tls_verdict: string;
  findings: SecurityFinding[];
  passed: string[];
  limitations: string[];
}

export interface RelatedReport {
  incident_id: string;
  kind: string;
  classification: string;
  first_seen: string;
  times_seen: number;
  links: string[];
  strong: boolean;
}

export interface Correlation {
  incident_id: string | null;
  related: RelatedReport[];
  strong_links: number;
  retention: string;
}

export interface Report {
  input: string;
  classification: Classification;
  indicators: Indicator[];
  confidence: string;
  recommended_actions: string[];
  limitations: string[];
  analysed_at: string;
  details?: Record<string, unknown>;
  ai_summary?: string | null;
  from_cache?: boolean;
  security_assessment?: SecurityAssessment | null;
  correlation?: Correlation | null;
}
