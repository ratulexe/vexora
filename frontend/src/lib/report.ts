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
}
