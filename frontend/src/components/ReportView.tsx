"use client";

import {
  ArrowRight,
  Bot,
  ChevronDown,
  CircleCheck,
  CircleHelp,
  Clock,
  FileSearch,
  Info,
  ListChecks,
  Lock,
  Network,
  OctagonAlert,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import type { ReactNode } from "react";
import type { Classification, Indicator, Report } from "@/lib/report";
import RegistryPanel from "./RegistryPanel";

type Risk = "low" | "suspicious" | "high" | "critical" | "unknown";

const VERDICTS: Record<Classification, { risk: Risk; icon: LucideIcon; headline: string; summary: string }> = {
  "Low Risk": {
    risk: "low",
    icon: ShieldCheck,
    headline: "No warning signs found",
    summary: "None of the checks that ran found a problem. That is not proof it is safe, so stay alert.",
  },
  Suspicious: {
    risk: "suspicious",
    icon: TriangleAlert,
    headline: "Be careful with this",
    summary: "There are warning signs that need checking before you trust it.",
  },
  "High Risk": {
    risk: "high",
    icon: ShieldAlert,
    headline: "This looks dangerous",
    summary: "Several strong warning signs point to a scam or attack.",
  },
  "Confirmed Malicious": {
    risk: "critical",
    icon: OctagonAlert,
    headline: "Known to be malicious",
    summary: "Threat intelligence lists this as an active threat.",
  },
  Inconclusive: {
    risk: "unknown",
    icon: CircleHelp,
    headline: "Not enough evidence to judge",
    summary: "Some checks could not run. Treat it with caution until you can verify it another way.",
  },
};

const WARNING = new Set(["Critical", "High", "Medium"]);

interface Props {
  report: Report;
  apiUrl: string;
  onRecheck: () => void;
  busy: boolean;
}

export default function ReportView({ report, apiUrl, onRecheck, busy }: Props) {
  const verdict = VERDICTS[report.classification];
  const Icon = verdict.icon;
  const warnings = report.indicators.filter((item) => WARNING.has(item.severity));
  const security = report.security_assessment;
  const related = report.correlation?.related ?? [];
  const [firstAction, ...otherActions] = report.recommended_actions;
  const reduceMotion = useReducedMotion() ?? false;
  const alarming = verdict.risk === "high" || verdict.risk === "critical";

  return (
    <article className="report" aria-label="Investigation report">
      <div className="verdict" data-risk={verdict.risk}>
        <div className="verdict-top">
          <motion.span
            className="verdict-icon"
            initial={reduceMotion ? false : { scale: 0.3, opacity: 0 }}
            animate={
              reduceMotion
                ? { scale: 1, opacity: 1 }
                : { scale: 1, opacity: 1, rotate: alarming ? [0, -12, 12, -8, 8, 0] : 0 }
            }
            transition={{
              scale: { type: "spring", stiffness: 380, damping: 16 },
              opacity: { duration: 0.2 },
              rotate: { delay: 0.35, duration: 0.6 },
            }}
          >
            <Icon size={44} aria-hidden />
          </motion.span>
          <div>
            <div className="verdict-label">{report.classification}</div>
            <h2>{verdict.headline}</h2>
            <p>{verdict.summary}</p>
            <p className="subject">{report.input.length > 160 ? `${report.input.slice(0, 160)}...` : report.input}</p>
          </div>
        </div>
        {firstAction && (
          <p className="verdict-first-action">
            <ArrowRight size={16} aria-hidden /> {firstAction}
          </p>
        )}
        <div className="meta-row">
          <span>
            <TriangleAlert size={14} aria-hidden /> {warnings.length} warning sign{warnings.length === 1 ? "" : "s"}
          </span>
          <span>
            <ListChecks size={14} aria-hidden /> Evidence coverage: {report.confidence}
          </span>
          <span>
            <Clock size={14} aria-hidden /> {report.from_cache ? `Saved result from ${minutesAgo(report.analysed_at)}` : `Checked ${new Date(report.analysed_at).toLocaleString()}`}
          </span>
          {report.from_cache && (
            <button type="button" className="link-button" onClick={onRecheck} disabled={busy}>
              <RefreshCw size={14} aria-hidden /> Re-check now
            </button>
          )}
        </div>
      </div>

      {report.ai_summary ? (
        <section className="card ai-card" style={{ marginTop: 16 }}>
          <h3>
            <Bot size={18} aria-hidden /> AI explanation
          </h3>
          <p>{report.ai_summary}</p>
          <p className="note" style={{ marginTop: 10 }}>
            Written by AI from the findings below. The risk level is set by fixed rules, not by the AI.
          </p>
        </section>
      ) : (
        <section className="card ai-card ai-card-missing" style={{ marginTop: 16 }}>
          <h3>
            <Bot size={18} aria-hidden /> AI explanation
          </h3>
          <p className="note">
            {report.limitations.find((item) => item.startsWith("AI explanation")) ??
              "No AI explanation for this report."}{" "}
            The risk level and evidence below come from fixed rules and do not depend on the AI.
          </p>
        </section>
      )}

      <section className="card" style={{ marginTop: 16 }}>
        <h3>
          <FileSearch size={18} aria-hidden /> Evidence
        </h3>
        {report.indicators.length === 0 ? (
          <p className="note">No indicators were found in the checks that ran. This does not prove it is safe.</p>
        ) : (
          <ul className="finding-list">
            {report.indicators.map((indicator) => (
              <Finding key={`${indicator.title}-${indicator.evidence}`} indicator={indicator} />
            ))}
          </ul>
        )}
      </section>

      {otherActions.length > 0 && (
        <section className="card" style={{ marginTop: 16 }}>
          <h3>
            <ShieldCheck size={18} aria-hidden /> What to do
          </h3>
          <ul className="action-list">
            {report.recommended_actions.map((action) => (
              <li key={action}>
                <ArrowRight size={15} aria-hidden /> {action}
              </li>
            ))}
          </ul>
        </section>
      )}

      {related.length > 0 && (
        <section className="card" style={{ marginTop: 16 }}>
          <h3>
            <Network size={18} aria-hidden /> Related reports
          </h3>
          <p className="note" style={{ marginBottom: 12 }}>
            Earlier suspicious reports that share something with this one. Connections come from exact matches, not
            from the AI.
          </p>
          <ul className="finding-list">
            {related.map((item) => (
              <li key={item.incident_id} className="finding">
                <span className="pill" data-severity={item.strong ? "High" : "Info"}>
                  {item.strong ? "Strong" : "Possible"}
                </span>
                <span className="finding-title">
                  {item.classification} {item.kind} report
                </span>
                <span className="finding-body">
                  {item.links.join("; ")}. First seen {new Date(item.first_seen).toLocaleString()}
                  {item.times_seen > 1 ? `, reported ${item.times_seen} times` : ""}.
                </span>
              </li>
            ))}
          </ul>
          {report.correlation && <p className="note" style={{ marginTop: 10 }}>{report.correlation.retention}</p>}
        </section>
      )}

      {security && (
        <section className="card" style={{ marginTop: 16 }}>
          <h3>
            <ShieldHalf size={18} aria-hidden /> Website security
          </h3>
          <p className="note" style={{ marginBottom: 12 }}>
            How well <code>{security.url}</code> protects its visitors. These configuration checks do not change the
            risk level above.
          </p>
          <p style={{ marginBottom: 12 }}>
            <Lock size={14} aria-hidden style={{ verticalAlign: "-2px" }} /> Certificate:{" "}
            <span className="tag">{security.tls_verdict}</span>
            {security.tls_verdict === "Valid" && <span className="note"> (a valid certificate does not mean the site is genuine)</span>}
          </p>
          {security.findings.length > 0 ? (
            <ul className="finding-list">
              {security.findings.map((finding) => (
                <li key={finding.issue} className="finding">
                  <span className="pill" data-severity={finding.severity}>
                    {finding.severity}
                  </span>
                  <span className="finding-title">{finding.issue}</span>
                  <span className="finding-body">
                    {finding.evidence} {finding.impact}
                    <br />
                    <strong>Fix:</strong> {finding.remediation}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="note">No configuration weaknesses found in the passive checks.</p>
          )}
          {security.passed.length > 0 && (
            <ul className="check-list" style={{ marginTop: 12 }}>
              {security.passed.map((item) => (
                <li key={item}>
                  <CircleCheck size={14} aria-hidden /> {item}
                </li>
              ))}
            </ul>
          )}
          <Disclosure icon={Info} title="What was not checked" style={{ marginTop: 12 }}>
            <ul>
              {security.limitations.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </Disclosure>
        </section>
      )}

      <RegistryPanel key={report.analysed_at} report={report} apiUrl={apiUrl} />

      <div style={{ marginTop: 16 }}>
        <Disclosure icon={Info} title={`Limitations (${report.limitations.length})`}>
          <ul>
            {report.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </Disclosure>
        {report.details && Object.keys(report.details).length > 0 && (
          <Disclosure icon={ScanSearch} title="Technical details">
            <pre>{JSON.stringify(report.details, null, 2)}</pre>
          </Disclosure>
        )}
      </div>
    </article>
  );
}

function Finding({ indicator }: { indicator: Indicator }) {
  return (
    <li className="finding">
      <span className="pill" data-severity={indicator.severity}>
        {indicator.severity}
      </span>
      <span className="finding-title">{indicator.title}</span>
      <span className="finding-body">
        {indicator.evidence}
        {indicator.evidence ? " " : ""}
        <em>Source: {indicator.source}</em>
      </span>
    </li>
  );
}

function Disclosure({
  icon: Icon,
  title,
  children,
  style,
}: {
  icon: LucideIcon;
  title: string;
  children: ReactNode;
  style?: React.CSSProperties;
}) {
  return (
    <details className="disclosure" style={style}>
      <summary>
        <Icon size={16} aria-hidden /> {title}
        <ChevronDown size={16} className="chevron" aria-hidden />
      </summary>
      <div className="disclosure-body">{children}</div>
    </details>
  );
}

function minutesAgo(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  return minutes < 1 ? "less than a minute ago" : minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
}
