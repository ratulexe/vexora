"use client";

import {
  ArrowRight,
  Blocks,
  Bot,
  ChevronDown,
  CircleCheck,
  CircleHelp,
  Clock,
  FileSearch,
  Gauge,
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
import { useEffect, useRef, useState, type ComponentProps, type ReactNode } from "react";
import type { Classification, Indicator, Report } from "@/lib/report";
import RegistryPanel, { canRegister } from "./RegistryPanel";
import CollapsibleCard from "./CollapsibleCard";
import TechnicalDetails from "./TechnicalDetails";

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
  const hasTechnical = Boolean(report.details && Object.keys(report.details).length > 0);

  const sections: NavSection[] = [
    { id: "report-summary", label: "Summary", icon: Gauge },
    { id: "report-ai", label: "AI", icon: Bot },
    { id: "report-evidence", label: "Evidence", icon: FileSearch },
    ...(otherActions.length > 0 ? [{ id: "report-actions", label: "What to do", icon: ShieldCheck }] : []),
    ...(related.length > 0 ? [{ id: "report-related", label: "Related", icon: Network }] : []),
    ...(security ? [{ id: "report-security", label: "Security", icon: ShieldHalf, opens: true }] : []),
    ...(canRegister(report) ? [{ id: "report-registry", label: "Registry", icon: Blocks, opens: true }] : []),
    ...(hasTechnical ? [{ id: "report-technical", label: "Technical details", icon: ScanSearch, opens: true }] : []),
    { id: "report-limitations", label: "Limitations", icon: Info, opens: true },
  ];

  return (
    <article className="report" aria-label="Investigation report">
      <ReportNav sections={sections} />

      <div id="report-summary" className="verdict report-section" data-risk={verdict.risk}>
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
          <div className="verdict-level">
            <span className="verdict-label">Risk level</span>
            <span className="risk-badge">{report.classification}</span>
            <RiskMeter risk={verdict.risk} />
          </div>
        </div>
        <h2>{verdict.headline}</h2>
        <p>{verdict.summary}</p>
        <p className="subject">{report.input.length > 160 ? `${report.input.slice(0, 160)}...` : report.input}</p>
        {firstAction && (
          <p className="verdict-first-action">
            <ArrowRight size={16} aria-hidden /> {firstAction}
          </p>
        )}
        <div className="meta-row">
          <span>
            <TriangleAlert size={14} aria-hidden /> {warnings.length} warning{warnings.length === 1 ? "" : "s"}
          </span>
          <span title={`Evidence coverage: ${report.confidence}`}>
            <ListChecks size={14} aria-hidden /> {shortCoverage(report.confidence)}
          </span>
          <span title={new Date(report.analysed_at).toLocaleString()}>
            <Clock size={14} aria-hidden />{" "}
            {report.from_cache ? `Saved ${minutesAgo(report.analysed_at)}` : checkedAt(report.analysed_at)}
          </span>
          {report.from_cache && (
            <button type="button" className="link-button" onClick={onRecheck} disabled={busy}>
              <RefreshCw size={14} aria-hidden /> Re-check now
            </button>
          )}
        </div>
      </div>

      {report.ai_summary ? (
        <section id="report-ai" className="card ai-card report-section">
          <h3>
            <Bot size={18} aria-hidden /> AI explanation
          </h3>
          <p>{report.ai_summary}</p>
          <p className="note" style={{ marginTop: 10 }}>
            Written by AI from the findings below. The risk level is set by fixed rules, not by the AI.
          </p>
        </section>
      ) : (
        <section id="report-ai" className="card ai-card ai-card-missing report-section">
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

      <section id="report-evidence" className="card report-section">
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
        <section id="report-actions" className="card report-section">
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
        <section id="report-related" className="card report-section">
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
        <CollapsibleCard id="report-security" icon={ShieldHalf} title="Website security">
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
        </CollapsibleCard>
      )}

      <RegistryPanel key={`registry-${report.analysed_at}`} report={report} apiUrl={apiUrl} />

      {hasTechnical && (
        <TechnicalDetails
          key={`technical-${report.analysed_at}`}
          id="report-technical"
          details={report.details as ComponentProps<typeof TechnicalDetails>["details"]}
        />
      )}

      <Disclosure
        icon={Info}
        title={`Limitations (${report.limitations.length})`}
        id="report-limitations"
       
      >
        <ul>
          {report.limitations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </Disclosure>
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
  id,
}: {
  icon: LucideIcon;
  title: string;
  children: ReactNode;
  style?: React.CSSProperties;
  id?: string;
}) {
  return (
    <details className="disclosure report-section" style={style} id={id}>
      <summary>
        <Icon size={16} aria-hidden /> {title}
        <ChevronDown size={16} className="chevron" aria-hidden />
      </summary>
      <div className="disclosure-body">{children}</div>
    </details>
  );
}

const RISK_STEPS: { risk: Risk; label: string }[] = [
  { risk: "low", label: "Low" },
  { risk: "suspicious", label: "Suspicious" },
  { risk: "high", label: "High" },
  { risk: "critical", label: "Malicious" },
];

/** Four-step bar showing where the result sits between Low Risk and Confirmed Malicious. */
function RiskMeter({ risk }: { risk: Risk }) {
  const reached = RISK_STEPS.findIndex((step) => step.risk === risk);
  return (
    <span className="risk-meter" aria-hidden data-unknown={reached < 0}>
      {RISK_STEPS.map((step, index) => (
        <span key={step.risk} className="risk-step" data-on={index <= reached} />
      ))}
    </span>
  );
}

interface NavSection {
  id: string;
  label: string;
  icon: LucideIcon;
  /** Open this disclosure when jumping to it. */
  opens?: boolean;
}

/** Sticky bar under the site header that jumps to each part of the report. */
function ReportNav({ sections }: { sections: NavSection[] }) {
  const [active, setActive] = useState(sections[0]?.id);
  const bar = useRef<HTMLElement>(null);
  const ids = sections.map((section) => section.id).join(" ");

  useEffect(() => {
    const targets = ids
      .split(" ")
      .map((id) => document.getElementById(id))
      .filter((element): element is HTMLElement => element !== null);
    // The active section is the last one whose top has scrolled under the two bars.
    function update() {
      const passed = targets.filter((element) => element.getBoundingClientRect().top < 170);
      const current = passed.at(-1) ?? targets[0];
      if (current) setActive(current.id);
    }
    window.addEventListener("scroll", update, { passive: true });
    return () => window.removeEventListener("scroll", update);
  }, [ids]);

  useEffect(() => {
    const chip = bar.current?.querySelector<HTMLElement>(`[data-target="${active}"]`);
    if (chip && bar.current) {
      bar.current.scrollTo({ left: chip.offsetLeft - bar.current.clientWidth / 2 + chip.clientWidth / 2 });
    }
  }, [active]);

  function jump(section: NavSection) {
    const target = document.getElementById(section.id);
    if (!target) return;
    if (section.opens && target instanceof HTMLDetailsElement) target.open = true;
    const smooth = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    target.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
    setActive(section.id);
  }

  return (
    <nav className="report-nav" aria-label="Report sections" ref={bar}>
      {sections.map((section) => {
        const SectionIcon = section.icon;
        return (
          <a
            key={section.id}
            href={`#${section.id}`}
            data-target={section.id}
            aria-current={active === section.id ? "true" : undefined}
            onClick={(event) => {
              event.preventDefault();
              jump(section);
            }}
          >
            <SectionIcon size={14} aria-hidden /> {section.label}
          </a>
        );
      })}
    </nav>
  );
}

/** "Medium (5 of 6 checks completed; ...)" becomes "5/6 checks"; other wording keeps just its level. */
function shortCoverage(confidence: string): string {
  const counts = confidence.match(/(\d+) of (\d+) checks/);
  if (counts) return `${counts[1]}/${counts[2]} checks`;
  const level = confidence.split(" (")[0];
  return /^(High|Medium|Low)$/.test(level) ? `${level} coverage` : level;
}

function checkedAt(iso: string): string {
  const date = new Date(iso);
  const sameDay = date.toDateString() === new Date().toDateString();
  return sameDay
    ? date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })
    : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function minutesAgo(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  return minutes < 1 ? "less than a minute ago" : minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
}
