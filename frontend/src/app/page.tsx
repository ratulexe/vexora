"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import type { Report } from "@/lib/report";
import RegistryPanel from "./RegistryPanel";
import styles from "./page.module.css";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Mode = "url" | "message";

export default function Home() {
  const [mode, setMode] = useState<Mode>("url");
  const [value, setValue] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    void runAnalysis(false);
  }

  async function runAnalysis(refresh: boolean) {
    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const response = await fetch(`${API_URL}/analyze/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(mode === "url" ? { url: value, refresh } : { message: value }),
      });
      if (!response.ok) throw new Error(`Request failed (${response.status})`);
      setReport(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  function switchMode(next: Mode) {
    setMode(next);
    setValue("");
    setReport(null);
    setError(null);
  }

  return (
    <main className={styles.main}>
      <h1>Vexora</h1>
      <p className={styles.intro}>
        Check a suspicious link or message and see the evidence. Never enter passwords, OTPs or
        private keys here. <Link href="/verify">Verify a registered report</Link>
      </p>

      <div className={styles.tabs}>
        <button type="button" aria-pressed={mode === "url"} onClick={() => switchMode("url")}>
          Link or domain
        </button>
        <button
          type="button"
          aria-pressed={mode === "message"}
          onClick={() => switchMode("message")}
        >
          Message or email
        </button>
      </div>

      <form className={styles.form} onSubmit={handleSubmit}>
        {mode === "url" ? (
          <input
            aria-label="Link or domain"
            placeholder="https://example.com"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            required
          />
        ) : (
          <textarea
            aria-label="Message or email"
            placeholder="Paste the suspicious message"
            rows={6}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            required
          />
        )}
        <button type="submit" disabled={loading}>
          {loading ? "Investigating..." : "Investigate"}
        </button>
      </form>

      {error && (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      )}

      {report && (
        <section className={styles.report}>
          <h2>{report.classification}</h2>
          <p>Evidence coverage: {report.confidence}</p>
          <p>Analysed: {new Date(report.analysed_at).toLocaleString()}</p>
          {report.from_cache && (
            <p className={styles.note}>
              Saved result from {minutesAgo(report.analysed_at)}. Results for the same link are reused for 30
              minutes.{" "}
              <button type="button" className={styles.linkButton} onClick={() => void runAnalysis(true)} disabled={loading}>
                {loading ? "Checking again..." : "Re-check now"}
              </button>
            </p>
          )}

          {report.ai_summary && (
            <div className={styles.aiSummary}>
              <h3>AI explanation</h3>
              <p>{report.ai_summary}</p>
              <p className={styles.note}>
                Written by AI from the findings below. The risk level is set by fixed rules, not by the AI.
              </p>
            </div>
          )}

          <h3>Indicators</h3>
          {report.indicators.length === 0 ? (
            <p>None identified in the available checks. This does not prove it is safe.</p>
          ) : (
            <ul>
              {report.indicators.map((indicator) => (
                <li key={`${indicator.title}-${indicator.evidence}`}>
                  <strong>
                    {indicator.severity}: {indicator.title}
                  </strong>
                  <br />
                  {indicator.evidence} (Source: {indicator.source})
                </li>
              ))}
            </ul>
          )}

          <h3>Recommended actions</h3>
          <ul>
            {report.recommended_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>

          <h3>Limitations</h3>
          <ul>
            {report.limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>

          {report.security_assessment && (
            <section className={styles.securitySection}>
              <h3>Website security</h3>
              <p className={styles.note}>
                How well {report.security_assessment.url} protects its visitors. These are configuration checks,
                separate from the risk level above.
              </p>
              <p>
                Certificate: <strong>{report.security_assessment.tls_verdict}</strong>
                {report.security_assessment.tls_verdict === "Valid" && " (a valid certificate does not mean the site is genuine)"}
              </p>
              {report.security_assessment.findings.length === 0 ? (
                <p>No configuration weaknesses found in the passive checks.</p>
              ) : (
                <ul>
                  {report.security_assessment.findings.map((finding) => (
                    <li key={finding.issue}>
                      <strong>
                        {finding.severity}: {finding.issue}
                      </strong>
                      <br />
                      {finding.evidence} {finding.impact}
                      <br />
                      <em>Fix:</em> {finding.remediation}
                    </li>
                  ))}
                </ul>
              )}
              {report.security_assessment.passed.length > 0 && (
                <p className={styles.note}>Passed: {report.security_assessment.passed.join(", ")}.</p>
              )}
              <details>
                <summary>What was not checked</summary>
                <ul>
                  {report.security_assessment.limitations.map((limitation) => (
                    <li key={limitation}>{limitation}</li>
                  ))}
                </ul>
              </details>
            </section>
          )}

          {report.details && Object.keys(report.details).length > 0 && (
            <details className={styles.details}>
              <summary>Technical details</summary>
              <pre>{JSON.stringify(report.details, null, 2)}</pre>
            </details>
          )}

          <RegistryPanel key={report.analysed_at} report={report} apiUrl={API_URL} />
        </section>
      )}
    </main>
  );
}

function minutesAgo(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  return minutes < 1 ? "less than a minute ago" : minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
}
