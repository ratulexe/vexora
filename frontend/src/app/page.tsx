"use client";

import {
  ArrowRight,
  Blocks,
  Bot,
  CircleAlert,
  Fingerprint,
  Link2,
  Lock,
  Mail,
  Network,
  ScanSearch,
  ShieldCheck,
  ShieldHalf,
  Sparkles,
} from "lucide-react";
import { FormEvent, useState } from "react";
import AnalysisProgress from "@/components/AnalysisProgress";
import ReportView from "@/components/ReportView";
import type { Report } from "@/lib/report";
import { ANALYSIS_TIMEOUT_MS, postJson } from "@/lib/request";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const FINISH_PAUSE_MS = 400;

type Mode = "url" | "message";
type Phase = "idle" | "running" | "finishing";

const EXAMPLES: Record<Mode, { label: string; value: string }[]> = {
  url: [
    { label: "Look-alike PayPal", value: "https://paypa1-secure-login.com/verify" },
    { label: "Expired certificate", value: "https://expired.badssl.com" },
    { label: "github.com", value: "https://github.com" },
  ],
  message: [
    {
      label: "Fake SBI KYC",
      value:
        "Dear Customer, your SBI account will be blocked today. Update your KYC immediately at hxxps://sbi-kyc-update[.]in/login or call 9876543210. Share the OTP to verify.",
    },
    {
      label: "Lottery fee",
      value: "Congratulations! You have won Rs 25,00,000 in KBC lucky draw. Pay registration fee of Rs 5000 to claim@ybl to release your prize.",
    },
    { label: "Genuine OTP", value: "Your OTP for login is 482913. Do not share it with anyone. - HDFC Bank" },
  ],
};

const FEATURES = [
  { icon: Link2, title: "Link investigation", text: "Look-alike domains, homographs, redirects and known phishing feeds, checked without ever running the page's scripts." },
  { icon: Lock, title: "Certificate trust", text: "Expiry, name mismatches, weak keys and distrusted certificate authorities, checked against browsers' root store." },
  { icon: Mail, title: "Scam message analysis", text: "OTP requests, fake KYC, digital arrest, lottery fees and job scams, with every finding quoted from the message." },
  { icon: Network, title: "Campaign correlation", text: "Links reports that reuse the same domain, destination, phone number, UPI ID or wording." },
  { icon: ShieldHalf, title: "Website security", text: "Passive checks of HSTS, CSP, clickjacking protection, cookies and old TLS versions, each with a fix." },
  { icon: Blocks, title: "On-chain registry", text: "Tamper-evident threat reports on Ethereum Sepolia that anyone can verify in their own browser." },
];

const STEPS = [
  { title: "Submit", text: "Paste a link, domain, email or message. Never paste passwords or OTPs." },
  { title: "Investigate", text: "Vexora checks threat feeds, certificates, redirects and scam patterns safely." },
  { title: "Assess", text: "Fixed rules set the risk level from the evidence. AI explains it in plain language." },
  { title: "Report and verify", text: "Share suspicious reports on-chain, so anyone can check they were never changed." },
];

export default function Home() {
  const [mode, setMode] = useState<Mode>("url");
  const [value, setValue] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [runId, setRunId] = useState(0);
  const busy = phase !== "idle";

  async function runAnalysis(refresh: boolean, input = value) {
    setPhase("running");
    setRunId((id) => id + 1);
    setError(null);
    setReport(null);
    try {
      const body = mode === "url" ? { url: input, refresh } : { message: input };
      const result = await postJson<Report>(`${API_URL}/analyze/${mode}`, body, ANALYSIS_TIMEOUT_MS);
      setPhase("finishing");
      // A brief moment at 100% so the jump to the report does not feel abrupt.
      await new Promise((resolve) => setTimeout(resolve, FINISH_PAUSE_MS));
      setReport(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setPhase("idle");
    }
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    void runAnalysis(false);
  }

  function switchMode(next: Mode) {
    setMode(next);
    setValue("");
    setReport(null);
    setError(null);
  }

  function tryExample(example: string) {
    setValue(example);
    void runAnalysis(false, example);
  }

  return (
    <>
      <section className="hero container">
        <span className="eyebrow">
          <Sparkles size={14} aria-hidden /> AI-powered web threat detection
        </span>
        <h1>
          Check before you click,
          <br />
          <span className="accent">pay or reply.</span>
        </h1>
        <p className="lead">
          Paste a suspicious link or message. Vexora investigates it, shows you the evidence, and tells you what to
          do next.
        </p>
        <div className="trust-row">
          <span>
            <ShieldCheck size={15} aria-hidden /> Evidence for every finding
          </span>
          <span>
            <Fingerprint size={15} aria-hidden /> Personal details removed before AI
          </span>
          <span>
            <Blocks size={15} aria-hidden /> Reports verifiable on-chain
          </span>
        </div>
      </section>

      <section id="check" className="container" style={{ scrollMarginTop: 80 }}>
        <div className="card checker">
          <div className="tabs" role="tablist" aria-label="What to check">
            <button type="button" role="tab" className="tab" aria-selected={mode === "url"} onClick={() => switchMode("url")}>
              <Link2 size={16} aria-hidden /> Link or domain
            </button>
            <button
              type="button"
              role="tab"
              className="tab"
              aria-selected={mode === "message"}
              onClick={() => switchMode("message")}
            >
              <Mail size={16} aria-hidden /> Message or email
            </button>
          </div>

          <form onSubmit={handleSubmit}>
            {mode === "url" ? (
              <div className="field-row">
                <input
                  className="input"
                  aria-label="Link or domain"
                  placeholder="Paste a link, e.g. https://example.com"
                  value={value}
                  onChange={(event) => setValue(event.target.value)}
                  required
                  autoComplete="off"
                  spellCheck={false}
                />
                <button type="submit" className="button button-primary" disabled={busy}>
                  <ScanSearch size={18} aria-hidden /> {busy ? "Investigating..." : "Investigate"}
                </button>
              </div>
            ) : (
              <div className="form-stack">
                <textarea
                  className="textarea"
                  aria-label="Message or email"
                  placeholder="Paste the suspicious SMS, WhatsApp message or email"
                  value={value}
                  onChange={(event) => setValue(event.target.value)}
                  required
                />
                <button type="submit" className="button button-primary" disabled={busy}>
                  <ScanSearch size={18} aria-hidden /> {busy ? "Investigating..." : "Investigate"}
                </button>
              </div>
            )}
          </form>

          <div className="examples">
            <span>Try an example:</span>
            {EXAMPLES[mode].map((example) => (
              <button key={example.label} type="button" className="chip" onClick={() => tryExample(example.value)} disabled={busy}>
                {example.label}
              </button>
            ))}
          </div>

          <p className="privacy-note">
            <Lock size={14} aria-hidden />
            Never paste passwords, OTPs or card numbers. Phone numbers, UPI IDs and other personal details are removed
            before anything is sent to the AI.
          </p>
        </div>

        <div className="checker">
          {busy && <AnalysisProgress key={runId} mode={mode} finished={phase === "finishing"} />}
          {error && (
            <p role="alert" className="alert-error">
              <CircleAlert size={18} aria-hidden /> {error}
            </p>
          )}
        </div>

        {report && <ReportView report={report} apiUrl={API_URL} onRecheck={() => void runAnalysis(true)} busy={busy} />}
      </section>

      <section className="section container" id="features">
        <h2 className="section-title">
          <ShieldHalf size={26} aria-hidden />
          <span>
            What Vexora <span className="accent accent-text">checks</span>
          </span>
        </h2>
        <p className="section-lead">
          Each finding comes with its evidence and source. Fixed rules decide the risk level; AI only explains it.
        </p>
        <div className="feature-grid">
          {FEATURES.map(({ icon: Icon, title, text }) => (
            <div key={title} className="card feature">
              <Icon size={22} aria-hidden />
              <h3>{title}</h3>
              <p>{text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section container" id="how-it-works" style={{ paddingTop: 0 }}>
        <h2 className="section-title">
          <Bot size={26} aria-hidden />
          <span>
            How it <span className="accent accent-text">works</span>
          </span>
        </h2>
        <p className="section-lead">
          A clean result means no warning signs were found in the checks that ran. It never proves something is safe.
        </p>
        <div className="steps">
          {STEPS.map((step, index) => (
            <div key={step.title} className="card step">
              <span className="step-number">{index + 1}</span>
              <h3>{step.title}</h3>
              <p>{step.text}</p>
            </div>
          ))}
        </div>
        <p style={{ marginTop: 24 }}>
          <a href="#check" className="button button-primary">
            Check something now <ArrowRight size={16} aria-hidden />
          </a>
        </p>
      </section>
    </>
  );
}
