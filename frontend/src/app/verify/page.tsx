"use client";

import {
  BadgeCheck,
  Blocks,
  CircleAlert,
  ExternalLink,
  FileJson,
  Hash,
  History,
  LoaderCircle,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import {
  OnChainRecord,
  REGISTRY,
  RegistryEntry,
  commitmentOf,
  explorerLink,
  lookup,
  packageFromFile,
  recentReports,
  registryConfigured,
} from "@/lib/registry";

const HASH = /^0x[0-9a-fA-F]{64}$/;

export default function VerifyPage() {
  const [packageText, setPackageText] = useState("");
  const [hashInput, setHashInput] = useState("");
  const [computed, setComputed] = useState<string | null>(null);
  const [record, setRecord] = useState<OnChainRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [recent, setRecent] = useState<RegistryEntry[] | null>(null);
  const [recentError, setRecentError] = useState<string | null>(null);

  useEffect(() => {
    if (!registryConfigured) return;
    recentReports()
      .then(setRecent)
      .catch(() => setRecentError("Could not load recent reports from the blockchain."));
  }, []);

  async function check(commitment: string, fromPackage: boolean) {
    setChecking(true);
    setError(null);
    setRecord(null);
    setComputed(fromPackage ? commitment : null);
    try {
      setRecord(await lookup(commitment));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read the blockchain.");
    } finally {
      setChecking(false);
    }
  }

  function verifyPackage(event: FormEvent) {
    event.preventDefault();
    try {
      void check(commitmentOf(packageFromFile(packageText)), true);
    } catch {
      setError("That is not valid report package JSON.");
    }
  }

  function verifyHash(event: FormEvent) {
    event.preventDefault();
    if (!HASH.test(hashInput.trim())) {
      setError("Enter a commitment: 0x followed by 64 hexadecimal characters.");
      return;
    }
    void check(hashInput.trim(), false);
  }

  async function loadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) setPackageText(await file.text());
  }

  return (
    <>
      <section className="hero container">
        <span className="eyebrow">
          <Blocks size={14} aria-hidden /> Independent verification
        </span>
        <h1>
          Verify a threat <span className="accent">report</span>
        </h1>
        <p className="lead">
          Check that a Vexora report has not been changed since it was registered. Your browser computes the
          report&apos;s fingerprint and reads the {REGISTRY.network} directly, so this does not depend on the Vexora
          server.
        </p>
      </section>

      <section className="container checker">
        {!registryConfigured && (
          <p role="alert" className="alert-error">
            <CircleAlert size={18} aria-hidden /> The registry is not configured for this site yet.
          </p>
        )}

        <div className="card">
          <h3>
            <FileJson size={18} aria-hidden /> Check a report file
          </h3>
          <form className="form-stack" onSubmit={verifyPackage}>
            <input type="file" accept="application/json,.json" aria-label="Report package file" onChange={loadFile} />
            <textarea
              className="textarea"
              aria-label="Report package JSON"
              placeholder="Or paste the report package JSON"
              value={packageText}
              onChange={(event) => setPackageText(event.target.value)}
              required
            />
            <button type="submit" className="button button-primary" disabled={checking || !registryConfigured}>
              {checking ? <LoaderCircle size={16} className="spin" aria-hidden /> : <BadgeCheck size={16} aria-hidden />}
              {checking ? "Checking the blockchain..." : "Verify report"}
            </button>
          </form>
        </div>

        <div className="card">
          <h3>
            <Hash size={18} aria-hidden /> Or look up a commitment
          </h3>
          <form className="field-row" onSubmit={verifyHash}>
            <input
              className="input"
              aria-label="Commitment hash"
              placeholder="0x..."
              value={hashInput}
              onChange={(event) => setHashInput(event.target.value)}
              required
              spellCheck={false}
            />
            <button type="submit" className="button" disabled={checking || !registryConfigured}>
              Look up
            </button>
          </form>
        </div>

        {error && (
          <p role="alert" className="alert-error">
            <CircleAlert size={18} aria-hidden /> {error}
          </p>
        )}

        {record && (
          <div className="verdict" data-risk={record.registered ? "low" : "critical"} style={{ marginTop: 16 }} aria-live="polite">
            <div className="verdict-top">
              {record.registered ? (
                <ShieldCheck size={44} className="verdict-icon" aria-hidden />
              ) : (
                <ShieldX size={44} className="verdict-icon" aria-hidden />
              )}
              <div>
                <div className="verdict-label">{record.registered ? "Match found" : "No match"}</div>
                <h2>
                  {record.registered
                    ? computed
                      ? "Verified: this report is unchanged"
                      : "Registered report found"
                    : "Not found on-chain"}
                </h2>
                <p>
                  {record.registered
                    ? "This proves the report has not changed since it was registered, and who registered it and when. It does not prove the report is correct."
                    : computed
                      ? "No registered report has this fingerprint. The file was changed after registration, or it was never registered."
                      : "No report is registered with this commitment."}
                </p>
              </div>
            </div>
            {record.registered ? (
              <RecordDetails record={record} onOpen={(hash) => void check(hash, false)} />
            ) : (
              computed && (
                <p className="note" style={{ marginTop: 12 }}>
                  Computed fingerprint: <code>{computed}</code>
                </p>
              )
            )}
          </div>
        )}

        {registryConfigured && (
          <div className="card" style={{ marginTop: 16 }}>
            <h3>
              <History size={18} aria-hidden /> Recently registered reports
            </h3>
            {recentError && <p className="note">{recentError}</p>}
            {!recent && !recentError && (
              <p className="note">
                <LoaderCircle size={14} className="spin" aria-hidden style={{ verticalAlign: "-2px" }} /> Loading from
                the blockchain...
              </p>
            )}
            {recent?.length === 0 && <p className="note">No reports have been registered yet.</p>}
            {recent && recent.length > 0 && (
              <ul className="finding-list">
                {recent.map((entry) => (
                  <li key={entry.commitment} className="finding">
                    <span className="pill" data-severity={pillFor(entry.classification)}>
                      {entry.kind}
                    </span>
                    <button type="button" className="link-button finding-title" onClick={() => void check(entry.commitment, false)}>
                      {entry.classification} {entry.kind.toLowerCase()} report
                    </button>
                    <span className="finding-body">
                      {entry.registeredAt.toLocaleString()} · <code>{short(entry.commitment)}</code>
                      {explorerLink("tx", entry.transactionHash) && (
                        <>
                          {" "}
                          ·{" "}
                          <a href={explorerLink("tx", entry.transactionHash)!} target="_blank" rel="noreferrer">
                            transaction <ExternalLink size={11} aria-hidden />
                          </a>
                        </>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <p className="note" style={{ marginTop: 12 }}>
              Contract:{" "}
              {explorerLink("address", REGISTRY.address) ? (
                <a href={explorerLink("address", REGISTRY.address)!} target="_blank" rel="noreferrer">
                  <code>{REGISTRY.address}</code>
                </a>
              ) : (
                <code>{REGISTRY.address}</code>
              )}{" "}
              on {REGISTRY.network}
            </p>
          </div>
        )}
      </section>
      <div style={{ height: 56 }} />
    </>
  );
}

function RecordDetails({ record, onOpen }: { record: OnChainRecord; onOpen: (hash: string) => void }) {
  const reporterLink = explorerLink("address", record.reporter);
  return (
    <ul className="result-row" style={{ marginTop: 14 }}>
      <li>
        <span className="label">Status</span> <span className="tag">{record.status}</span>
      </li>
      <li>
        <span className="label">Classification</span> {record.classification}
      </li>
      <li>
        <span className="label">Type</span> {record.kind}
      </li>
      <li>
        <span className="label">Registered</span> {record.registeredAt?.toLocaleString()}
      </li>
      <li>
        <span className="label">Registered by</span>
        {reporterLink ? (
          <a href={reporterLink} target="_blank" rel="noreferrer">
            <code>{record.reporter}</code>
          </a>
        ) : (
          <code>{record.reporter}</code>
        )}
      </li>
      <li>
        <span className="label">Disputes</span> {record.disputes}
      </li>
      <li>
        <span className="label">Commitment</span> <code>{record.commitment}</code>
      </li>
      {record.previous && (
        <li>
          <span className="label">Revises</span>
          <button type="button" className="link-button" onClick={() => onOpen(record.previous!)}>
            {short(record.previous)}
          </button>
        </li>
      )}
      {record.next && (
        <li>
          <span className="label">Replaced by</span>
          <button type="button" className="link-button" onClick={() => onOpen(record.next!)}>
            {short(record.next)}
          </button>
        </li>
      )}
    </ul>
  );
}

function pillFor(classification: string): string {
  return classification === "Confirmed Malicious" ? "Critical" : classification === "High Risk" ? "High" : "Medium";
}

function short(hash: string): string {
  return `${hash.slice(0, 10)}...${hash.slice(-6)}`;
}
