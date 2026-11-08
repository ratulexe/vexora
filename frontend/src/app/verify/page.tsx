"use client";

import {
  BadgeCheck,
  Blocks,
  CircleAlert,
  ChevronDown,
  ExternalLink,
  FileCheck2,
  FileJson,
  FileUp,
  Hash,
  History,
  LoaderCircle,
  Search,
  ShieldCheck,
  ShieldX,
  X,
} from "lucide-react";
import { FormEvent, useEffect, useRef, useState } from "react";
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
  const [method, setMethod] = useState<"file" | "hash">("file");
  const [packageText, setPackageText] = useState("");
  const [fileInfo, setFileInfo] = useState<{ name: string; size: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
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

  async function loadFile(file: File | undefined) {
    if (!file) return;
    setError(null);
    setPackageText(await file.text());
    setFileInfo({ name: file.name, size: file.size });
  }

  function clearFile() {
    setPackageText("");
    setFileInfo(null);
    if (fileInput.current) fileInput.current.value = "";
  }

  function switchMethod(next: "file" | "hash") {
    setMethod(next);
    setError(null);
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
          <div className="tabs" role="tablist" aria-label="How to verify">
            <button type="button" role="tab" className="tab" aria-selected={method === "file"} onClick={() => switchMethod("file")}>
              <FileJson size={16} aria-hidden /> Report file
            </button>
            <button type="button" role="tab" className="tab" aria-selected={method === "hash"} onClick={() => switchMethod("hash")}>
              <Hash size={16} aria-hidden /> Commitment
            </button>
          </div>

          {method === "file" ? (
            <form className="form-stack" onSubmit={verifyPackage}>
              {fileInfo ? (
                <div className="file-chip">
                  <FileCheck2 size={22} aria-hidden />
                  <div>
                    <strong>{fileInfo.name}</strong>
                    <span className="note">{formatSize(fileInfo.size)} · ready to verify</span>
                  </div>
                  <button type="button" className="icon-button" onClick={clearFile} aria-label="Remove file">
                    <X size={16} aria-hidden />
                  </button>
                </div>
              ) : (
                <div
                  className="drop-zone"
                  data-dragging={dragging}
                  onDragOver={(event) => {
                    event.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(event) => {
                    event.preventDefault();
                    setDragging(false);
                    void loadFile(event.dataTransfer.files[0]);
                  }}
                >
                  <FileUp size={34} aria-hidden className="drop-icon" />
                  <p>
                    <strong>Drop your report file here</strong>
                  </p>
                  <p className="note">The .json file you downloaded after registering a report</p>
                  <button type="button" className="button" onClick={() => fileInput.current?.click()}>
                    <FileUp size={16} aria-hidden /> Choose file
                  </button>
                  <input
                    ref={fileInput}
                    type="file"
                    accept="application/json,.json"
                    aria-label="Report package file"
                    hidden
                    onChange={(event) => void loadFile(event.target.files?.[0])}
                  />
                </div>
              )}

              {!fileInfo && (
                <details className="disclosure">
                  <summary>
                    <FileJson size={16} aria-hidden /> Or paste the JSON instead
                    <ChevronDown size={16} className="chevron" aria-hidden />
                  </summary>
                  <div className="disclosure-body">
                    <textarea
                      className="textarea"
                      aria-label="Report package JSON"
                      placeholder='{"package": {...}, "commitment": "0x..."}'
                      value={packageText}
                      onChange={(event) => setPackageText(event.target.value)}
                    />
                  </div>
                </details>
              )}

              <button
                type="submit"
                className="button button-primary"
                disabled={checking || !registryConfigured || !packageText.trim()}
              >
                {checking ? <LoaderCircle size={16} className="spin" aria-hidden /> : <BadgeCheck size={16} aria-hidden />}
                {checking ? "Checking the blockchain..." : "Verify report"}
              </button>
            </form>
          ) : (
            <form className="form-stack" onSubmit={verifyHash}>
              <p className="note">Paste the commitment shown when the report was registered (0x followed by 64 characters).</p>
              <div className="field-row">
                <input
                  className="input"
                  aria-label="Commitment hash"
                  placeholder="0x..."
                  value={hashInput}
                  onChange={(event) => setHashInput(event.target.value)}
                  required
                  spellCheck={false}
                />
                <button type="submit" className="button button-primary" disabled={checking || !registryConfigured}>
                  {checking ? <LoaderCircle size={16} className="spin" aria-hidden /> : <Search size={16} aria-hidden />}
                  Look up
                </button>
              </div>
            </form>
          )}
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

function formatSize(bytes: number): string {
  return bytes < 1024 ? `${bytes} bytes` : `${(bytes / 1024).toFixed(1)} KB`;
}
