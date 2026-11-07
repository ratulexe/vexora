"use client";

import Link from "next/link";
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
import styles from "../page.module.css";

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
    <main className={styles.main}>
      <p>
        <Link href="/">← Back to Vexora</Link>
      </p>
      <h1>Verify a threat report</h1>
      <p className={styles.intro}>
        Check that a Vexora threat report has not been changed since it was registered. Your browser
        computes the report&apos;s fingerprint and reads the {REGISTRY.network} directly, so this check
        does not depend on the Vexora server.
      </p>

      {!registryConfigured && (
        <p role="alert" className={styles.error}>
          The registry is not configured for this site yet.
        </p>
      )}

      <h3>Check a report file</h3>
      <form className={styles.form} onSubmit={verifyPackage}>
        <input type="file" accept="application/json,.json" aria-label="Report package file" onChange={loadFile} />
        <textarea
          aria-label="Report package JSON"
          placeholder="Or paste the report package JSON"
          rows={6}
          value={packageText}
          onChange={(event) => setPackageText(event.target.value)}
          required
        />
        <button type="submit" disabled={checking || !registryConfigured}>
          {checking ? "Checking..." : "Verify report"}
        </button>
      </form>

      <h3>Or look up a commitment</h3>
      <form className={styles.form} onSubmit={verifyHash}>
        <input
          aria-label="Commitment hash"
          placeholder="0x..."
          value={hashInput}
          onChange={(event) => setHashInput(event.target.value)}
          required
        />
        <button type="submit" disabled={checking || !registryConfigured}>
          {checking ? "Checking..." : "Look up"}
        </button>
      </form>

      {error && (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      )}

      {record && (
        <section className={styles.report}>
          {record.registered ? (
            <>
              <h2>{computed ? "Verified: this report is unchanged" : "Registered report found"}</h2>
              <p>
                {computed
                  ? "The fingerprint of this file matches a report registered on-chain."
                  : "This commitment is registered on-chain."}{" "}
                This proves the report has not changed since it was registered, and who registered it and
                when. It does not prove that the report is correct.
              </p>
              <RecordDetails record={record} onOpen={(hash) => void check(hash, false)} />
            </>
          ) : (
            <>
              <h2>Not found on-chain</h2>
              <p>
                {computed
                  ? "No registered report has this fingerprint. The file was changed after registration, or it was never registered."
                  : "No report is registered with this commitment."}
              </p>
              {computed && (
                <p className={styles.note}>
                  Computed fingerprint: <code>{computed}</code>
                </p>
              )}
            </>
          )}
        </section>
      )}

      {registryConfigured && (
        <section className={styles.report}>
          <h3>Recently registered reports</h3>
          {recentError && <p>{recentError}</p>}
          {!recent && !recentError && <p>Loading from the blockchain...</p>}
          {recent?.length === 0 && <p>No reports have been registered yet.</p>}
          {recent && recent.length > 0 && (
            <ul>
              {recent.map((entry) => (
                <li key={entry.commitment}>
                  <button type="button" className={styles.linkButton} onClick={() => void check(entry.commitment, false)}>
                    {entry.classification} {entry.kind.toLowerCase()} report
                  </button>{" "}
                  · {entry.registeredAt.toLocaleString()} · <code>{short(entry.commitment)}</code>
                  {explorerLink("tx", entry.transactionHash) && (
                    <>
                      {" "}
                      ·{" "}
                      <a href={explorerLink("tx", entry.transactionHash)!} target="_blank" rel="noreferrer">
                        transaction
                      </a>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
          <p className={styles.note}>
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
        </section>
      )}
    </main>
  );
}

function RecordDetails({ record, onOpen }: { record: OnChainRecord; onOpen: (hash: string) => void }) {
  const reporterLink = explorerLink("address", record.reporter);
  return (
    <ul>
      <li>Status: {record.status}</li>
      <li>Classification: {record.classification}</li>
      <li>Type: {record.kind}</li>
      <li>Registered: {record.registeredAt?.toLocaleString()}</li>
      <li>
        Registered by:{" "}
        {reporterLink ? (
          <a href={reporterLink} target="_blank" rel="noreferrer">
            <code>{record.reporter}</code>
          </a>
        ) : (
          <code>{record.reporter}</code>
        )}
      </li>
      <li>Disputes: {record.disputes}</li>
      <li>
        Commitment: <code>{record.commitment}</code>
      </li>
      {record.previous && (
        <li>
          Revises an earlier report:{" "}
          <button type="button" className={styles.linkButton} onClick={() => onOpen(record.previous!)}>
            {short(record.previous)}
          </button>
        </li>
      )}
      {record.next && (
        <li>
          Replaced by a newer version:{" "}
          <button type="button" className={styles.linkButton} onClick={() => onOpen(record.next!)}>
            {short(record.next)}
          </button>
        </li>
      )}
    </ul>
  );
}

function short(hash: string): string {
  return `${hash.slice(0, 10)}...${hash.slice(-6)}`;
}
