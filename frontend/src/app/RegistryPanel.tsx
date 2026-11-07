"use client";

import Link from "next/link";
import { useState } from "react";
import { registryConfigured } from "@/lib/registry";
import type { Report } from "@/lib/report";
import styles from "./page.module.css";

const REGISTRABLE = ["Suspicious", "High Risk", "Confirmed Malicious"];

interface Registration {
  commitment: string;
  transaction_hash: string;
  block_number: number;
  contract_address: string;
  chain_id: number;
  explorer_url: string | null;
  package: Record<string, unknown>;
}

export default function RegistryPanel({ report, apiUrl }: { report: Report; apiUrl: string }) {
  const [registration, setRegistration] = useState<Registration | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  if (!registryConfigured || !REGISTRABLE.includes(report.classification)) return null;

  async function register() {
    setSaving(true);
    setError(null);
    try {
      const response = await fetch(`${apiUrl}/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? `Request failed (${response.status})`);
      setRegistration(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  function download() {
    if (!registration) return;
    const file = {
      package: registration.package,
      commitment: registration.commitment,
      transaction_hash: registration.transaction_hash,
      contract_address: registration.contract_address,
      chain_id: registration.chain_id,
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `vexora-report-${registration.commitment.slice(2, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className={styles.aiSummary}>
      <h3>Share with the threat registry</h3>
      {!registration ? (
        <>
          <p>
            Record a tamper-evident fingerprint of this report on the blockchain, so others can see this
            threat was reported. Only a hash goes on-chain. The shared report holds the risk level, finding
            titles and domains, never your message text, full links or personal details.
          </p>
          <button type="button" className={styles.primaryButton} onClick={register} disabled={saving}>
            {saving ? "Registering on-chain (up to a minute)..." : "Add to threat registry"}
          </button>
          {error && (
            <p role="alert" className={styles.error}>
              {error}
            </p>
          )}
        </>
      ) : (
        <>
          <p>Registered in block {registration.block_number}.</p>
          <ul>
            <li>
              Commitment: <code>{registration.commitment}</code>
            </li>
            <li>
              Transaction:{" "}
              {registration.explorer_url ? (
                <a href={registration.explorer_url} target="_blank" rel="noreferrer">
                  <code>{registration.transaction_hash}</code>
                </a>
              ) : (
                <code>{registration.transaction_hash}</code>
              )}
            </li>
          </ul>
          <div className={styles.tabs}>
            <button type="button" onClick={download}>
              Download report file
            </button>
            <Link href="/verify" className={styles.linkButton}>
              Verify it independently
            </Link>
          </div>
          <p className={styles.note}>
            Keep the report file: it is the only full copy. A registry record proves the report has not been
            changed, not that it is correct.
          </p>
        </>
      )}
    </div>
  );
}
