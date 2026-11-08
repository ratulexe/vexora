"use client";

import { BadgeCheck, Blocks, CircleAlert, CircleCheck, Download, ExternalLink, LoaderCircle } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { registryConfigured } from "@/lib/registry";
import type { Report } from "@/lib/report";
import { REGISTRATION_TIMEOUT_MS, postJson } from "@/lib/request";

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
      setRegistration(await postJson<Registration>(`${apiUrl}/reports`, { report }, REGISTRATION_TIMEOUT_MS));
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
    <section className="card" style={{ marginTop: 16 }}>
      <h3>
        <Blocks size={18} aria-hidden /> Warn others: add to the threat registry
      </h3>
      {!registration ? (
        <>
          <p className="note" style={{ marginBottom: 14 }}>
            Records a tamper-evident fingerprint of this report on the Ethereum Sepolia blockchain, so other people
            checking this site see it was reported. Only a hash goes on-chain. The shared report holds the risk
            level, finding titles and domains, never your message text, full links or personal details.
          </p>
          <button type="button" className="button button-primary" onClick={register} disabled={saving}>
            {saving ? (
              <>
                <LoaderCircle size={16} className="spin" aria-hidden /> Recording on the blockchain (up to a minute)...
              </>
            ) : (
              <>
                <Blocks size={16} aria-hidden /> Add to threat registry
              </>
            )}
          </button>
          {error && (
            <p role="alert" className="alert-error">
              <CircleAlert size={18} aria-hidden /> {error}
            </p>
          )}
        </>
      ) : (
        <>
          <p style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, fontWeight: 600 }}>
            <CircleCheck size={18} aria-hidden style={{ color: "var(--risk-low)" }} /> Recorded in block{" "}
            {registration.block_number}
          </p>
          <ul className="result-row" style={{ marginBottom: 14 }}>
            <li>
              <span className="label">Commitment</span>
              <code>{registration.commitment}</code>
            </li>
            <li>
              <span className="label">Transaction</span>
              {registration.explorer_url ? (
                <a href={registration.explorer_url} target="_blank" rel="noreferrer">
                  <code>{registration.transaction_hash}</code> <ExternalLink size={12} aria-hidden />
                </a>
              ) : (
                <code>{registration.transaction_hash}</code>
              )}
            </li>
          </ul>
          <div className="field-row">
            <button type="button" className="button" onClick={download}>
              <Download size={16} aria-hidden /> Download report file
            </button>
            <Link href="/verify" className="button">
              <BadgeCheck size={16} aria-hidden /> Verify it independently
            </Link>
          </div>
          <p className="note" style={{ marginTop: 12 }}>
            Keep the report file: it is the only full copy. A registry record proves the report has not been
            changed, not that it is correct.
          </p>
        </>
      )}
    </section>
  );
}
