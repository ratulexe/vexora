// Reads the on-chain threat registry directly from the browser, so anyone can verify
// a report without trusting the Vexora server. The commitment must be computed exactly
// as backend/app/registry/package.py does: keccak256 of canonical JSON (sorted keys,
// no spaces, UTF-8).

import { Contract, JsonRpcProvider, keccak256, toUtf8Bytes } from "ethers";
import abi from "./registry-abi.json";

export const REGISTRY = {
  address: process.env.NEXT_PUBLIC_REGISTRY_ADDRESS ?? "",
  rpcUrl: process.env.NEXT_PUBLIC_REGISTRY_RPC_URL ?? "",
  explorer: (process.env.NEXT_PUBLIC_REGISTRY_EXPLORER_URL ?? "").replace(/\/$/, ""),
  fromBlock: Number(process.env.NEXT_PUBLIC_REGISTRY_FROM_BLOCK ?? 0),
  network: process.env.NEXT_PUBLIC_REGISTRY_NETWORK ?? "Sepolia testnet",
};

export const registryConfigured = Boolean(REGISTRY.address && REGISTRY.rpcUrl);

const STATUSES = ["Not registered", "Active", "Superseded", "Disputed", "Validated", "Rejected"];
const CLASSIFICATIONS = ["Low Risk", "Suspicious", "High Risk", "Confirmed Malicious", "Inconclusive"];
const KINDS = ["Link", "Message"];
const ZERO = "0x" + "0".repeat(64);

export type ReportPackage = Record<string, unknown>;

export interface OnChainRecord {
  commitment: string;
  registered: boolean;
  reporter: string;
  registeredAt: Date | null;
  status: string;
  classification: string;
  kind: string;
  indicatorHash: string | null;
  previous: string | null;
  next: string | null;
  disputes: number;
}

export interface RegistryEntry {
  commitment: string;
  reporter: string;
  classification: string;
  kind: string;
  registeredAt: Date;
  transactionHash: string;
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.keys(value as object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

export function commitmentOf(reportPackage: ReportPackage): string {
  return keccak256(toUtf8Bytes(canonicalJson(reportPackage)));
}

/** Accepts either a downloaded Vexora file ({ package, commitment, ... }) or a bare package. */
export function packageFromFile(text: string): ReportPackage {
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object") throw new Error("The file is not a report package.");
  return (parsed.package ?? parsed) as ReportPackage;
}

function contract(): Contract {
  if (!registryConfigured) throw new Error("The registry is not configured for this site.");
  return new Contract(REGISTRY.address, abi, new JsonRpcProvider(REGISTRY.rpcUrl));
}

export async function lookup(commitment: string): Promise<OnChainRecord> {
  const [registered, record] = await contract().verifyReport(commitment);
  const hashOrNull = (value: string) => (value === ZERO ? null : value);
  return {
    commitment,
    registered,
    reporter: record.reporter,
    registeredAt: registered ? new Date(Number(record.registeredAt) * 1000) : null,
    status: STATUSES[Number(record.status)] ?? "Unknown",
    classification: CLASSIFICATIONS[Number(record.classification)] ?? "Unknown",
    kind: KINDS[Number(record.kind)] ?? "Unknown",
    indicatorHash: hashOrNull(record.indicatorHash),
    previous: hashOrNull(record.previous),
    next: hashOrNull(record.next),
    disputes: Number(record.disputes),
  };
}

export async function recentReports(limit = 10): Promise<RegistryEntry[]> {
  const registry = contract();
  const events = await registry.queryFilter(registry.filters.ReportRegistered(), REGISTRY.fromBlock);
  return events
    .slice(-limit)
    .reverse()
    .map((event) => {
      const args = (event as unknown as { args: Record<string, bigint | string> }).args;
      return {
        commitment: String(args.commitment),
        reporter: String(args.reporter),
        classification: CLASSIFICATIONS[Number(args.classification)] ?? "Unknown",
        kind: KINDS[Number(args.kind)] ?? "Unknown",
        registeredAt: new Date(Number(args.registeredAt) * 1000),
        transactionHash: event.transactionHash,
      };
    });
}

export function explorerLink(kind: "tx" | "address", value: string): string | null {
  return REGISTRY.explorer ? `${REGISTRY.explorer}/${kind}/${value}` : null;
}
