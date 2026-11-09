"use client";

import {
  Braces,
  CalendarClock,
  Check,
  ChevronDown,
  Globe,
  LayoutList,
  Link2,
  ListTree,
  Lock,
  QrCode,
  Radar,
  Route,
  ScanSearch,
  ScrollText,
  X,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import CollapsibleCard from "./CollapsibleCard";

type Value = string | number | boolean | null | undefined | Value[] | { [key: string]: Value };
type Details = Record<string, Value>;

/** Short tab names and icons for the groups the backend produces; anything else gets a generic tab. */
const GROUPS: Record<string, { label: string; title?: string; icon: LucideIcon }> = {
  "Domain analysis": { label: "Domain", icon: Globe },
  "Redirect analysis": { label: "Redirects", icon: Route },
  "TLS certificate": { label: "TLS", icon: Lock },
  "Threat intelligence": { label: "Threat intel", icon: Radar },
  "Domain age": { label: "Domain age", icon: CalendarClock },
  "Certificate Transparency": { label: "CT logs", icon: ScrollText },
  extracted: { label: "Extracted", title: "Extracted from the message", icon: ListTree },
  links: { label: "Links", title: "Links in the message", icon: Link2 },
  qr: { label: "QR code", title: "QR code contents", icon: QrCode },
};

const ACRONYMS: Record<string, string> = {
  url: "URL",
  urls: "URLs",
  ip: "IP",
  tls: "TLS",
  upi: "UPI",
  qr: "QR",
  ct: "CT",
  id: "ID",
};

interface Group {
  key: string;
  label: string;
  title: string;
  icon: LucideIcon;
  value: Value;
}

function isRecord(value: Value): value is { [key: string]: Value } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Splits the details into tabs: each object-shaped check is a tab, and loose values share an Overview tab. */
function groupsOf(details: Details): Group[] {
  const overview: Details = {};
  const groups: Group[] = [];
  for (const [key, value] of Object.entries(details)) {
    const known = GROUPS[key];
    if (known || isRecord(value)) {
      groups.push({
        key,
        label: known?.label ?? prettyKey(key),
        title: known?.title ?? prettyKey(key),
        icon: known?.icon ?? Braces,
        value,
      });
    } else {
      overview[key] = value;
    }
  }
  if (Object.keys(overview).length === 0) return groups;
  // Link reports: the loose values describe the link itself, so they lead the Domain tab.
  const domain = groups.find((group) => group.key === "Domain analysis");
  if (domain && isRecord(domain.value)) {
    domain.value = { ...overview, ...domain.value };
  } else {
    groups.unshift({ key: "overview", label: "Overview", title: "Overview", icon: LayoutList, value: overview });
  }
  return groups;
}

export default function TechnicalDetails({ details, id }: { details: Details; id: string }) {
  const groups = groupsOf(details);
  const [selected, setSelected] = useState(groups[0]?.key);
  const group = groups.find((item) => item.key === selected) ?? groups[0];
  if (!group) return null;
  const GroupIcon = group.icon;

  return (
    <CollapsibleCard id={id} icon={ScanSearch} title="Technical details">
      <p className="note" style={{ marginBottom: 12 }}>
        The raw results of each check, for anyone who wants to look closer.
      </p>

      <div className="detail-tabs" role="tablist" aria-label="Technical detail groups">
        {groups.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              type="button"
              role="tab"
              id={`detail-tab-${item.key}`}
              aria-selected={item.key === group.key}
              aria-controls="detail-panel"
              onClick={() => setSelected(item.key)}
            >
              <Icon size={14} aria-hidden /> {item.label}
            </button>
          );
        })}
      </div>

      <div id="detail-panel" role="tabpanel" aria-labelledby={`detail-tab-${group.key}`} className="detail-panel">
        <h4>
          <GroupIcon size={16} aria-hidden /> {group.title}
        </h4>
        <ValueView value={group.value} name={group.key} />
      </div>

      <details className="disclosure" style={{ marginTop: 12 }}>
        <summary>
          <Braces size={16} aria-hidden /> Raw JSON
          <ChevronDown size={16} className="chevron" aria-hidden />
        </summary>
        <div className="disclosure-body">
          <pre>{JSON.stringify(details, null, 2)}</pre>
        </div>
      </details>
    </CollapsibleCard>
  );
}

function ValueView({ value, name }: { value: Value; name: string }) {
  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return <span className="kv-empty">None</span>;
    return (
      <dl className="kv-list">
        {entries.map(([key, item]) => (
          <div key={key} className="kv-row">
            <dt>{prettyKey(key)}</dt>
            <dd>
              <ValueView value={item} name={key} />
            </dd>
          </div>
        ))}
      </dl>
    );
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="kv-empty">None</span>;
    if (value.every((item) => !isRecord(item) && !Array.isArray(item))) {
      return (
        <ul className="kv-chips">
          {value.map((item, index) => (
            <li key={index}>{formatScalar(item as Value, name)}</li>
          ))}
        </ul>
      );
    }
    const itemLabel = name === "redirect_chain" ? "Hop" : "Item";
    return (
      <ol className="kv-items">
        {value.map((item, index) => (
          <li key={index}>
            <span className="kv-item-label">
              {itemLabel} {index + 1}
            </span>
            <ValueView value={item} name={name} />
          </li>
        ))}
      </ol>
    );
  }
  if (typeof value === "boolean") {
    return (
      <span className="kv-bool" data-value={value}>
        {value ? <Check size={13} aria-hidden /> : <X size={13} aria-hidden />} {value ? "Yes" : "No"}
      </span>
    );
  }
  if (value === null || value === undefined || value === "") return <span className="kv-empty">None</span>;
  return <span className="kv-value">{formatScalar(value, name)}</span>;
}

function formatScalar(value: Value, key: string): string {
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toLocaleString();
  }
  if (typeof value === "number" && key.endsWith("_days")) return `${value} days`;
  if (typeof value === "number" && key === "key_bits") return `${value} bits`;
  if (typeof value === "string" && key === "rules_matched") return value.replaceAll("_", " ");
  return String(value);
}

function prettyKey(key: string): string {
  const words = key.split(/[_\s]+/).filter(Boolean);
  return words
    .map((word, index) => {
      const lower = word.toLowerCase();
      if (ACRONYMS[lower]) return ACRONYMS[lower];
      if (word !== lower) return word;
      return index === 0 ? lower[0].toUpperCase() + lower.slice(1) : lower;
    })
    .join(" ");
}
