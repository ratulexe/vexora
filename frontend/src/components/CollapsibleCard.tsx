"use client";

import { ChevronDown, type LucideIcon } from "lucide-react";
import { useState, type ReactNode } from "react";

const PHONE = "(max-width: 720px)";

/**
 * A report card that can fold away. Secondary sections start folded on phones, where the report is a long
 * scroll, and open on larger screens. The section bar opens it when jumping here.
 */
export default function CollapsibleCard({
  id,
  icon: Icon,
  title,
  children,
}: {
  id: string;
  icon: LucideIcon;
  title: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(() => typeof window === "undefined" || !window.matchMedia(PHONE).matches);

  return (
    <details
      id={id}
      className="card collapsible report-section"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <h3>
          <Icon size={18} aria-hidden /> {title}
        </h3>
        <ChevronDown size={18} className="chevron" aria-hidden />
      </summary>
      <div className="collapsible-body">{children}</div>
    </details>
  );
}
