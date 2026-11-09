"use client";

import { BadgeCheck, Code, Info, Menu, ScanSearch, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import ThemeToggle from "./ThemeToggle";

const REPOSITORY = "https://github.com/ratulexe/vexora";

export default function SiteHeader() {
  const path = usePathname();
  // The menu remembers the page it was opened on, so it closes by itself after navigating.
  const [openOn, setOpenOn] = useState<string | null>(null);
  const open = openOn === path;
  const header = useRef<HTMLElement>(null);
  const menuButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpenOn(null);
        menuButton.current?.focus();
      }
    }
    function onPointer(event: PointerEvent) {
      if (!header.current?.contains(event.target as Node)) setOpenOn(null);
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
    };
  }, [open]);

  const close = () => setOpenOn(null);

  return (
    <header className="site-header" ref={header}>
      <div className="container">
        <Link href="/" className="brand" aria-label="Vexora home" onClick={close}>
          Vexora
        </Link>
        <div className="header-actions">
          <nav id="site-nav" className="nav" aria-label="Main" data-open={open}>
            <Link href="/#check" aria-current={path === "/" ? "page" : undefined} onClick={close}>
              <ScanSearch size={16} aria-hidden />
              <span>Check</span>
            </Link>
            <Link href="/verify" aria-current={path === "/verify" ? "page" : undefined} onClick={close}>
              <BadgeCheck size={16} aria-hidden />
              <span>Verify</span>
            </Link>
            <Link href="/#how-it-works" onClick={close}>
              <Info size={16} aria-hidden />
              <span>How it works</span>
            </Link>
            <a href={REPOSITORY} target="_blank" rel="noreferrer" onClick={close}>
              <Code size={16} aria-hidden />
              <span>Code</span>
            </a>
          </nav>
          <ThemeToggle />
          <button
            ref={menuButton}
            type="button"
            className="icon-button menu-button"
            aria-expanded={open}
            aria-controls="site-nav"
            aria-label={open ? "Close menu" : "Open menu"}
            onClick={() => setOpenOn(open ? null : path)}
          >
            {open ? <X size={18} aria-hidden /> : <Menu size={18} aria-hidden />}
          </button>
        </div>
      </div>
    </header>
  );
}
