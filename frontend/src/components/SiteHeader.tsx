"use client";

import { BadgeCheck, Code, Info, ScanSearch, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import ThemeToggle from "./ThemeToggle";

const REPOSITORY = "https://github.com/ratulexe/vexora";

export default function SiteHeader() {
  const path = usePathname();
  return (
    <header className="site-header">
      <div className="container">
        <Link href="/" className="brand" aria-label="Vexora home">
          <ShieldCheck size={24} aria-hidden />
          Vexora
        </Link>
        <nav className="nav" aria-label="Main">
          <Link href="/#check" aria-current={path === "/" ? "page" : undefined}>
            <ScanSearch size={16} aria-hidden />
            <span className="nav-label">Check</span>
          </Link>
          <Link href="/verify" aria-current={path === "/verify" ? "page" : undefined}>
            <BadgeCheck size={16} aria-hidden />
            <span className="nav-label">Verify</span>
          </Link>
          <Link href="/#how-it-works">
            <Info size={16} aria-hidden />
            <span className="nav-label">How it works</span>
          </Link>
          <a href={REPOSITORY} target="_blank" rel="noreferrer">
            <Code size={16} aria-hidden />
            <span className="nav-label">Code</span>
          </a>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
