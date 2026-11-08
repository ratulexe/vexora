import { ShieldCheck } from "lucide-react";
import Link from "next/link";

export default function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="container">
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <ShieldCheck size={16} aria-hidden /> Vexora. Results describe the checks that ran; they never prove a link
          or message is safe.
        </span>
        <span>
          <Link href="/verify">Verify a report</Link> · Report fraud: <a href="https://cybercrime.gov.in">cybercrime.gov.in</a> or call 1930 (India)
        </span>
      </div>
    </footer>
  );
}
