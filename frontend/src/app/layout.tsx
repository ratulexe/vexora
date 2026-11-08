import type { Metadata } from "next";
import { Roboto_Mono } from "next/font/google";
import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";
import "./globals.css";

const robotoMono = Roboto_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Vexora",
  description: "Check suspicious links and messages, see the evidence, and verify threat reports on-chain.",
};

// Applies a saved theme choice before the page paints, so it never flashes the wrong theme.
const themeScript = `try{var t=localStorage.getItem("vexora-theme");if(t==="light"||t==="dark")document.documentElement.dataset.theme=t}catch(e){}`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={robotoMono.variable} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        {/* Redaction 20 is not in next/font's list yet, so it loads from Google Fonts directly.
            This root layout wraps every page, so the font loads site-wide (the rule targets the Pages Router). */}
        {/* eslint-disable-next-line @next/next/no-page-custom-font */}
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Redaction+20:ital,wght@0,400;0,700;1,400&display=swap"
        />
      </head>
      <body>
        <SiteHeader />
        <main>{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}
