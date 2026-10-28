import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SiteAudit Pro — Evidence-based website audits",
  description:
    "Audit website quality, product readiness, security hygiene, UX resilience and required documents with evidence-backed reports.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
