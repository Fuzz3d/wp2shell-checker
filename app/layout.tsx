import type { Metadata, Viewport } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "WP2Shell Checker — Escáner de vulnerabilidad WordPress",
  description:
    "Determina si un sitio WordPress es vulnerable a wp2shell, un RCE de pre-autenticación en WordPress Core. Comprobador premium para pentesters, bug bounty hunters e investigadores de seguridad.",
  applicationName: "WP2Shell Checker",
  authors: [{ name: "Adam Kues, Searchlight Cyber" }],
  keywords: [
    "wp2shell",
    "wordpress",
    "rce",
    "vulnerabilidad",
    "comprobador",
    "seguridad",
    "pentest",
  ],
  openGraph: {
    title: "WP2Shell Checker — Escáner de vulnerabilidad WordPress",
    description:
      "Determina si un sitio WordPress es vulnerable a wp2shell, un RCE de pre-autenticación en WordPress Core.",
    type: "website",
  },
  twitter: {
    card: "summary",
    title: "WP2Shell Checker",
    description: "Escáner de vulnerabilidad wp2shell para WordPress.",
  },
};

export const viewport: Viewport = {
  themeColor: "#09090B",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="bg-background text-white antialiased">{children}</body>
    </html>
  );
}
