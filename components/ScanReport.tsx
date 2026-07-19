"use client";

import { motion } from "framer-motion";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  CircleAlert,
  Globe,
  Tag,
  Server,
  Eye,
  ListChecks,
  Wrench,
  Download,
  Copy,
  RotateCcw,
  Check,
} from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ScanResult } from "@/lib/scanner";
import { cn } from "@/lib/utils";

interface ScanReportProps {
  result: ScanResult;
  onRunAgain: () => void;
}

const severityConfig = {
  vulnerable: {
    label: "Vulnerable",
    variant: "danger" as const,
    icon: ShieldAlert,
    accent: "text-danger",
    glow: "shadow-glow-danger",
    bar: "from-danger/60 to-danger/0",
  },
  safe: {
    label: "Seguro",
    variant: "success" as const,
    icon: ShieldCheck,
    accent: "text-success",
    glow: "shadow-glow-success",
    bar: "from-success/60 to-success/0",
  },
  protected: {
    label: "Protegido",
    variant: "warning" as const,
    icon: Shield,
    accent: "text-warning",
    glow: "",
    bar: "from-warning/60 to-warning/0",
  },
  unknown: {
    label: "Desconocido",
    variant: "warning" as const,
    icon: CircleAlert,
    accent: "text-warning",
    glow: "",
    bar: "from-warning/60 to-warning/0",
  },
};

function InfoRow({
  icon: Icon,
  label,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3 py-3 border-b border-white/5 last:border-0">
      <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white/[0.04] border border-white/8">
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium">
          {label}
        </div>
        <div className="mt-0.5 text-sm text-white/90 break-words">{children}</div>
      </div>
    </div>
  );
}

function BatchStatusBadge({ result }: { result: ScanResult }) {
  const { batch, verdict } = result;

  if (batch.routeConfusion) {
    return (
      <span className="flex items-center gap-2">
        <span className="font-mono">HTTP 207</span>
        <span className="text-danger">
          {"· "}Route confusion detectada — vulnerable
        </span>
      </span>
    );
  }

  if (batch.status === 403) {
    return (
      <span className="flex items-center gap-2">
        <span className="font-mono">HTTP 403</span>
        <span className="text-warning">
          {"· "}Bloqueado por WAF o plugin de seguridad
        </span>
      </span>
    );
  }

  if (batch.status === 401) {
    return (
      <span className="flex items-center gap-2">
        <span className="font-mono">HTTP 401</span>
        <span className="text-warning">
          {"· "}Requiere autenticación
        </span>
      </span>
    );
  }

  if (batch.status === 207) {
    return (
      <span className="flex items-center gap-2">
        <span className="font-mono">HTTP 207</span>
        <span className="text-success">
          {"· "}Sin route confusion — parcheado
        </span>
      </span>
    );
  }

  if (batch.status === 404) {
    return (
      <span className="flex items-center gap-2">
        <span className="font-mono">HTTP 404</span>
        <span className="text-muted-foreground">· No disponible</span>
      </span>
    );
  }

  if (batch.status === null) {
    return <span className="text-muted-foreground">No alcanzable</span>;
  }

  return (
    <span className="flex items-center gap-2">
      <span className="font-mono">HTTP {batch.status}</span>
      <span className="text-muted-foreground">· Estado desconocido</span>
    </span>
  );
}

export function ScanReport({ result, onRunAgain }: ScanReportProps) {
  const [copied, setCopied] = useState(false);
  const config = severityConfig[result.verdict.level];
  const SeverityIcon = config.icon;

  const reportText = buildReportText(result);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(reportText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* ignored */
    }
  };

  const handleDownload = () => {
    const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `wp2shell-informe-${new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[:T]/g, "-")}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="mt-2"
    >
      {/* Severity banner */}
      <div
        className={cn(
          "relative overflow-hidden rounded-2xl border border-white/8 p-5",
          "bg-gradient-to-b from-white/[0.03] to-transparent",
          config.glow
        )}
      >
        <div
          className={cn(
            "absolute top-0 left-0 right-0 h-px bg-gradient-to-r",
            config.bar
          )}
        />
        <div className="flex items-start gap-4">
          <div
            className={cn(
              "flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border",
              result.verdict.level === "vulnerable" &&
                "bg-danger/10 border-danger/25",
              result.verdict.level === "safe" &&
                "bg-success/10 border-success/25",
              result.verdict.level === "unknown" &&
                "bg-warning/10 border-warning/25"
            )}
          >
            <SeverityIcon className={cn("h-5 w-5", config.accent)} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant={config.variant}>{config.label}</Badge>
              <span className="text-[11px] uppercase tracking-wider text-muted-foreground">
                Nivel de riesgo
              </span>
            </div>
            <h3 className="mt-2 text-[17px] font-semibold text-white leading-snug">
              {result.verdict.title}
            </h3>
            <p className="mt-1 text-sm text-white/65 leading-relaxed">
              {result.verdict.detail}
            </p>
          </div>
        </div>
      </div>

      {/* Target info */}
      <div className="mt-4 rounded-2xl border border-white/8 bg-white/[0.02] p-5">
        <div className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground font-medium">
          <Eye className="h-3.5 w-3.5" />
          Información del objetivo
        </div>
        <InfoRow icon={Globe} label="URL analizada">
          {result.target}
        </InfoRow>
        <InfoRow icon={Tag} label="Versión de WordPress">
          {result.version ? (
            <span className="font-mono">{result.version}</span>
          ) : (
            <span className="text-muted-foreground">No detectada</span>
          )}
        </InfoRow>
        <InfoRow icon={Server} label="Detección de WordPress">
          {result.markers.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {result.markers.map((m) => (
                <span
                  key={m}
                  className="rounded-md bg-white/[0.05] border border-white/10 px-2 py-0.5 font-mono text-xs text-white/80"
                >
                  {m}
                </span>
              ))}
              {result.wpLogin && (
                <span className="rounded-md bg-white/[0.05] border border-white/10 px-2 py-0.5 font-mono text-xs text-white/80">
                  wp-login
                </span>
              )}
            </div>
          ) : (
            <span className="text-muted-foreground">
              No se detectaron marcadores de WordPress
            </span>
          )}
        </InfoRow>
        <InfoRow icon={Shield} label="Endpoint batch">
          <BatchStatusBadge result={result} />
        </InfoRow>
      </div>

      {/* Evidence */}
      <div className="mt-4 rounded-2xl border border-white/8 bg-white/[0.02] p-5">
        <div className="mb-3 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground font-medium">
          <ListChecks className="h-3.5 w-3.5" />
          Evidencia encontrada
        </div>
        <ul className="space-y-2">
          {result.signals.map((sig, i) => (
            <motion.li
              key={i}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 + i * 0.05, duration: 0.35 }}
              className="flex items-start gap-2.5 text-sm text-white/70"
            >
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary/60" />
              <span className="leading-relaxed">{sig}</span>
            </motion.li>
          ))}
        </ul>
      </div>

      {/* Remediation */}
      <div className="mt-4 rounded-2xl border border-white/8 bg-white/[0.02] p-5">
        <div className="mb-3 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground font-medium">
          <Wrench className="h-3.5 w-3.5" />
          Remediación recomendada
        </div>
        <ol className="space-y-2.5">
          {result.remediation.map((step, i) => (
            <motion.li
              key={i}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 + i * 0.05, duration: 0.35 }}
              className="flex items-start gap-3 text-sm text-white/75"
            >
              <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-primary/10 border border-primary/20 text-[11px] font-mono text-primary">
                {i + 1}
              </span>
              <span className="leading-relaxed">{step}</span>
            </motion.li>
          ))}
        </ol>
      </div>

      {/* Actions */}
      <div className="mt-5 flex flex-wrap gap-2.5">
        <Button variant="secondary" size="md" onClick={handleDownload}>
          <Download className="h-4 w-4" />
          Descargar informe
        </Button>
        <Button variant="secondary" size="md" onClick={handleCopy}>
          {copied ? (
            <Check className="h-4 w-4 text-success" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
          {copied ? "Copiado" : "Copiar hallazgos"}
        </Button>
        <Button variant="ghost" size="md" onClick={onRunAgain} className="ml-auto">
          <RotateCcw className="h-4 w-4" />
          Escanear otra vez
        </Button>
      </div>
    </motion.div>
  );
}

function buildReportText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push("WP2SHELL CHECKER — INFORME DE VULNERABILIDAD");
  lines.push("=".repeat(48));
  lines.push(`Generado: ${new Date().toISOString()}`);
  lines.push("");
  lines.push("VEREDICTO");
  lines.push("-".repeat(48));
  lines.push(`Nivel:    ${result.verdict.level.toUpperCase()}`);
  lines.push(`Título:   ${result.verdict.title}`);
  lines.push(`Detalle:  ${result.verdict.detail}`);
  lines.push("");
  lines.push("OBJETIVO");
  lines.push("-".repeat(48));
  lines.push(`URL:                     ${result.target}`);
  lines.push(`Versión de WordPress:    ${result.version ?? "no detectada"}`);
  lines.push(
    `Marcadores:              ${result.markers.join(", ") || "ninguno"}`
  );
  lines.push(
    `wp-login.php:            ${result.wpLogin ? "presente" : "ausente"}`
  );
  lines.push(
    `Endpoint batch:          ${
      result.batch.status === null
        ? "inalcanzable"
        : `HTTP ${result.batch.status}`
    }${result.batch.routeConfusion ? " (route confusion detectada)" : ""}`
  );
  if (result.batch.markers.length > 0) {
    lines.push(
      `Markers:                 ${result.batch.markers.join(", ")}`
    );
  }
  lines.push("");
  lines.push("EVIDENCIA");
  lines.push("-".repeat(48));
  result.signals.forEach((s, i) =>
    lines.push(`${(i + 1).toString().padStart(2, "0")}. ${s}`)
  );
  lines.push("");
  lines.push("REMEDIACIÓN");
  lines.push("-".repeat(48));
  result.remediation.forEach((s, i) =>
    lines.push(`${(i + 1).toString().padStart(2, "0")}. ${s}`)
  );
  lines.push("");
  lines.push(
    "Referencia: https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core"
  );
  lines.push("");
  return lines.join("\n");
}
