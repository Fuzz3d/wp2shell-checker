"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useCallback, useEffect, useRef, useState } from "react";
import { Search, Terminal, X, AlertCircle } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScanTimeline, type TimelineStep } from "@/components/ScanTimeline";
import { ScanReport } from "@/components/ScanReport";
import type { ScanResult } from "@/lib/scanner";

type Phase = "idle" | "scanning" | "done" | "error";

const SCAN_STEPS: { id: string; label: string }[] = [
  { id: "dns", label: "Resolviendo DNS..." },
  { id: "wp", label: "Detectando WordPress..." },
  { id: "version", label: "Enumerando versión..." },
  { id: "batch", label: "Comprobando endpoints vulnerables..." },
  { id: "exploit", label: "Verificando condiciones de explotación..." },
  { id: "report", label: "Generando informe..." },
];

const STEP_DELAYS = [400, 900, 1500, 2200, 3000, 3700];

export function ScannerModule() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [url, setUrl] = useState("");
  const [steps, setSteps] = useState<TimelineStep[]>(
    SCAN_STEPS.map((s) => ({ ...s, status: "pending" }))
  );
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      timersRef.current.forEach(clearTimeout);
    };
  }, []);

  const resetSteps = useCallback(() => {
    setSteps(SCAN_STEPS.map((s) => ({ ...s, status: "pending" })));
  }, []);

  const animateStepsProgressively = useCallback(() => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];

    SCAN_STEPS.forEach((_, i) => {
      const t1 = setTimeout(() => {
        setSteps((prev) =>
          prev.map((s, idx) =>
            idx === i
              ? { ...s, status: "active" }
              : idx < i
                ? { ...s, status: "done" }
                : s
          )
        );
      }, STEP_DELAYS[i]);
      timersRef.current.push(t1);
    });
  }, []);

  const completeAllSteps = useCallback(() => {
    timersRef.current.forEach(clearTimeout);
    setSteps(SCAN_STEPS.map((s) => ({ ...s, status: "done" })));
  }, []);

  const runScan = useCallback(async () => {
    if (!url.trim()) return;

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setError("");
    setResult(null);
    setPhase("scanning");
    resetSteps();
    animateStepsProgressively();

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
        signal: controller.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error || "Error al escanear.");
      }

      completeAllSteps();

      setTimeout(() => {
        if (!controller.signal.aborted) {
          setResult(data as ScanResult);
          setPhase("done");
        }
      }, 500);
    } catch (e) {
      if (controller.signal.aborted) return;
      completeAllSteps();
      setTimeout(() => {
        if (!controller.signal.aborted) {
          setError((e as Error).message || "Error al escanear.");
          setPhase("error");
        }
      }, 400);
    }
  }, [url, animateStepsProgressively, completeAllSteps, resetSteps]);

  const handleRunAgain = useCallback(() => {
    abortRef.current?.abort();
    setResult(null);
    setError("");
    resetSteps();
    setPhase("idle");
  }, [resetSteps]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter" && phase === "idle") {
        e.preventDefault();
        runScan();
      }
    },
    [phase, runScan]
  );

  const inputDisabled = phase === "scanning";

  return (
    <motion.div
      initial={{ opacity: 0, y: 24, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
      className="relative w-full max-w-[640px] rounded-3xl border border-white/8 glass shadow-soft overflow-hidden"
    >
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />

      <div className="flex items-center justify-between px-5 py-4 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-danger/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-warning/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-success/70" />
          </div>
          <span className="ml-2 text-xs font-mono text-muted-foreground">
            wp2shell-checker ~ /escanear
          </span>
        </div>
        <Terminal className="h-4 w-4 text-muted-foreground" />
      </div>

      <div className="px-5 py-5 sm:px-7 sm:py-6">
        <AnimatePresence mode="wait">
          {(phase !== "done" && phase !== "error") && (
            <motion.div
              key="input"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.3 }}
            >
              <div className="flex flex-col sm:flex-row gap-2.5">
                <div className="relative flex-1">
                  <Search className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="mi-sitio-wordpress.com"
                    disabled={inputDisabled}
                    autoComplete="off"
                    autoCapitalize="off"
                    spellCheck={false}
                    className="pl-10 font-mono"
                  />
                </div>
                <Button
                  variant="primary"
                  size="lg"
                  onClick={runScan}
                  disabled={inputDisabled || !url.trim()}
                  className="sm:w-auto w-full"
                >
                  {inputDisabled ? (
                    <>
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                      Escaneando
                    </>
                  ) : (
                    <>Escanear</>
                  )}
                </Button>
              </div>

              {phase === "scanning" && <ScanTimeline steps={steps} />}

              {phase === "idle" && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  className="mt-4 text-xs text-muted-foreground leading-relaxed"
                >
                  Introduce la URL de un sitio WordPress para comprobar si es vulnerable al
                  RCE de pre-autenticación wp2shell (afecta a WordPress 6.9.0–6.9.4 y
                  7.0.0–7.0.1).
                </motion.p>
              )}
            </motion.div>
          )}

          {phase === "done" && result && (
            <motion.div
              key="done"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.3 }}
            >
              <ScanReport result={result} onRunAgain={handleRunAgain} />
            </motion.div>
          )}

          {phase === "error" && (
            <motion.div
              key="error"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.3 }}
            >
              <div className="flex items-start gap-3 rounded-2xl border border-danger/25 bg-danger/5 p-5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-danger/15 border border-danger/25">
                  <AlertCircle className="h-4 w-4 text-danger" />
                </div>
                <div className="flex-1">
                  <h3 className="text-sm font-semibold text-white">
                    Error en el escaneo
                  </h3>
                  <p className="mt-1 text-sm text-white/65">{error}</p>
                </div>
                <button
                  onClick={handleRunAgain}
                  className="flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground hover:text-white hover:bg-white/5 transition-colors"
                  aria-label="Cerrar"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="mt-4 flex justify-end">
                <Button variant="secondary" size="md" onClick={handleRunAgain}>
                  Intentar de nuevo
                </Button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
