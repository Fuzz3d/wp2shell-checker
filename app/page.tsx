import { AnimatedBackground } from "@/components/AnimatedBackground";
import { ScannerModule } from "@/components/ScannerModule";

export default function Home() {
  return (
    <main className="relative min-h-screen flex flex-col items-center">
      <AnimatedBackground />

      <header className="w-full max-w-6xl px-6 py-6 flex items-center justify-between">
        <div className="leading-tight">
          <div className="text-sm font-semibold text-white">WP2Shell</div>
          <div className="text-[11px] text-muted-foreground">
            diseñado por <span className="text-white/80">Fuzz3d</span>
          </div>
        </div>

        <a
          href="https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-muted-foreground hover:text-white transition-colors hidden sm:inline-block"
        >
          Advisory original ↗
        </a>
      </header>

      <section className="flex-1 w-full flex flex-col items-center justify-center px-6 pb-24 -mt-8">
        <div className="w-full max-w-[640px] flex flex-col items-center">
          <div className="mb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/8 bg-white/[0.03] px-3 py-1 text-[11px] uppercase tracking-wider text-muted-foreground mb-6">
              <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse-soft" />
              RCE de pre-autenticación · WordPress Core
            </div>

            <h1 className="text-[34px] sm:text-[44px] font-semibold tracking-tight text-white leading-[1.05]">
              Comprueba si tu
              <br />
              <span className="bg-gradient-to-r from-white via-white to-white/40 bg-clip-text text-transparent">
                WordPress es vulnerable a wp2shell
              </span>
            </h1>

            <p className="mt-5 text-[15px] text-muted-foreground max-w-md mx-auto leading-relaxed">
              Un escáner de vulnerabilidades premium para pentesters, bug bounty hunters
              e investigadores de seguridad. Sin instalación. Sin agentes. Solo resultados.
            </p>
          </div>

          <ScannerModule />

          <div className="mt-8 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-[11px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <span className="h-1 w-1 rounded-full bg-success" />
              Sin almacenamiento
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1 w-1 rounded-full bg-primary" />
              Tiempo real
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1 w-1 rounded-full bg-warning" />
              Seguro por diseño
            </span>
          </div>
        </div>
      </section>

      <footer className="w-full max-w-6xl px-6 py-6 border-t border-white/5">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-muted-foreground">
          <div>
            Descubierto por{" "}
            <a
              href="https://x.com/hash_kitten"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white/70 hover:text-white transition-colors"
            >
              Adam Kues
            </a>{" "}
            ·{" "}
            <a
              href="https://slcyber.io"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white/70 hover:text-white transition-colors"
            >
              Searchlight Cyber
            </a>
          </div>
          <div className="font-mono">
            <a
              href="https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors"
            >
              CVE-2026-63030
            </a>
            {" · "}WP 6.9.0–6.9.4, 7.0.0–7.0.1
          </div>
        </div>
      </footer>
    </main>
  );
}
