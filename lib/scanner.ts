// wp2shell checker — marker probe approach
// Based on the route-confusion behavior described in the wp2shell advisory.
// The marker probe sends a benign batch request that exposes the vulnerable
// alignment bug. On vulnerable builds, three specific error codes appear in
// the response; on patched builds, they don't.

export type Version = [number, number, number];

export type VerdictLevel = "vulnerable" | "safe" | "protected" | "unknown";

export interface Verdict {
  level: VerdictLevel;
  title: string;
  detail: string;
}

export interface BatchResult {
  status: number | null;
  markers: string[];
  routeConfusion: boolean;
}

export interface ScanResult {
  verdict: Verdict;
  signals: string[];
  target: string;
  version: string | null;
  markers: string[];
  batch: BatchResult;
  wpLogin: boolean;
  remediation: string[];
}

export interface SafeFetchResponse {
  body: string;
  status: number;
  headers: Headers;
}

export interface SafeFetchOptions {
  method?: "GET" | "POST";
  body?: string;
  redirectCount?: number;
}

type SafeFetch = (url: string, options?: SafeFetchOptions) => Promise<SafeFetchResponse>;

// ─── Version utilities ──────────────────────────────────────────────────────

function parseVersion(input: string): Version | null {
  const cleaned = String(input).replace(/-.*$/, "");
  const match = cleaned.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return [parseInt(match[1], 10), parseInt(match[2], 10), parseInt(match[3] || "0", 10)];
}

function cmpVersion(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

const versionLt = (a: Version, b: Version) => cmpVersion(a, b) < 0;
const versionLte = (a: Version, b: Version) => cmpVersion(a, b) <= 0;
const versionGte = (a: Version, b: Version) => cmpVersion(a, b) >= 0;

function isAffectedVersion(v: Version): boolean {
  return (
    (versionGte(v, [6, 9, 0]) && versionLte(v, [6, 9, 4])) ||
    (versionGte(v, [7, 0, 0]) && versionLte(v, [7, 0, 1]))
  );
}

// ─── Marker probe ───────────────────────────────────────────────────────────

// The three error codes that only appear together on vulnerable builds.
// Based on the WordPress core fix: the malformed "///" path creates
// parse_path_failed; the spacer request gets dispatched under the
// block-renderer handler (block_cannot_read); the block-renderer request
// gets dispatched under /batch/v1 (rest_batch_not_allowed).
const MARKER_CODES = [
  "parse_path_failed",
  "block_cannot_read",
  "rest_batch_not_allowed",
] as const;

function buildMarkerProbePayload(): object {
  return {
    requests: [
      { method: "POST", path: "///" },
      { method: "POST", path: "/wp/v2/posts" },
      { method: "POST", path: "/wp/v2/block-renderer/core/archives" },
      { method: "POST", path: "/batch/v1", body: { requests: [] } },
    ],
  };
}

function findMarkerCodes(data: unknown): string[] {
  const found: string[] = [];
  function walk(value: unknown) {
    if (Array.isArray(value)) {
      value.forEach(walk);
    } else if (value && typeof value === "object") {
      const obj = value as Record<string, unknown>;
      const code = obj.code;
      if (
        typeof code === "string" &&
        MARKER_CODES.includes(code as (typeof MARKER_CODES)[number]) &&
        !found.includes(code)
      ) {
        found.push(code);
      }
      Object.values(obj).forEach(walk);
    }
  }
  walk(data);
  return found;
}

async function markerProbe(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<BatchResult> {
  const url = `${baseUrl}/?rest_route=/batch/v1`;
  const body = JSON.stringify(buildMarkerProbePayload());

  try {
    const { status, body: responseBody } = await fetchFn(url, {
      method: "POST",
      body,
    });

    if (status !== 207) {
      return { status, markers: [], routeConfusion: false };
    }

    let data: unknown;
    try {
      data = JSON.parse(responseBody);
    } catch {
      return { status, markers: [], routeConfusion: false };
    }

    const markers = findMarkerCodes(data);
    const routeConfusion = MARKER_CODES.every((c) => markers.includes(c));
    return { status, markers, routeConfusion };
  } catch {
    return { status: null, markers: [], routeConfusion: false };
  }
}

// ─── WordPress detection ────────────────────────────────────────────────────

async function detectAllFromHomepage(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version | null; source: string; signals: string[] }> {
  const signals: string[] = [];
  let version: Version | null = null;
  let source = "";

  try {
    const { body, headers } = await fetchFn(`${baseUrl}/`);

    const metaMatch = body.match(
      /<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.-]+)["']/i
    );
    if (metaMatch) {
      const v = parseVersion(metaMatch[1]);
      if (v) {
        version = v;
        source = "meta generator";
      }
    }

    const linkHeader = headers.get?.("link") ?? headers.get?.("Link") ?? "";
    if (linkHeader && /\/wp-json\//.test(linkHeader)) {
      signals.push("Header Link apunta a la API REST de WordPress.");
    }
  } catch {
    /* ignored */
  }

  return { version, source, signals };
}

async function detectFromFeed(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version | null; source: string }> {
  const feedUrls = [`${baseUrl}/?feed=rss2`, `${baseUrl}/feed/`];

  const results = await Promise.allSettled(
    feedUrls.map(async (url) => {
      const { body } = await fetchFn(url);
      const genMatch = body.match(
        /<generator[^>]*>https?:\/\/\S+\?v=(\d+\.\d+(?:\.\d+)?)<\/generator>/i
      );
      if (genMatch) {
        const v = parseVersion(genMatch[1]);
        if (v) return { version: v, source: "feed RSS" };
      }
      const generatorMatch = body.match(
        /<generator>WordPress\s+([\d.-]+)<\/generator>/i
      );
      if (generatorMatch) {
        const v = parseVersion(generatorMatch[1]);
        if (v) return { version: v, source: "feed RSS" };
      }
      return null;
    })
  );

  for (const result of results) {
    if (result.status === "fulfilled" && result.value) {
      return result.value;
    }
  }
  return { version: null, source: "" };
}

async function detectFromReadme(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version | null; source: string }> {
  try {
    const { body, status } = await fetchFn(`${baseUrl}/readme.html`);
    if (status === 404) return { version: null, source: "" };

    const h1Match = body.match(
      /<h1[^>]*id=["']logo["'][^>]*>[^<]*WordPress\s+([\d.]+)[^<]*<\/h1>/i
    );
    if (h1Match) {
      const v = parseVersion(h1Match[1]);
      if (v) return { version: v, source: "readme.html" };
    }

    const strongMatch = body.match(/<strong>\s*WordPress\s+([\d.]+)/i);
    if (strongMatch) {
      const v = parseVersion(strongMatch[1]);
      if (v) return { version: v, source: "readme.html" };
    }
  } catch {
    /* ignored */
  }
  return { version: null, source: "" };
}

async function detectFromWpJson(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version | null; source: string }> {
  try {
    const { body } = await fetchFn(`${baseUrl}/wp-json/`);
    const data = JSON.parse(body);
    if (data?.endpoints?.[0]?.version) {
      const v = parseVersion(data.endpoints[0].version);
      if (v) return { version: v, source: "API REST" };
    }
  } catch {
    /* ignored */
  }
  return { version: null, source: "" };
}

async function detectMarkers(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<string[]> {
  const paths = ["/wp-content/", "/wp-includes/", "/wp-json/", "/wp-admin/"];
  const results = await Promise.allSettled(
    paths.map(async (path) => {
      const { status } = await fetchFn(`${baseUrl}${path}`);
      return { path, status };
    })
  );

  const found: string[] = [];
  for (const result of results) {
    if (result.status === "fulfilled" && result.value.status !== 404) {
      found.push(result.value.path.replace(/\//g, ""));
    }
  }
  return found;
}

async function detectWpLogin(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<boolean> {
  try {
    const { status } = await fetchFn(`${baseUrl}/wp-login.php`);
    return status === 200;
  } catch {
    return false;
  }
}

// ─── Remediation ────────────────────────────────────────────────────────────

function buildRemediation(level: VerdictLevel): string[] {
  if (level === "safe") {
    return [
      "Continúa manteniendo WordPress actualizado con las últimas versiones de seguridad.",
      "Monitoriza el blog de seguridad de WordPress para nuevas vulnerabilidades.",
    ];
  }

  if (level === "protected") {
    return [
      "Actualiza WordPress a 7.0.2 (o 6.9.5 si estás en la rama 6.9) — el WAF protege la explotación pero la vulnerabilidad sigue presente en el código.",
      "Mantén la regla WAF o plugin de seguridad que bloquea /wp-json/batch/v1 y ?rest_route=/batch/v1.",
      "Verifica periódicamente que el WAF siga activo.",
    ];
  }

  if (level === "unknown") {
    return [
      "Verifica manualmente la versión de WordPress desde el panel de administración.",
      "Si la versión es 6.9.0–6.9.4 o 7.0.0–7.0.1, actualiza inmediatamente.",
    ];
  }

  // vulnerable
  return [
    "Actualiza WordPress a 7.0.2 (o 6.9.5 si estás en la rama 6.9) inmediatamente.",
    "Bloquea /wp-json/batch/v1 y ?rest_route=/batch/v1 con un WAF hasta actualizar.",
    "Instala el plugin »Disable WP REST API« como mitigación temporal.",
    "Rota cualquier secreto que pueda haber sido expuesto y audita los logs.",
  ];
}

// ─── Main scan ──────────────────────────────────────────────────────────────

export async function runScan(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<ScanResult> {
  // Fase 1: detección paralela (WordPress markers + version hints)
  const [homepage, feed, readme, wpJson, wpLogin, markers] = await Promise.allSettled([
    detectAllFromHomepage(baseUrl, fetchFn),
    detectFromFeed(baseUrl, fetchFn),
    detectFromReadme(baseUrl, fetchFn),
    detectFromWpJson(baseUrl, fetchFn),
    detectWpLogin(baseUrl, fetchFn),
    detectMarkers(baseUrl, fetchFn),
  ]);

  const signals: string[] = [];

  // Recopilar versión (informativa, no determina el veredicto)
  let detectedVersion: Version | null = null;
  let versionSource = "";

  if (homepage.status === "fulfilled" && homepage.value.version) {
    detectedVersion = homepage.value.version;
    versionSource = homepage.value.source;
    signals.push(...homepage.value.signals);
  }
  if (!detectedVersion) {
    for (const r of [feed, readme, wpJson]) {
      if (r.status === "fulfilled" && r.value.version) {
        detectedVersion = r.value.version;
        versionSource = r.value.source;
        break;
      }
    }
  }

  if (detectedVersion) {
    const v = detectedVersion.join(".");
    const affected = isAffectedVersion(detectedVersion);
    signals.push(
      `Versión ${v} detectada (vía ${versionSource}) — ${affected ? "en rango afectado" : "fuera de rango afectado"}.`
    );
  }

  // Markers de WordPress
  const markersFound = markers.status === "fulfilled" ? markers.value : [];
  const wpLoginFound = wpLogin.status === "fulfilled" ? wpLogin.value : false;

  if (markersFound.length > 0) {
    signals.push(`WordPress detectado (${markersFound.join(", ")}).`);
  }
  if (wpLoginFound) {
    signals.push("/wp-login.php accesible.");
  }

  // Fase 2: marker probe (detección primaria)
  const batch = await markerProbe(baseUrl, fetchFn);

  if (batch.markers.length > 0) {
    signals.push(`Marker probe: ${batch.markers.join(", ")}.`);
  }

  // Fase 3: veredicto
  let verdict: Verdict;

  if (batch.routeConfusion) {
    verdict = {
      level: "vulnerable",
      title: "Vulnerable",
      detail:
        "Se detectó el patrón de route-confusion del batch endpoint (parse_path_failed + block_cannot_read + rest_batch_not_allowed). El sitio es vulnerable a wp2shell. Actualiza inmediatamente.",
    };
  } else if (batch.status === 403) {
    verdict = {
      level: "protected",
      title: "Protegido por WAF",
      detail:
        "El endpoint batch está bloqueado por un WAF o plugin de seguridad. No es explotable en este momento, pero la vulnerabilidad podría seguir presente. Actualiza de todos modos.",
    };
  } else if (batch.status === 401) {
    verdict = {
      level: "protected",
      title: "Protegido por autenticación",
      detail:
        "El endpoint batch requiere autenticación. No es explotable sin credenciales, pero actualiza WordPress de todos modos.",
    };
  } else if (batch.status === 207) {
    verdict = {
      level: "safe",
      title: "No vulnerable",
      detail:
        "El endpoint batch responde pero no se detectó el patrón de route-confusion. El sitio está parcheado o no es vulnerable.",
    };
  } else if (batch.status === 404 || batch.status === null) {
    if (markersFound.length > 0) {
      verdict = {
        level: "safe",
        title: "No vulnerable",
        detail:
          "WordPress detectado pero el endpoint batch no está disponible. El sitio no es vulnerable a wp2shell.",
      };
    } else {
      verdict = {
        level: "unknown",
        title: "No parece ser WordPress",
        detail:
          "No se detectaron marcadores de WordPress. El sitio podría no ser WordPress o no ser accesible.",
      };
    }
  } else {
    // Non-207 (400, 500, etc.) — following the PoC approach: "patched or REST API disabled"
    if (markersFound.length > 0) {
      verdict = {
        level: "safe",
        title: "No vulnerable",
        detail:
          "El endpoint batch respondió pero no con HTTP 207 (route confusion no detectada). El sitio está parcheado o la API REST está deshabilitada.",
      };
    } else {
      verdict = {
        level: "unknown",
        title: "No se pudo determinar",
        detail: `El endpoint batch respondió con HTTP ${batch.status}. No se pudo determinar el estado de vulnerabilidad.`,
      };
    }
  }

  const remediation = buildRemediation(verdict.level);

  return {
    verdict,
    signals,
    target: baseUrl,
    version: detectedVersion ? detectedVersion.join(".") : null,
    markers: markersFound,
    batch,
    wpLogin: wpLoginFound,
    remediation,
  };
}
