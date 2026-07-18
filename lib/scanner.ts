export type Version = [number, number, number];

export type VerdictLevel = "vulnerable" | "safe" | "unknown";

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
}

export interface SafeFetchResponse {
  body: string;
  status: number;
  headers: Headers;
}

export interface SafeFetchOptions {
  method?: "GET" | "POST";
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
      level: "safe",
      title: "No vulnerable",
      detail:
        "La API batch está bloqueada (probablemente por un WAF o plugin de seguridad), por lo que no puede ser explotada. Mantén WordPress actualizado de todos modos.",
    };
  }

  if (markersFound && batchStatus === 401) {
    return {
      level: "safe",
      title: "No vulnerable",
      detail:
        "El endpoint batch requiere autenticación. No puede ser explotado sin credenciales, pero actualiza WordPress de todos modos.",
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

  try {
    const result = await fetchFn(`${baseUrl}/wp-json/batch/v1`, { method: "POST" });
    status = result.status;
  } catch {
    try {
      const result = await fetchFn(`${baseUrl}/wp-json/batch/v1`);
      status = result.status;
    } catch {
      return { accessible: false, status: null };
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

  const verdict = computeVerdict(detectedVersion, markersFound.length > 0, batch);
  const remediation = buildRemediation(verdict);

  return {
    verdict,
    signals,
    target: baseUrl,
    version: detectedVersion ? detectedVersion.join(".") : null,
    markers: markersFound,
    batch,
    wpLogin,
    remediation,
  };
}
