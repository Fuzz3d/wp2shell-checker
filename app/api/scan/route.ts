import { NextRequest, NextResponse } from "next/server";
import { lookup } from "node:dns";
import { runScan, type SafeFetchResponse, type SafeFetchOptions } from "@/lib/scanner";

export const runtime = "nodejs";
export const maxDuration = 30;

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\.0\.0\.0$/,
  /^0$/,
];

const PRIVATE_HOSTNAMES = new Set(["localhost", "ip6-localhost", "ip6-loopback"]);

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT = 8000;
const MAX_BODY_SIZE = 1024 * 1024;

function isPrivateIP(ip: string): boolean {
  if (ip === "::1" || ip === "::ffff:127.0.0.1") return true;
  if (ip.startsWith("fe80:")) return true;
  if (ip.startsWith("fc") || ip.startsWith("fd")) return true;
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

function resolveHost(hostname: string): Promise<{ address: string; family: number }[]> {
  return new Promise((resolve, reject) => {
    lookup(hostname, { family: 0, all: true }, (err, addresses) => {
      if (err) return reject(new Error("No se pudo resolver el dominio."));
      resolve(addresses);
    });
  });
}

async function safeFetch(
  rawUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResponse> {
  const method = options.method || "GET";
  const redirectCount = options.redirectCount || 0;

  if (redirectCount > MAX_REDIRECTS) {
    throw new Error("Demasiadas redirecciones al escanear el sitio.");
  }

  let target: URL;
  try {
    target = new URL(rawUrl);
  } catch {
    throw new Error("URL inválida generada durante el escaneo.");
  }

  if (!/^https?:$/.test(target.protocol)) {
    throw new Error("Solo se permiten URLs HTTP o HTTPS.");
  }

  const hostname = target.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (PRIVATE_HOSTNAMES.has(hostname) || hostname.endsWith(".local")) {
    throw new Error("No se permiten destinos locales o privados.");
  }

  let addresses: { address: string; family: number }[];
  try {
    addresses = await resolveHost(hostname);
  } catch {
    throw new Error("No se pudo resolver el dominio del sitio.");
  }

  for (const addr of addresses) {
    if (isPrivateIP(addr.address)) {
      throw new Error(
        "El dominio resuelve a una IP privada. Solo se pueden escanear sitios públicos."
      );
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

  try {
    const headers: Record<string, string> = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      Accept:
        "text/html, application/json, application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    };

    const fetchOpts: RequestInit & { headers: Record<string, string> } = {
      method,
      redirect: "manual",
      signal: controller.signal,
      headers,
    };

    if (method === "POST") {
      headers["Content-Type"] = "application/json";
      fetchOpts.body = '{"requests":[]}';
    }

    const response = await fetch(target.href, fetchOpts as RequestInit);

    if (
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.has("location")
    ) {
      const location = response.headers.get("location") as string;
      const nextUrl = new URL(location, target).href;
      return safeFetch(nextUrl, { method: "GET", redirectCount: redirectCount + 1 });
    }

    if (
      !response.ok &&
      response.status !== 404 &&
      response.status !== 403 &&
      response.status !== 401 &&
      response.status !== 400 &&
      response.status !== 405 &&
      response.status !== 422
    ) {
      throw new Error(`El servidor respondió con estado ${response.status}.`);
    }

    const contentType = response.headers.get("content-type") || "";
    const isText =
      /text\/html|application\/json|application\/rss\+xml|application\/xml|text\/xml|text\/plain/i.test(
        contentType
      );

    if (!isText) {
      return { body: "", status: response.status, headers: response.headers };
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return { body: "", status: response.status, headers: response.headers };
    }

    let body = "";
    let totalSize = 0;
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalSize += value.byteLength;
      if (totalSize > MAX_BODY_SIZE) {
        reader.cancel();
        break;
      }
      body += decoder.decode(value, { stream: true });
    }

    return { body, status: response.status, headers: response.headers };
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      throw new Error("El sitio tardó demasiado en responder (timeout de 8 segundos).");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export async function POST(req: NextRequest) {
  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Cuerpo JSON no válido." },
      { status: 400 }
    );
  }

  const raw = String(body?.url || "").trim();
  if (!raw) {
    return NextResponse.json(
      { error: "Introduce una URL para escanear." },
      { status: 400 }
    );
  }

  if (/^[a-z][a-z0-9+\-.]*:\/\//i.test(raw) && !/^https?:\/\//i.test(raw)) {
    return NextResponse.json(
      { error: "Solo se permiten URLs con protocolo HTTP o HTTPS." },
      { status: 400 }
    );
  }

  let target: URL;
  try {
    const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    target = new URL(withProto);
  } catch {
    return NextResponse.json(
      {
        error:
          "La URL no es válida. Introduce un dominio sin ruta (ej: misitio.com).",
      },
      { status: 400 }
    );
  }

  if (!/^https?:$/.test(target.protocol)) {
    return NextResponse.json(
      { error: "Solo se permiten URLs con protocolo HTTP o HTTPS." },
      { status: 400 }
    );
  }

  const hostname = target.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (PRIVATE_HOSTNAMES.has(hostname) || hostname.endsWith(".local")) {
    return NextResponse.json(
      { error: "No se permiten escanear destinos locales o privados." },
      { status: 400 }
    );
  }

  let addresses: { address: string; family: number }[];
  try {
    addresses = await resolveHost(hostname);
  } catch {
    return NextResponse.json(
      {
        error:
          "No se pudo resolver el dominio. Verifica que esté bien escrito.",
      },
      { status: 400 }
    );
  }

  for (const addr of addresses) {
    if (isPrivateIP(addr.address)) {
      return NextResponse.json(
        {
          error:
            "El dominio resuelve a una IP privada. Solo se pueden escanear sitios públicos.",
        },
        { status: 400 }
      );
    }
  }

  const baseUrl = target.origin;

  try {
    const result = await runScan(baseUrl, safeFetch);
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      {
        error:
          (e as Error).message || "No se pudo completar el escaneo.",
      },
      { status: 502 }
    );
  }
}
