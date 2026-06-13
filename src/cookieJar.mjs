import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { dirname } from "node:path";

export async function loadCookieJar(path) {
  try {
    const raw = await readFile(path, "utf8");
    return JSON.parse(raw);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export async function saveCookieJar(path, jar) {
  await mkdir(dirname(path), { recursive: true });
  const payload = {
    ...jar,
    version: 1,
    updatedAt: new Date().toISOString()
  };
  await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

export function mergeCookies(existing = [], incoming = []) {
  const map = new Map();
  for (const cookie of [...existing, ...incoming]) {
    const key = `${cookie.domain}\0${cookie.name}\0${cookie.path || "/"}`;
    map.set(key, cookie);
  }
  return [...map.values()];
}

export function cookiesForHost(cookies, host) {
  const normalized = host.toLowerCase().replace(/^\./, "");
  return cookies.filter((cookie) => {
    const domain = String(cookie.domain || "").toLowerCase().replace(/^\./, "");
    return normalized === domain || normalized.endsWith(`.${domain}`) || domain.endsWith(`.${normalized}`);
  });
}

export function buildCookieHeader(cookies, host) {
  return cookiesForHost(cookies, host)
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

const SESSION_COOKIE_PATTERN =
  /^(JSESSIONID|sid|SID|connect\.sid|session|_session|auth|oauth|PDSESSION|atlassian|bitbucket|crowd\.|seraph\.|luf_|DT|ln|idx|__Host-|__Secure-)/i;

export function hasMeaningfulSessionCookies(cookies, host) {
  return cookiesForHost(cookies, host).some(
    (cookie) => cookie.httpOnly || SESSION_COOKIE_PATTERN.test(cookie.name) || cookie.name.includes("SESSION")
  );
}

export function listCookieHostCandidates(jar, domains = []) {
  const candidates = [];
  const seen = new Set();
  const add = (host) => {
    const bare = String(host || "").replace(/^\./, "").toLowerCase();
    if (!bare || seen.has(bare)) return;
    seen.add(bare);
    candidates.push(bare);
  };
  for (const domain of domains) add(domain);
  if (jar?.cookies?.length) {
    for (const cookie of jar.cookies) {
      const cookieDomain = String(cookie.domain || "").replace(/^\./, "").toLowerCase();
      for (const domain of domains) {
        const bare = domain.replace(/^\./, "").toLowerCase();
        if (cookieDomain === bare || cookieDomain.endsWith(`.${bare}`) || bare.endsWith(`.${cookieDomain}`)) {
          add(cookieDomain);
        }
      }
    }
  }
  return candidates;
}

export function resolveBestCookieHost(jar, domains = [], { requireSession = false } = {}) {
  if (!jar?.cookies?.length) {
    return { host: domains[0] ?? "", cookie: "", hasCookies: false, hasSession: false };
  }
  for (const host of listCookieHostCandidates(jar, domains)) {
    const cookie = buildCookieHeader(jar.cookies, host);
    if (!cookie) continue;
    const hasSession = hasMeaningfulSessionCookies(jar.cookies, host);
    if (!requireSession || hasSession) {
      return { host, cookie, hasCookies: true, hasSession };
    }
  }
  return { host: domains[0] ?? "", cookie: "", hasCookies: false, hasSession: false };
}

export function jarSummary(jar, config) {
  if (!jar?.cookies?.length) {
    return {
      authenticated: false,
      mode: "browser-session",
      domain: config.domain,
      message: "No SSO cookie jar. Sign in through your SSO provider in Chrome, or enable browser auto-auth."
    };
  }
  const oktaCookies = cookiesForHost(jar.cookies, config.domain);
  const valid = jar.authenticated === true && oktaCookies.length > 0;
  return {
    authenticated: valid,
    mode: "browser-session",
    domain: config.domain,
    cookieCount: jar.cookies.length,
    oktaCookieCount: oktaCookies.length,
    validatedAt: jar.validatedAt ?? null,
    updatedAt: jar.updatedAt ?? null,
    domains: [...new Set(jar.cookies.map((cookie) => cookie.domain))].sort()
  };
}

export function isValidationFresh(jar, ttlMs, now = Date.now()) {
  if (!jar?.validatedAt) return false;
  const validatedAt = Date.parse(jar.validatedAt);
  if (Number.isNaN(validatedAt)) return false;
  return now - validatedAt < ttlMs;
}
