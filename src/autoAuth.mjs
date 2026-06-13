/**
 * Shared Okta auto-auth defaults.
 * When session is missing or stale, open Chrome so the user can sign in.
 */

export function isAutoAuthEnabled(env = process.env) {
  return env.BROWSER_SSO_AUTO_AUTH?.trim().toLowerCase() !== "false";
}

/** Normalize auto-auth flags for any Okta read/session path. */
export function resolveAutoAuthOptions(options = {}) {
  const env = options.env ?? process.env;
  const probeOnly = options.probeOnly === true;
  const autoAuth = probeOnly ? false : (options.autoAuth ?? isAutoAuthEnabled(env));
  const openBrowserOnMissing =
    probeOnly ? false : (options.openBrowserOnMissing ?? autoAuth);
  return {
    ...options,
    env,
    autoAuth,
    openBrowserOnMissing,
    probeOnly
  };
}

export function isAuthStatusResponse(status) {
  return status === 401 || status === 403;
}

export function shouldRetryAuthAfterFailure(error, options = {}) {
  const auth = resolveAutoAuthOptions(options);
  if (auth.probeOnly || auth.openBrowserOnMissing === false || auth._retriedAuth) {
    return false;
  }
  if (error && typeof error === "object" && "status" in error) {
    return isAuthStatusResponse(Number(error.status));
  }
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /\b(401|403)\b/.test(message) || /session not ready|no cookies|not authenticated/i.test(message);
}
