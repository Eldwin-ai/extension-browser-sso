import { buildRequestUrl, normalizeBaseUrl, parseResponseBody } from "@eldwin-ai/extension-read-only-toolkit/enterprise-api-read";
import { assertNonHtmlApiResponse } from "@eldwin-ai/extension-read-only-toolkit/devops-diagnostics";
import { resolveAutoAuthOptions, shouldRetryAuthAfterFailure } from "./autoAuth.mjs";

export function assertReadOnlyGet(input = {}) {
  const method = String(input.method || "GET").toUpperCase();
  if (method !== "GET") {
    throw new Error(`Read-only browser SSO: HTTP method ${method} is not allowed.`);
  }
  const restPath = String(input.restPath || input.path || "");
  if (/^https?:\/\//i.test(restPath)) {
    throw new Error("Use restPath relative to baseUrl, not an absolute URL.");
  }
  if (restPath.includes("..")) {
    throw new Error("restPath cannot contain parent directory traversal.");
  }
}

/**
 * Generic cookie-backed GET read. Caller supplies resolveCookieHeader({ baseUrl, domains }).
 */
export async function browserReadGet(input = {}, options = {}) {
  assertReadOnlyGet(input);
  const authOptions = resolveAutoAuthOptions(options);
  const fetchImpl = authOptions.fetchImpl ?? globalThis.fetch;
  const baseUrl = normalizeBaseUrl(input.baseUrl);
  if (!baseUrl) throw new Error("baseUrl is required for browserReadGet.");
  const restPath = String(input.restPath || input.path || "").trim();
  if (!restPath) throw new Error("restPath is required.");
  const resolveCookieHeader = options.resolveCookieHeader;
  if (typeof resolveCookieHeader !== "function") {
    throw new Error("resolveCookieHeader option is required.");
  }

  async function once() {
    const cookie = await resolveCookieHeader({ ...input, baseUrl, ...authOptions });
    if (!cookie) throw new Error("No browser cookies available for this request.");
    const url = buildRequestUrl(baseUrl, restPath, input.query);
    const response = await fetchImpl(url, {
      method: "GET",
      headers: {
        accept: input.accept ?? "application/json,text/html",
        cookie,
        "user-agent": input.userAgent ?? "Mozilla/5.0 eldwin-browser-sso/0.1",
        ...(input.headers ?? {})
      },
      redirect: input.followRedirects ? "follow" : "manual"
    });
    const text = await response.text();
    if (!authOptions.allowHtml) assertNonHtmlApiResponse(input.serviceName ?? "Browser SSO", text);
    const data = parseResponseBody(text);
    if (!response.ok && !authOptions.allowHtml) {
      const error = new Error(`Browser SSO read failed (${response.status}) at ${restPath}`);
      error.status = response.status;
      throw error;
    }
    return {
      readOnly: true,
      method: "GET",
      baseUrl,
      restPath,
      url: url.toString(),
      status: response.status,
      contentType: response.headers.get("content-type"),
      data
    };
  }

  try {
    return await once();
  } catch (error) {
    if (!shouldRetryAuthAfterFailure(error, authOptions)) throw error;
    if (typeof options.onRetryAuth === "function") await options.onRetryAuth();
    return once();
  }
}
