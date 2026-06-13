/** Extract structured session/user info from authenticated HTML pages (GET only). */

export function extractGithubProfile(html) {
  const text = String(html || "");
  const login =
    text.match(/meta name="user-login" content="([^"]+)"/i)?.[1] ||
    text.match(/data-login="([^"]+)"/i)?.[1] ||
    text.match(/"login":"([^"]+)"/)?.[1];
  const name = text.match(/<title>([^<]+)<\/title>/i)?.[1]?.trim();
  const authenticated = Boolean(login) && !/sign_in_form|login-field/i.test(text);
  return { authenticated, login, name, source: "github-html-profile" };
}

export function extractAtlassianSession(html, { url } = {}) {
  const text = String(html || "");
  const loginRedirect = /\/login\?|signin|authorize/i.test(String(url || "")) || /login-form|id="login-form"/i.test(text);
  const username =
    text.match(/data-username="([^"]+)"/i)?.[1] ||
    text.match(/"userName":"([^"]+)"/)?.[1] ||
    text.match(/data-account-username="([^"]+)"/i)?.[1];
  return {
    authenticated: Boolean(username) && !loginRedirect,
    username,
    loginRedirect,
    source: "atlassian-html"
  };
}

export function extractEmbeddedJson(html, marker) {
  const text = String(html || "");
  const pattern = new RegExp(`${marker}[^=]*=\\s*(\\{[\\s\\S]*?\\});`, "m");
  const match = text.match(pattern);
  if (!match?.[1]) return null;
  try {
    return JSON.parse(match[1]);
  } catch {
    return null;
  }
}

export function extractGenericPage(html) {
  const text = String(html || "");
  const title = text.match(/<title>([^<]+)<\/title>/i)?.[1]?.trim() || "";
  const loginPage = /login|signin|authorize|okta/i.test(title) || /<form[^>]+login/i.test(text.slice(0, 4000));
  return {
    authenticated: !loginPage && title.length > 0,
    title,
    loginPage,
    source: "generic-html"
  };
}

export function extractHtmlSession(kind, html, context = {}) {
  switch (kind) {
    case "github-profile":
      return extractGithubProfile(html);
    case "atlassian-session":
      return extractAtlassianSession(html, context);
    case "generic":
      return extractGenericPage(html);
    default:
      return extractGenericPage(html);
  }
}
