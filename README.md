# @eldwin-ai/extension-browser-sso

Generic browser cookie SSO primitives for read-only HTTP GET (Eldwin #22).

## Exports

- `auto-auth` — auto-auth flags and retry policy
- `chrome-cookies` — Chrome cookie import
- `cookie-jar` — cookie jar persistence
- `html-session-extract` — HTML login detection
- `browser-login` — open browser for auth
- `browser-http-read` — generic `browserReadGet`

Products supply domain catalogs and `resolveCookieHeader` wiring.
