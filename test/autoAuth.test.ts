import { describe, expect, it } from "vitest";
import { isAutoAuthEnabled, resolveAutoAuthOptions } from "../src/autoAuth.mjs";

describe("browser-sso autoAuth", () => {
  it("defaults auto auth to enabled", () => {
    expect(isAutoAuthEnabled({})).toBe(true);
    expect(isAutoAuthEnabled({ BROWSER_SSO_AUTO_AUTH: "false" })).toBe(false);
  });

  it("disables browser open on probeOnly", () => {
    expect(resolveAutoAuthOptions({ probeOnly: true }).openBrowserOnMissing).toBe(false);
  });
});
