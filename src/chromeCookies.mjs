import { execFile, execFileSync } from "node:child_process";
import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

function getChromeEncryptionKey() {
  const password = execFileSync(
    "security",
    ["find-generic-password", "-w", "-s", "Chrome Safe Storage", "-a", "Chrome"],
    { encoding: "utf8" }
  ).trim();
  return pbkdf2Sync(password, "saltysalt", 1003, 16, "sha1");
}

function normalizeDecryptedValue(plain) {
  if (!plain?.length) return "";
  const asUtf8 = plain.toString("utf8");
  if (/^[\x20-\x7E]+$/.test(asUtf8)) return asUtf8;
  if (plain.length > 32) {
    const trimmed = plain.slice(32).toString("utf8");
    if (trimmed) return trimmed;
  }
  return asUtf8;
}

function decryptChromeCookie(encryptedValue, key) {
  if (!encryptedValue || encryptedValue.length === 0) return "";
  const prefix = encryptedValue.slice(0, 3).toString("utf8");
  if (prefix === "v10") {
    const iv = Buffer.alloc(16, " ");
    const ciphertext = encryptedValue.slice(3);
    const decipher = createDecipheriv("aes-128-cbc", key, iv);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return normalizeDecryptedValue(plain);
  }
  if (prefix === "v11") {
    const iv = encryptedValue.slice(3, 15);
    const payload = encryptedValue.slice(15);
    const tag = payload.slice(-16);
    const ciphertext = payload.slice(0, -16);
    const decipher = createDecipheriv("aes-128-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return normalizeDecryptedValue(plain);
  }
  return normalizeDecryptedValue(encryptedValue);
}

function chromeExpiryToUnix(expiresUtc) {
  if (!expiresUtc) return undefined;
  const value = Number(expiresUtc);
  if (!Number.isFinite(value) || value <= 0) return undefined;
  return Math.floor(value / 1_000_000 - 11_644_473_600);
}

async function querySqlite(dbPath, sql) {
  try {
    const { stdout } = await execFileAsync(
      "sqlite3",
      ["-separator", "\t", "-noheader", dbPath, sql],
      { maxBuffer: 8 * 1024 * 1024 }
    );
    return stdout.trim();
  } catch {
    const script = `import sqlite3,sys; con=sqlite3.connect(sys.argv[1]); cur=con.cursor(); cur.execute(sys.argv[2]); print('\\n'.join('\\t'.join(str(c) for c in row) for row in cur.fetchall()))`;
    const { stdout } = await execFileAsync("python3", ["-c", script, dbPath, sql], {
      maxBuffer: 8 * 1024 * 1024
    });
    return stdout.trim();
  }
}

export async function readChromeCookies(cookiesPath, hostPatterns = []) {
  if (!existsSync(cookiesPath)) {
    return [];
  }
  if (process.platform !== "darwin") {
    throw new Error("Chrome cookie import is supported on macOS only for now.");
  }

  const tempDir = mkdtempSync(join(tmpdir(), "eldwin-chrome-"));
  const tempDb = join(tempDir, "Cookies");
  copyFileSync(cookiesPath, tempDb);

  try {
    const clauses = hostPatterns
      .filter(Boolean)
      .map((pattern) => `host_key LIKE '${pattern.replaceAll("'", "''")}'`);
    const where = clauses.length ? `WHERE ${clauses.join(" OR ")}` : "";
    const rows = await querySqlite(
      tempDb,
      `SELECT host_key, name, path, is_secure, is_httponly, expires_utc, hex(encrypted_value) FROM cookies ${where}`
    );
    if (!rows) return [];

    const key = getChromeEncryptionKey();
    const cookies = [];
    for (const line of rows.split("\n")) {
      if (!line) continue;
      const [hostKey, name, path, isSecure, isHttpOnly, expiresUtc, encryptedHex] = line.split("\t");
      if (!encryptedHex) continue;
      const encryptedValue = Buffer.from(encryptedHex, "hex");
      const value = decryptChromeCookie(encryptedValue, key);
      if (!value) continue;
      cookies.push({
        domain: hostKey,
        name,
        value,
        path: path || "/",
        secure: isSecure === "1",
        httpOnly: isHttpOnly === "1",
        expires: chromeExpiryToUnix(expiresUtc)
      });
    }
    return cookies;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

export function resolveChromeCookiesPath(config) {
  if (existsSync(config.chromeCookiesPath)) {
    return config.chromeCookiesPath;
  }
  const chromeRoot = join(homedir(), "Library", "Application Support", "Google", "Chrome");
  if (!existsSync(chromeRoot)) return config.chromeCookiesPath;

  let bestPath = config.chromeCookiesPath;
  let bestCount = 0;
  for (const entry of readdirSync(chromeRoot)) {
    if (!entry.startsWith("Profile")) continue;
    const candidate = join(chromeRoot, entry, "Cookies");
    if (!existsSync(candidate)) continue;
    try {
      const domain = config.domain ?? config.ssoDomain;
      const query = domain
        ? (() => {
            const patterns = hostPatternsForDomains([domain]);
            const conditions = patterns.map(
              (pattern) => `host_key LIKE '${pattern.replace(/'/g, "''")}'`
            );
            return `SELECT count(*) FROM cookies WHERE ${conditions.join(" OR ")}`;
          })()
        : "SELECT count(*) FROM cookies";
      const count = Number(
        execFileSync("sqlite3", ["-separator", "\t", "-noheader", candidate, query])
          .toString()
          .trim()
      );
      if (count > bestCount) {
        bestCount = count;
        bestPath = candidate;
      }
    } catch {
      // ignore unreadable profiles
    }
  }
  return bestPath;
}

export function hostPatternsForDomains(domains) {
  const patterns = new Set();
  for (const domain of domains) {
    const bare = domain.replace(/^\./, "");
    patterns.add(`%${bare}`);
    patterns.add(`%.${bare}`);
  }
  return [...patterns];
}
