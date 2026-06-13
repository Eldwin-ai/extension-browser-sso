import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function openBrowser(url) {
  if (process.platform === "darwin") {
    await execFileAsync("open", ["-a", "Google Chrome", url]).catch(async () => {
      await execFileAsync("open", [url]);
    });
    return;
  }
  await execFileAsync("xdg-open", [url]).catch(async () => {
    await execFileAsync("open", [url]);
  });
}

export async function waitFor(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
