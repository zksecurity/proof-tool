import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { afterEach, expect, test } from "vitest";

const tempDirs = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

test("stages Windows artifacts as unsigned even when the environment claims signing", async () => {
  const root = await fsp.mkdtemp("/tmp/proof-helper-windows-stage-");
  tempDirs.push(root);
  const app = path.join(root, "apps", "proof-helper-desktop");
  const bundle = path.join(root, "bundle");
  await fsp.mkdir(path.join(app, "src-tauri"), { recursive: true });
  await fsp.mkdir(bundle, { recursive: true });
  await fsp.writeFile(path.join(app, "package.json"), '{"version":"0.2.2"}\n');
  await fsp.writeFile(
    path.join(app, "src-tauri", "tauri.conf.json"),
    '{"version":"0.2.2","productName":"Proof Helper"}\n',
  );
  await fsp.writeFile(
    path.join(app, "src-tauri", "Cargo.toml"),
    '[package]\nname = "proof-helper-desktop"\nversion = "0.2.2"\n',
  );

  const installer = path.join(bundle, "Proof Helper.msi");
  const sidecar = path.join(root, "proof-tool-x86_64-pc-windows-msvc.exe");
  const out = path.join(root, "out");
  await fsp.writeFile(installer, "installer-bytes");
  await fsp.writeFile(sidecar, "sidecar-bytes");

  execFileSync(
    process.execPath,
    [
      path.resolve("scripts/stage-windows-release.mjs"),
      "--repo-root",
      root,
      "--tag",
      "proof-helper-desktop-v0.2.2-windows-preview.1",
      "--bundle-dir",
      bundle,
      "--sidecar",
      sidecar,
      "--out-dir",
      out,
    ],
    { env: { ...process.env, PROOF_HELPER_WINDOWS_SIGNED: "1" } },
  );

  const artifact = "proof-helper_0.2.2_windows_x64.msi";
  const bytes = await fsp.readFile(path.join(out, artifact));
  const digest = createHash("sha256").update(bytes).digest("hex");
  expect(await fsp.readFile(path.join(out, `${artifact}.sha256`), "utf8")).toBe(`${digest}  ${artifact}\n`);
  const manifest = JSON.parse(await fsp.readFile(path.join(out, "proof-helper-windows-release-manifest.json"), "utf8"));
  expect(manifest.signed).toBe(false);
});
