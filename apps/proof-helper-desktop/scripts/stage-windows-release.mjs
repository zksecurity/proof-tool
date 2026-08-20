#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const TARGET = "x86_64-pc-windows-msvc";
const WINDOWS_ASSET_EXTENSIONS = new Set([".exe", ".msi", ".msix", ".msixbundle", ".zip"]);
const RESERVED_TAGS = new Set(["proof-helper-v0.1.0"]);

// Mirrors active_descriptor() in src-tauri/src/proof_assets_release.rs; env
// vars remain as overrides for staging against an unpublished archive.
const proofAssetsDescriptor = {
  release_tag: "proof-assets-ownership-destination-v2-preprod-9fac96b-g3a",
  profile: "preprod-single-destination",
  archive_url:
    process.env.PROOF_ASSETS_ARCHIVE_URL ||
    "https://github.com/Anastasia-Labs/proof-tool-release/releases/download/proof-assets-ownership-destination-v2-preprod-9fac96b-g3a/proof-assets-ownership-destination-v2-preprod-9fac96b-g3a.tar",
  archive_size: numberFromEnv("PROOF_ASSETS_ARCHIVE_SIZE") ?? 1417943040,
  archive_sha256:
    process.env.PROOF_ASSETS_ARCHIVE_SHA256 ||
    "sha256:ee2f232f828da815428965ceb7d57719e32b706fce3373cff603de73a29fdff9",
  archive_blake2b256:
    process.env.PROOF_ASSETS_ARCHIVE_BLAKE2B256 ||
    "blake2b256:2a44af40ef01cbdca91728098c96978af247ca65dd7ea632090393709a516a28",
  expected_key_version: "ownership-destination-v2",
  expected_circuit_id: "root-ownership-destination-v2/bls12-381/groth16",
  expected_vk_hash: "blake2b256:b1c03cf24376bcd6c743cb372169ff71f93b210e0d8d52b2c6831808f50ded80",
  expected_signature_key_id: "preprod-local-destination-v2-9fac96b-g3a",
  trusted_manifest_public_key_hex: "2af3b300b9e641ede236d4b7d48b43eccfb843ffa9aca74abb38f98e7211eccb",
  expected_cardano_vk_blake2b256: "blake2b256:06ce913c931a53561fe5d022ed45a5fbc033b06d80eebdd9f646d23a05b7d5c4",
};

const args = parseArgs(process.argv.slice(2));
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(args.repoRoot ?? path.join(scriptDir, "..", "..", ".."));
const appDir = path.resolve(args.appDir ?? path.join(repoRoot, "apps", "proof-helper-desktop"));
const releaseTag = requiredArg(args.tag, "--tag");
const bundleDir = path.resolve(appDir, requiredArg(args.bundleDir, "--bundle-dir"));
const sidecarPath = path.resolve(appDir, requiredArg(args.sidecar, "--sidecar"));
const outDir = path.resolve(appDir, requiredArg(args.outDir, "--out-dir"));

if (RESERVED_TAGS.has(releaseTag)) {
  fail(`${releaseTag} is reserved for the portable fixture-helper bundles; use a new desktop release tag`);
}

await fs.rm(outDir, { recursive: true, force: true });
await fs.mkdir(outDir, { recursive: true });

const packageJson = await readJson(path.join(appDir, "package.json"));
const tauriConfig = await readJson(path.join(appDir, "src-tauri", "tauri.conf.json"));
const cargoToml = await fs.readFile(path.join(appDir, "src-tauri", "Cargo.toml"), "utf8");
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const appVersion = packageJson.version;
const tauriVersion = tauriConfig.version;

if (!appVersion || appVersion !== tauriVersion || appVersion !== cargoVersion) {
  fail(
    `app version mismatch: package.json=${appVersion ?? "missing"}, tauri.conf.json=${
      tauriVersion ?? "missing"
    }, Cargo.toml=${cargoVersion ?? "missing"}`,
  );
}

await assertFile(sidecarPath, "Windows sidecar");
const sidecarDigest = await digestFile(sidecarPath);
const bundleAssets = await findWindowsAssets(bundleDir);
if (bundleAssets.length === 0) {
  fail(`no Windows release assets found under ${bundleDir}`);
}

const usedNames = new Set();
const stagedArtifacts = [];
for (const sourcePath of bundleAssets) {
  const name = uniqueName(assetName(sourcePath, appVersion), usedNames);
  const destination = path.join(outDir, name);
  await fs.copyFile(sourcePath, destination);
  const digest = await digestFile(destination);
  const checksumName = `${name}.sha256`;
  await fs.writeFile(path.join(outDir, checksumName), `${digest.sha256}  ${name}\n`, "utf8");
  stagedArtifacts.push({
    name,
    kind: artifactKind(name),
    source_path: path.relative(repoRoot, sourcePath).split(path.sep).join("/"),
    size: digest.size,
    sha256: `sha256:${digest.sha256}`,
    checksum: checksumName,
  });
}

const manifest = {
  schema: "proof-helper-windows-release-manifest-v1",
  release_tag: releaseTag,
  generated_at: new Date().toISOString(),
  target: TARGET,
  product_name: tauriConfig.productName,
  app_version: appVersion,
  package_version: packageJson.version,
  tauri_config_version: tauriConfig.version,
  cargo_version: cargoVersion,
  // Staging does not Authenticode-sign or verify artifacts. A future signed
  // release path must derive this field from signature verification, never
  // from operator input.
  signed: false,
  sidecar: {
    name: path.basename(sidecarPath),
    target: TARGET,
    size: sidecarDigest.size,
    sha256: `sha256:${sidecarDigest.sha256}`,
  },
  proof_assets_descriptor: {
    ...proofAssetsDescriptor,
    download_configured:
      Boolean(proofAssetsDescriptor.archive_url) &&
      proofAssetsDescriptor.archive_size !== null &&
      Boolean(proofAssetsDescriptor.archive_sha256) &&
      Boolean(proofAssetsDescriptor.archive_blake2b256),
  },
  artifacts: stagedArtifacts,
};

await fs.writeFile(
  path.join(outDir, "proof-helper-windows-release-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  "utf8",
);

console.log(`staged ${stagedArtifacts.length} Windows release artifact(s) in ${outDir}`);

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      // pnpm 10 forwards the literal `--` separator from `pnpm run ... -- args`.
      continue;
    }
    if (!arg.startsWith("--")) {
      fail(`unexpected argument: ${arg}`);
    }
    const key = arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      fail(`missing value for ${arg}`);
    }
    parsed[key] = value;
    index += 1;
  }
  return parsed;
}

function requiredArg(value, name) {
  if (!value) {
    fail(`missing ${name}`);
  }
  return value;
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function assertFile(filePath, label) {
  const stat = await fs.stat(filePath).catch(() => null);
  if (!stat?.isFile() || stat.size === 0) {
    fail(`${label} is missing or empty: ${filePath}`);
  }
}

async function findWindowsAssets(root) {
  const assets = [];
  await walk(root, assets);
  return assets.sort();
}

async function walk(dir, assets) {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch((error) => {
    fail(`read bundle directory ${dir}: ${error.message}`);
  });
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(entryPath, assets);
    } else if (entry.isFile() && WINDOWS_ASSET_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      assets.push(entryPath);
    }
  }
}

function assetName(sourcePath, appVersion) {
  const extension = path.extname(sourcePath).toLowerCase();
  const sourceName = path.basename(sourcePath).toLowerCase();
  if (extension === ".msi") {
    return `proof-helper_${appVersion}_windows_x64.msi`;
  }
  if (extension === ".zip") {
    return `proof-helper_${appVersion}_windows_x64_portable.zip`;
  }
  if (extension === ".exe" && sourceName.includes("setup")) {
    return `proof-helper_${appVersion}_windows_x64_setup.exe`;
  }
  if (extension === ".exe") {
    return `proof-helper_${appVersion}_windows_x64.exe`;
  }
  return `proof-helper_${appVersion}_windows_x64${extension}`;
}

function uniqueName(name, usedNames) {
  if (!usedNames.has(name)) {
    usedNames.add(name);
    return name;
  }
  const extension = path.extname(name);
  const base = name.slice(0, -extension.length);
  let counter = 2;
  while (usedNames.has(`${base}_${counter}${extension}`)) {
    counter += 1;
  }
  const next = `${base}_${counter}${extension}`;
  usedNames.add(next);
  return next;
}

function artifactKind(name) {
  if (name.endsWith(".msi")) {
    return "msi-installer";
  }
  if (name.endsWith("_setup.exe")) {
    return "nsis-installer";
  }
  if (name.endsWith("_portable.zip")) {
    return "portable-zip";
  }
  return "windows-artifact";
}

async function digestFile(filePath) {
  const hash = createHash("sha256");
  const stat = await fs.stat(filePath);
  await new Promise((resolve, reject) => {
    createReadStream(filePath)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", resolve);
  });
  return {
    size: stat.size,
    sha256: hash.digest("hex"),
  };
}

function numberFromEnv(name) {
  const value = process.env[name];
  if (!value) {
    return null;
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    fail(`${name} must be a non-negative integer`);
  }
  return number;
}

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}
