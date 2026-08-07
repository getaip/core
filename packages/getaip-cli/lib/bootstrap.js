import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmod,
  mkdtemp,
  open,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const RELEASE_ORIGIN = "https://github.com/getaip/core/releases/download/";
const RELEASE_REDIRECT_HOST = "release-assets.githubusercontent.com";
const RELEASE_REDIRECT_PATH = "/github-production-release-asset/";
const MANIFEST_NAME = "getaip-distribution-manifest.v1.json";
const SIGNATURE_NAME = "getaip-distribution-manifest.v1.json.sig";
const MANIFEST_LIMIT = 4 * 1024 * 1024;
const SIGNATURE_LIMIT = 64 * 1024;
const ARTIFACT_LIMIT = 1024 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 300_000;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const FORWARDED_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"];

const PLATFORM_MATRIX = Object.freeze({
  "darwin:arm64": Object.freeze({
    platform: "darwin-arm64",
    rustTarget: "aarch64-apple-darwin",
  }),
  "darwin:x64": Object.freeze({
    platform: "darwin-x64",
    rustTarget: "x86_64-apple-darwin",
  }),
  "linux:arm64": Object.freeze({
    platform: "linux-arm64",
    rustTarget: "aarch64-unknown-linux-gnu",
  }),
  "linux:x64": Object.freeze({
    platform: "linux-x64",
    rustTarget: "x86_64-unknown-linux-gnu",
  }),
});

const packageDocument = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);
const trustDocument = JSON.parse(
  await readFile(
    new URL("../trust/getaip-distribution-trusted-keys.json", import.meta.url),
    "utf8",
  ),
);

const packageIdentity = validatePackageDocument(packageDocument);
export const PACKAGE_VERSION = packageIdentity.packageVersion;
export const NATIVE_VERSION = packageIdentity.nativeVersion;
const TRUST_STORE = validateTrustDocument(trustDocument);

export class BootstrapError extends Error {
  constructor(message) {
    super(message);
    this.name = "BootstrapError";
  }
}

/**
 * Runs the reviewed native setup bootstrap and returns its exit result.
 *
 * The optional dependency injection is intentionally undocumented package
 * surface and exists only for deterministic tests.
 */
export async function runBootstrap(argumentsList, options = {}) {
  requireSupportedNode(options.nodeVersion ?? process.versions.node);
  const target = detectPlatform(
    options.platform ?? process.platform,
    options.architecture ?? process.arch,
  );
  const forwardedArguments = parseBootstrapArguments(argumentsList);
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  if (typeof fetchImplementation !== "function") {
    throw new BootstrapError("Node.js fetch support is unavailable");
  }

  const manifestUrl = releaseMetadataUrl(NATIVE_VERSION, MANIFEST_NAME);
  const signatureUrl = releaseMetadataUrl(NATIVE_VERSION, SIGNATURE_NAME);
  const [manifestBytes, signatureBytes] = await Promise.all([
    fetchBoundedBytes(manifestUrl, MANIFEST_LIMIT, fetchImplementation),
    fetchBoundedBytes(signatureUrl, SIGNATURE_LIMIT, fetchImplementation),
  ]);
  const verified = verifyAndSelectBootstrap(
    manifestBytes,
    signatureBytes,
    target,
    NATIVE_VERSION,
    options.trustStore ?? TRUST_STORE,
  );

  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), `getaip-${PACKAGE_VERSION}-bootstrap-`),
  );
  await chmod(temporaryDirectory, 0o700);
  try {
    const executablePath = join(temporaryDirectory, verified.artifact.name);
    const manifestPath = join(temporaryDirectory, MANIFEST_NAME);
    const signaturePath = join(temporaryDirectory, SIGNATURE_NAME);
    await downloadVerifiedExecutable(
      verified.artifact,
      executablePath,
      fetchImplementation,
    );
    await writeFile(manifestPath, manifestBytes, {
      flag: "wx",
      mode: 0o600,
    });
    await writeFile(signaturePath, signatureBytes, {
      flag: "wx",
      mode: 0o600,
    });
    return await executeNativeSetup(
      executablePath,
      manifestPath,
      signaturePath,
      forwardedArguments,
      options.spawnImplementation ?? spawn,
    );
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

/** Executes the bootstrap as a process entrypoint without exposing secrets. */
export async function runBootstrapMain(argumentsList) {
  try {
    const result = await runBootstrap(argumentsList);
    if (result.signal !== null) {
      process.exitCode = signalExitCode(result.signal);
      process.kill(process.pid, result.signal);
      return;
    }
    process.exitCode = result.code;
  } catch (error) {
    const message =
      error instanceof BootstrapError
        ? error.message
        : "the verified native setup bootstrap failed";
    process.stderr.write(`getaip bootstrap: ${message}\n`);
    process.exitCode = 1;
  }
}

export function detectPlatform(platform, architecture) {
  const target = PLATFORM_MATRIX[`${platform}:${architecture}`];
  if (target === undefined) {
    throw new BootstrapError(
      `unsupported platform ${platform}/${architecture}; no files were downloaded`,
    );
  }
  return target;
}

export function verifyAndSelectBootstrap(
  manifestBytes,
  signatureBytes,
  target,
  nativeVersion = NATIVE_VERSION,
  trustStore = TRUST_STORE,
) {
  if (!Buffer.isBuffer(manifestBytes) || !Buffer.isBuffer(signatureBytes)) {
    throw new BootstrapError("release metadata must be exact byte buffers");
  }
  const envelope = parseJson(signatureBytes, "signature envelope");
  assertExactKeys(
    envelope,
    ["algorithm", "key_id", "schema_version", "signature"],
    "signature envelope",
  );
  if (
    envelope.schema_version !== 1 ||
    envelope.algorithm !== "ed25519" ||
    typeof envelope.key_id !== "string"
  ) {
    throw new BootstrapError("unsupported release signature envelope");
  }
  const trustedKey = trustStore.get(envelope.key_id);
  if (trustedKey === undefined || trustedKey.revoked) {
    throw new BootstrapError("release manifest uses an untrusted signing key");
  }
  const signature = decodeCanonicalBase64(
    envelope.signature,
    64,
    "release signature",
  );
  const rawPublicKey = decodeCanonicalBase64(
    trustedKey.publicKeyBase64,
    32,
    "release public key",
  );
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: "der",
    type: "spki",
  });
  if (!verifySignature(null, manifestBytes, publicKey, signature)) {
    throw new BootstrapError("release manifest signature verification failed");
  }

  const manifest = parseJson(manifestBytes, "distribution manifest");
  const selectedTarget = validateBootstrapManifest(
    manifest,
    envelope.key_id,
    target,
    nativeVersion,
  );
  return { manifest, artifact: selectedTarget.bootstrap };
}

export function isApprovedReleaseRedirect(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.hostname === RELEASE_REDIRECT_HOST &&
    url.username === "" &&
    url.password === "" &&
    url.port === "" &&
    url.hash === "" &&
    url.pathname.startsWith(RELEASE_REDIRECT_PATH) &&
    url.search.length > 1
  );
}

function validatePackageDocument(document) {
  if (
    !isPlainObject(document) ||
    document.name !== "@getaip/cli" ||
    typeof document.version !== "string" ||
    typeof document.getaipNativeVersion !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(document.getaipNativeVersion) ||
    ![
      document.getaipNativeVersion,
      `${document.getaipNativeVersion}-bootstrap.0`,
    ].includes(document.version)
  ) {
    throw new BootstrapError("@getaip/cli package identity is invalid");
  }
  return {
    packageVersion: document.version,
    nativeVersion: document.getaipNativeVersion,
  };
}

function validateTrustDocument(document) {
  assertExactKeys(document, ["keys", "schema_version"], "release trust store");
  if (document.schema_version !== 1 || !Array.isArray(document.keys)) {
    throw new BootstrapError("release trust store schema is unsupported");
  }
  const keys = new Map();
  for (const key of document.keys) {
    assertExactKeys(
      key,
      ["algorithm", "key_id", "public_key_base64", "revoked"],
      "release trust key",
    );
    if (
      typeof key.key_id !== "string" ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(key.key_id) ||
      key.algorithm !== "ed25519" ||
      typeof key.revoked !== "boolean"
    ) {
      throw new BootstrapError("release trust key is invalid");
    }
    decodeCanonicalBase64(key.public_key_base64, 32, "release public key");
    if (keys.has(key.key_id)) {
      throw new BootstrapError("release trust store contains a duplicate key");
    }
    keys.set(key.key_id, {
      publicKeyBase64: key.public_key_base64,
      revoked: key.revoked,
    });
  }
  if (keys.size === 0) {
    throw new BootstrapError("release trust store is empty");
  }
  return keys;
}

function requireSupportedNode(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (match === null) {
    throw new BootstrapError("could not determine the Node.js version");
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major < 22 || (major === 22 && minor < 14)) {
    throw new BootstrapError("Node.js 22.14.0 or newer is required");
  }
}

function parseBootstrapArguments(argumentsList) {
  if (!Array.isArray(argumentsList) || argumentsList[0] !== "setup") {
    throw new BootstrapError(
      "the npm launcher supports only `getaip setup`; use the installed `getaip` for other commands",
    );
  }
  const forwarded = argumentsList.slice(1);
  for (const argument of forwarded) {
    if (
      argument === "--manifest" ||
      argument.startsWith("--manifest=") ||
      argument === "--signature" ||
      argument.startsWith("--signature=")
    ) {
      throw new BootstrapError(
        "--manifest and --signature are reserved for the verified npm handoff",
      );
    }
  }
  return forwarded;
}

function releaseMetadataUrl(version, name) {
  return new URL(`v${version}/${name}`, RELEASE_ORIGIN);
}

async function fetchBoundedBytes(url, maximum, fetchImplementation) {
  const response = await fetchWithApprovedRedirect(url, fetchImplementation);
  requireOkResponse(response, maximum);
  const chunks = [];
  let received = 0;
  if (response.body !== null) {
    for await (const value of response.body) {
      const chunk = Buffer.from(value);
      received = checkedDownloadSize(received, chunk.length, maximum);
      chunks.push(chunk);
    }
  }
  return Buffer.concat(chunks, received);
}

async function fetchWithApprovedRedirect(url, fetchImplementation) {
  let response = await safeFetch(url, fetchImplementation);
  if (!isRedirectStatus(response.status)) {
    return response;
  }
  const location = response.headers.get("location");
  if (location === null) {
    throw new BootstrapError("GitHub release redirect omitted its location");
  }
  const redirect = new URL(location, url);
  if (!isApprovedReleaseRedirect(redirect.href)) {
    throw new BootstrapError("GitHub release returned an unapproved redirect");
  }
  await response.body?.cancel();
  response = await safeFetch(redirect, fetchImplementation);
  if (isRedirectStatus(response.status)) {
    await response.body?.cancel();
    throw new BootstrapError("GitHub release exceeded the one-redirect limit");
  }
  return response;
}

async function safeFetch(url, fetchImplementation) {
  try {
    return await fetchImplementation(url, {
      cache: "no-store",
      headers: {
        accept: "application/octet-stream",
        "user-agent": `getaip-npm/${PACKAGE_VERSION}`,
      },
      redirect: "manual",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new BootstrapError("GetAIP release request failed");
  }
}

function requireOkResponse(response, maximum, expectedSize = undefined) {
  if (response.status !== 200) {
    throw new BootstrapError(
      `GetAIP release request returned HTTP ${response.status}`,
    );
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      throw new BootstrapError(
        "GetAIP release returned an invalid Content-Length",
      );
    }
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared > maximum) {
      throw new BootstrapError("GetAIP release exceeds the download limit");
    }
    if (expectedSize !== undefined && declared !== expectedSize) {
      throw new BootstrapError(
        "native bootstrap Content-Length does not match its manifest",
      );
    }
  }
}

function checkedDownloadSize(current, additional, maximum) {
  const next = current + additional;
  if (!Number.isSafeInteger(next) || next > maximum) {
    throw new BootstrapError("GetAIP release exceeds the download limit");
  }
  return next;
}

async function downloadVerifiedExecutable(
  artifact,
  destination,
  fetchImplementation,
) {
  const response = await fetchWithApprovedRedirect(
    new URL(artifact.url),
    fetchImplementation,
  );
  requireOkResponse(response, artifact.size, artifact.size);
  const output = await open(destination, "wx", 0o600);
  const digest = createHash("sha256");
  let received = 0;
  try {
    if (response.body !== null) {
      for await (const value of response.body) {
        const chunk = Buffer.from(value);
        received = checkedDownloadSize(received, chunk.length, artifact.size);
        digest.update(chunk);
        let offset = 0;
        while (offset < chunk.length) {
          const result = await output.write(
            chunk,
            offset,
            chunk.length - offset,
          );
          if (result.bytesWritten === 0) {
            throw new BootstrapError("native bootstrap write made no progress");
          }
          offset += result.bytesWritten;
        }
      }
    }
    if (received !== artifact.size) {
      throw new BootstrapError(
        "native bootstrap size does not match its manifest",
      );
    }
    const actualDigest = digest.digest("hex");
    if (actualDigest !== artifact.sha256) {
      throw new BootstrapError(
        "native bootstrap digest does not match its manifest",
      );
    }
    await output.sync();
  } finally {
    await output.close();
  }
  await chmod(destination, 0o700);
}

function validateBootstrapManifest(manifest, keyId, selected, nativeVersion) {
  assertExactKeys(
    manifest,
    [
      "network_policy",
      "previous_version",
      "release",
      "schema_version",
      "signing_key_id",
      "targets",
    ],
    "distribution manifest",
  );
  if (manifest.schema_version !== 1 || manifest.signing_key_id !== keyId) {
    throw new BootstrapError("distribution manifest identity is invalid");
  }
  validateNetworkPolicy(manifest.network_policy);
  assertExactKeys(
    manifest.release,
    [
      "aip_protocol_version",
      "channel",
      "minimum_cli_version",
      "published_at",
      "source",
      "version",
    ],
    "release identity",
  );
  if (
    manifest.release.version !== nativeVersion ||
    manifest.release.aip_protocol_version !== "1.0" ||
    typeof manifest.release.published_at !== "string" ||
    typeof manifest.release.minimum_cli_version !== "string"
  ) {
    throw new BootstrapError(
      "npm and signed native release versions are incompatible",
    );
  }
  if (!Array.isArray(manifest.targets) || manifest.targets.length !== 4) {
    throw new BootstrapError(
      "distribution manifest does not contain four targets",
    );
  }
  const expectedPlatforms = new Set(
    Object.values(PLATFORM_MATRIX).map((value) => value.platform),
  );
  const seenPlatforms = new Set();
  let selectedTarget;
  for (const target of manifest.targets) {
    validateTarget(target, nativeVersion);
    if (
      !expectedPlatforms.has(target.platform) ||
      seenPlatforms.has(target.platform)
    ) {
      throw new BootstrapError(
        "distribution manifest target matrix is invalid",
      );
    }
    seenPlatforms.add(target.platform);
    if (target.platform === selected.platform) {
      if (target.rust_target !== selected.rustTarget) {
        throw new BootstrapError(
          "distribution manifest Rust target is incompatible",
        );
      }
      selectedTarget = target;
    }
  }
  if (
    seenPlatforms.size !== expectedPlatforms.size ||
    selectedTarget === undefined
  ) {
    throw new BootstrapError(
      "current platform is absent from the signed manifest",
    );
  }
  return selectedTarget;
}

function validateNetworkPolicy(policy) {
  assertExactKeys(
    policy,
    ["maximum_redirects", "redirect_hosts", "schema_version"],
    "release network policy",
  );
  if (
    policy.schema_version !== 1 ||
    policy.maximum_redirects !== 1 ||
    !Array.isArray(policy.redirect_hosts) ||
    policy.redirect_hosts.length !== 1 ||
    policy.redirect_hosts[0] !== RELEASE_REDIRECT_HOST
  ) {
    throw new BootstrapError("release network policy is unsupported");
  }
}

function validateTarget(target, nativeVersion) {
  assertExactKeys(
    target,
    [
      "bootstrap",
      "cli_archive",
      "cli_version",
      "distribution_archive",
      "minimum_platform_version",
      "platform",
      "rust_target",
      "server_archive",
      "server_version",
    ],
    "distribution target",
  );
  if (
    typeof target.platform !== "string" ||
    typeof target.rust_target !== "string" ||
    typeof target.minimum_platform_version !== "string" ||
    target.minimum_platform_version.length === 0 ||
    target.cli_version !== nativeVersion ||
    target.server_version !== nativeVersion
  ) {
    throw new BootstrapError("distribution target compatibility is invalid");
  }
  const expected =
    PLATFORM_MATRIX[
      Object.keys(PLATFORM_MATRIX).find(
        (key) => PLATFORM_MATRIX[key].platform === target.platform,
      )
    ];
  if (expected === undefined || target.rust_target !== expected.rustTarget) {
    throw new BootstrapError("distribution target identity is invalid");
  }
  validateBootstrapArtifact(target.bootstrap, target.platform, nativeVersion);
  for (const archive of [
    target.cli_archive,
    target.server_archive,
    target.distribution_archive,
  ]) {
    if (!isPlainObject(archive)) {
      throw new BootstrapError("distribution archive metadata is invalid");
    }
  }
}

function validateBootstrapArtifact(artifact, platform, nativeVersion) {
  assertExactKeys(
    artifact,
    ["archive_root", "files", "kind", "name", "sha256", "size", "url"],
    "native bootstrap artifact",
  );
  const expectedName = `getaip-${nativeVersion}-${platform}`;
  const expectedUrl = `${RELEASE_ORIGIN}v${nativeVersion}/${expectedName}`;
  if (
    artifact.name !== expectedName ||
    artifact.kind !== "raw-executable" ||
    artifact.url !== expectedUrl ||
    !Number.isSafeInteger(artifact.size) ||
    artifact.size < 1 ||
    artifact.size > ARTIFACT_LIMIT ||
    typeof artifact.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(artifact.sha256) ||
    artifact.archive_root !== null ||
    !Array.isArray(artifact.files) ||
    artifact.files.length !== 0
  ) {
    throw new BootstrapError("native bootstrap artifact is invalid");
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new BootstrapError(`${label} is invalid JSON`);
  }
}

function assertExactKeys(value, expectedKeys, label) {
  if (!isPlainObject(value)) {
    throw new BootstrapError(`${label} must be a JSON object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new BootstrapError(`${label} contains unexpected or missing fields`);
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function decodeCanonicalBase64(value, expectedLength, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new BootstrapError(`${label} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.length !== expectedLength ||
    decoded.toString("base64") !== value
  ) {
    throw new BootstrapError(`${label} has an invalid length or encoding`);
  }
  return decoded;
}

function isRedirectStatus(status) {
  return [301, 302, 303, 307, 308].includes(status);
}

function executeNativeSetup(
  executablePath,
  manifestPath,
  signaturePath,
  forwardedArguments,
  spawnImplementation,
) {
  return new Promise((resolve, reject) => {
    const child = spawnImplementation(
      executablePath,
      [
        "setup",
        "--manifest",
        manifestPath,
        "--signature",
        signaturePath,
        ...forwardedArguments,
      ],
      {
        shell: false,
        stdio: "inherit",
        windowsHide: true,
      },
    );
    const handlers = new Map();
    const removeHandlers = () => {
      for (const [signal, handler] of handlers) {
        process.off(signal, handler);
      }
    };
    for (const signal of FORWARDED_SIGNALS) {
      const handler = () => {
        if (!child.killed) {
          child.kill(signal);
        }
      };
      handlers.set(signal, handler);
      process.on(signal, handler);
    }
    child.once("error", () => {
      removeHandlers();
      reject(
        new BootstrapError("failed to execute the verified native bootstrap"),
      );
    });
    child.once("exit", (code, signal) => {
      removeHandlers();
      resolve({
        code: Number.isInteger(code) ? code : signalExitCode(signal),
        signal: signal ?? null,
      });
    });
  });
}

function signalExitCode(signal) {
  const numbers = { SIGHUP: 1, SIGINT: 2, SIGTERM: 15 };
  return 128 + (numbers[signal] ?? 1);
}
