import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  BootstrapError,
  NATIVE_VERSION,
  PACKAGE_VERSION,
  detectPlatform,
  isApprovedReleaseRedirect,
  runBootstrap,
  verifyAndSelectBootstrap,
} from "../lib/bootstrap.js";

test("stable npm and native release identities match", () => {
  assert.equal(PACKAGE_VERSION, "2.1.0");
  assert.equal(NATIVE_VERSION, "2.1.0");
});

const RELEASE_ORIGIN = "https://github.com/getaip/core/releases/download/";

function signedFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const rawPublicKey = publicDer.subarray(publicDer.length - 32);
  const keyId = "test-release-key";
  const executable = Buffer.from("reviewed native bootstrap\n");
  const targets = [
    ["darwin-arm64", "aarch64-apple-darwin"],
    ["darwin-x64", "x86_64-apple-darwin"],
    ["linux-arm64", "aarch64-unknown-linux-gnu"],
    ["linux-x64", "x86_64-unknown-linux-gnu"],
  ].map(([platform, rustTarget]) => {
    const name = `getaip-${NATIVE_VERSION}-${platform}`;
    return {
      platform,
      rust_target: rustTarget,
      minimum_platform_version: "qualified",
      cli_version: NATIVE_VERSION,
      server_version: NATIVE_VERSION,
      bootstrap: {
        name,
        kind: "raw-executable",
        url: `${RELEASE_ORIGIN}v${NATIVE_VERSION}/${name}`,
        size: executable.length,
        sha256: createHash("sha256").update(executable).digest("hex"),
        archive_root: null,
        files: [],
      },
      cli_archive: {},
      server_archive: {},
      distribution_archive: {},
    };
  });
  const manifest = {
    schema_version: 1,
    release: {
      version: NATIVE_VERSION,
      aip_protocol_version: "1.0",
      channel: "development",
      published_at: "2026-08-04T00:00:00Z",
      minimum_cli_version: NATIVE_VERSION,
      source: {
        gitea_commit: "a".repeat(40),
        gitea_tree: "b".repeat(40),
        github_commit: "c".repeat(40),
        github_tree: "d".repeat(40),
      },
    },
    signing_key_id: keyId,
    network_policy: {
      schema_version: 1,
      maximum_redirects: 1,
      redirect_hosts: ["release-assets.githubusercontent.com"],
    },
    previous_version: null,
    targets,
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const signature = sign(null, manifestBytes, privateKey);
  const signatureBytes = Buffer.from(
    `${JSON.stringify(
      {
        schema_version: 1,
        key_id: keyId,
        algorithm: "ed25519",
        signature: signature.toString("base64"),
      },
      null,
      2,
    )}\n`,
  );
  const trustStore = new Map([
    [
      keyId,
      {
        publicKeyBase64: rawPublicKey.toString("base64"),
        revoked: false,
      },
    ],
  ]);
  return { executable, manifest, manifestBytes, signatureBytes, trustStore };
}

test("exact signed bytes select only the matching bootstrap", () => {
  const fixture = signedFixture();
  const selected = verifyAndSelectBootstrap(
    fixture.manifestBytes,
    fixture.signatureBytes,
    detectPlatform("darwin", "arm64"),
    NATIVE_VERSION,
    fixture.trustStore,
  );
  assert.equal(
    selected.artifact.name,
    `getaip-${NATIVE_VERSION}-darwin-arm64`,
  );
  const tampered = Buffer.from(fixture.manifestBytes);
  tampered[tampered.length - 2] ^= 1;
  assert.throws(
    () =>
      verifyAndSelectBootstrap(
        tampered,
        fixture.signatureBytes,
        detectPlatform("darwin", "arm64"),
        NATIVE_VERSION,
        fixture.trustStore,
      ),
    /signature verification failed/,
  );
});

test("network policy and platform boundary reject lookalikes", () => {
  assert.equal(
    isApprovedReleaseRedirect(
      "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?token=3",
    ),
    true,
  );
  for (const rejected of [
    "http://release-assets.githubusercontent.com/github-production-release-asset/1/2?token=3",
    "https://evil.example/github-production-release-asset/1/2?token=3",
    "https://release-assets.githubusercontent.com/other/1/2?token=3",
    "https://release-assets.githubusercontent.com/github-production-release-asset/1/2",
  ]) {
    assert.equal(isApprovedReleaseRedirect(rejected), false);
  }
  assert.throws(() => detectPlatform("win32", "x64"), BootstrapError);
});

test("unsupported input fails before any network request", async () => {
  let fetched = false;
  const fetchImplementation = async () => {
    fetched = true;
    throw new Error("must not run");
  };
  await assert.rejects(
    runBootstrap(["setup"], {
      platform: "win32",
      architecture: "x64",
      fetchImplementation,
    }),
    /unsupported platform/,
  );
  await assert.rejects(
    runBootstrap(["doctor"], {
      platform: "linux",
      architecture: "x64",
      fetchImplementation,
    }),
    /supports only `getaip setup`/,
  );
  await assert.rejects(
    runBootstrap(["setup", "--manifest=untrusted.json"], {
      platform: "linux",
      architecture: "x64",
      fetchImplementation,
    }),
    /reserved for the verified npm handoff/,
  );
  await assert.rejects(
    runBootstrap(["setup"], {
      nodeVersion: "22.13.1",
      platform: "linux",
      architecture: "x64",
      fetchImplementation,
    }),
    /22\.14\.0 or newer/,
  );
  assert.equal(fetched, false);
});

test("unapproved redirect and bootstrap tamper fail before execution", async () => {
  let spawned = false;
  const spawnImplementation = () => {
    spawned = true;
    throw new Error("must not execute");
  };
  const redirectFetch = async () =>
    new Response(null, {
      status: 302,
      headers: { location: "https://evil.example/release" },
    });
  await assert.rejects(
    runBootstrap(["setup"], {
      platform: "linux",
      architecture: "x64",
      fetchImplementation: redirectFetch,
      spawnImplementation,
    }),
    /unapproved redirect/,
  );

  const fixture = signedFixture();
  const tamperedExecutable = Buffer.from(fixture.executable);
  tamperedExecutable[0] ^= 1;
  const responses = new Map([
    [
      `${RELEASE_ORIGIN}v${NATIVE_VERSION}/getaip-distribution-manifest.v1.json`,
      fixture.manifestBytes,
    ],
    [
      `${RELEASE_ORIGIN}v${NATIVE_VERSION}/getaip-distribution-manifest.v1.json.sig`,
      fixture.signatureBytes,
    ],
    [
      `${RELEASE_ORIGIN}v${NATIVE_VERSION}/getaip-${NATIVE_VERSION}-linux-x64`,
      tamperedExecutable,
    ],
  ]);
  const tamperFetch = async (url) => {
    const bytes = responses.get(url.href);
    assert.notEqual(bytes, undefined);
    return new Response(bytes, {
      status: 200,
      headers: { "content-length": String(bytes.length) },
    });
  };
  await assert.rejects(
    runBootstrap(["setup"], {
      platform: "linux",
      architecture: "x64",
      fetchImplementation: tamperFetch,
      spawnImplementation,
      trustStore: fixture.trustStore,
    }),
    /digest does not match/,
  );
  assert.equal(spawned, false);
});

test("verified bootstrap hands exact metadata to Rust and preserves exit status", async () => {
  const fixture = signedFixture();
  const responses = new Map([
    [
      `${RELEASE_ORIGIN}v${NATIVE_VERSION}/getaip-distribution-manifest.v1.json`,
      fixture.manifestBytes,
    ],
    [
      `${RELEASE_ORIGIN}v${NATIVE_VERSION}/getaip-distribution-manifest.v1.json.sig`,
      fixture.signatureBytes,
    ],
    [
      `${RELEASE_ORIGIN}v${NATIVE_VERSION}/getaip-${NATIVE_VERSION}-linux-x64`,
      fixture.executable,
    ],
  ]);
  const fetchImplementation = async (url) => {
    const bytes = responses.get(url.href);
    assert.notEqual(bytes, undefined);
    return new Response(bytes, {
      status: 200,
      headers: { "content-length": String(bytes.length) },
    });
  };
  let observation;
  const spawnImplementation = (executablePath, argumentsList, options) => {
    const child = new EventEmitter();
    child.killed = false;
    child.kill = () => {
      child.killed = true;
      return true;
    };
    observation = (async () => {
      assert.deepEqual(await readFile(executablePath), fixture.executable);
      assert.equal(argumentsList[0], "setup");
      assert.equal(argumentsList[1], "--manifest");
      assert.equal(argumentsList[3], "--signature");
      assert.deepEqual(argumentsList.slice(5), [
        "--dry-run",
        "--global",
        "--codex",
      ]);
      assert.equal(options.shell, false);
      assert.equal(options.stdio, "inherit");
      assert.deepEqual(await readFile(argumentsList[2]), fixture.manifestBytes);
      assert.deepEqual(
        await readFile(argumentsList[4]),
        fixture.signatureBytes,
      );
      child.emit("exit", 17, null);
    })();
    return child;
  };
  const result = await runBootstrap(
    ["setup", "--dry-run", "--global", "--codex"],
    {
      platform: "linux",
      architecture: "x64",
      fetchImplementation,
      spawnImplementation,
      trustStore: fixture.trustStore,
    },
  );
  await observation;
  assert.deepEqual(result, { code: 17, signal: null });
});
