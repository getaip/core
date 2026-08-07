import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const version = "2.1.0";
const packages = [
  {
    directory: join(root, "packages/getaip-cli"),
    name: "@getaip/cli",
    files: [
      "LICENSE",
      "bin/getaip.js",
      "lib/bootstrap.js",
      "package.json",
      "trust/getaip-distribution-trusted-keys.json",
    ],
  },
  {
    directory: join(root, "packages/getaip"),
    name: "getaip",
    files: ["LICENSE", "bin/getaip.js", "package.json"],
  },
];

await verifyCopiedEvidence();
const temporary = await mkdtemp(join(tmpdir(), "getaip-npm-pack-"));
try {
  const rootPackage = await readJson(join(root, "package.json"));
  assert.equal(rootPackage.version, version);
  assert.equal(rootPackage.private, true);
  assert.equal(rootPackage.packageManager, "npm@11.5.1");
  assert.deepEqual(rootPackage.workspaces, [
    "packages/getaip-cli",
    "packages/getaip",
  ]);
  for (const packageSpec of packages) {
    const document = await readJson(
      join(packageSpec.directory, "package.json"),
    );
    validatePublishedPackage(document, packageSpec.name, version);
    validateNoLifecycleScripts(document);
    const binPath = join(packageSpec.directory, "bin/getaip.js");
    const metadata = await lstat(binPath);
    assert.equal(metadata.isFile(), true);
    assert.equal(metadata.isSymbolicLink(), false);
    assert.notEqual(metadata.mode & 0o111, 0);
    run("node", ["--check", binPath], root);

    const packed = run(
      "npm",
      ["pack", "--json", "--ignore-scripts", "--pack-destination", temporary],
      packageSpec.directory,
    );
    const report = JSON.parse(packed);
    assert.equal(report.length, 1);
    assert.equal(report[0].name, packageSpec.name);
    assert.equal(report[0].version, version);
    assert.match(report[0].integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
    assert.deepEqual(
      report[0].files.map((file) => file.path).sort(),
      [...packageSpec.files].sort(),
    );
    for (const file of report[0].files) {
      assert.equal(file.mode, file.path === "bin/getaip.js" ? 0o755 : 0o644);
    }
  }

  const shortPackage = await readJson(
    join(root, "packages/getaip/package.json"),
  );
  assert.deepEqual(shortPackage.dependencies, { "@getaip/cli": version });
  const scopedPackage = await readJson(
    join(root, "packages/getaip-cli/package.json"),
  );
  assert.equal(scopedPackage.dependencies, undefined);
  assert.equal(scopedPackage.getaipNativeVersion, version);
  await verifyFirstPublicationCandidates(temporary);
  process.stdout.write("npm package boundary: PASS\n");
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function verifyCopiedEvidence() {
  const sourceLicense = await readFile(join(root, "LICENSE"));
  for (const packageSpec of packages) {
    const packageLicense = await readFile(
      join(packageSpec.directory, "LICENSE"),
    );
    assert.deepEqual(packageLicense, sourceLicense);
  }
  const sourceTrust = await readFile(
    join(root, "release/getaip-distribution-trusted-keys.json"),
  );
  const packageTrust = await readFile(
    join(
      root,
      "packages/getaip-cli/trust/getaip-distribution-trusted-keys.json",
    ),
  );
  assert.deepEqual(packageTrust, sourceTrust);
}

async function verifyFirstPublicationCandidates(temporary) {
  const output = join(temporary, "first-publication");
  run(
    "node",
    [
      "tools/npm/create-first-publication-candidates.mjs",
      "--output",
      output,
    ],
    root,
  );
  const bootstrapVersion = `${version}-bootstrap.0`;
  const candidates = [
    {
      directory: join(output, "getaip-cli"),
      name: "@getaip/cli",
      files: packages[0].files,
    },
    {
      directory: join(output, "getaip"),
      name: "getaip",
      files: packages[1].files,
    },
  ];
  for (const candidate of candidates) {
    const document = await readJson(join(candidate.directory, "package.json"));
    validatePublishedPackage(document, candidate.name, bootstrapVersion);
    const report = JSON.parse(
      run(
        "npm",
        ["pack", "--json", "--ignore-scripts", "--pack-destination", temporary],
        candidate.directory,
      ),
    );
    assert.equal(report[0].version, bootstrapVersion);
    assert.deepEqual(
      report[0].files.map((file) => file.path).sort(),
      [...candidate.files].sort(),
    );
  }
  const scoped = await readJson(join(candidates[0].directory, "package.json"));
  const short = await readJson(join(candidates[1].directory, "package.json"));
  assert.equal(scoped.getaipNativeVersion, version);
  assert.deepEqual(short.dependencies, { "@getaip/cli": bootstrapVersion });
  const bootstrap = await import(
    pathToFileURL(join(candidates[0].directory, "lib/bootstrap.js")).href
  );
  assert.equal(bootstrap.PACKAGE_VERSION, bootstrapVersion);
  assert.equal(bootstrap.NATIVE_VERSION, version);
}

function validatePublishedPackage(document, expectedName, expectedVersion) {
  assert.equal(document.name, expectedName);
  assert.equal(document.version, expectedVersion);
  assert.equal(document.private, undefined);
  assert.deepEqual(document.bin, { getaip: "./bin/getaip.js" });
  assert.deepEqual(document.engines, { node: ">=22.14.0" });
  assert.equal(document.license, "BUSL-1.1");
  assert.deepEqual(document.author, {
    name: "WAI LLC",
    email: "hi@getaip.org",
    url: "https://getaip.org",
  });
  assert.equal(document.homepage, "https://getaip.org");
  assert.deepEqual(document.publishConfig, {
    access: "public",
    provenance: true,
  });
}

function validateNoLifecycleScripts(document) {
  const forbidden = new Set([
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
    "prepare",
  ]);
  for (const name of Object.keys(document.scripts ?? {})) {
    assert.equal(
      forbidden.has(name),
      false,
      `forbidden lifecycle script ${name}`,
    );
  }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function run(program, argumentsList, cwd) {
  const result = spawnSync(program, argumentsList, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, npm_config_update_notifier: "false" },
  });
  if (result.status !== 0) {
    throw new Error(
      `${program} failed with ${result.status}: ${result.stderr.trim()}`,
    );
  }
  return result.stdout.trim();
}
