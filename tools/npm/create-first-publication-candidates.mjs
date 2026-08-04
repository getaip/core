import { cp, lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const nativeVersion = "2.1.0";
const bootstrapVersion = `${nativeVersion}-bootstrap.0`;

const outputFlag = process.argv.indexOf("--output");
if (outputFlag < 0 || outputFlag + 2 !== process.argv.length) {
  throw new Error("usage: create-first-publication-candidates.mjs --output DIR");
}
const output = resolve(process.argv[outputFlag + 1]);
if (output === root || output.startsWith(`${root}/packages/`)) {
  throw new Error("first-publication output must not replace reviewed packages");
}
await mkdir(output, { recursive: false, mode: 0o700 });

const scopedDirectory = resolve(output, "getaip-cli");
const shortDirectory = resolve(output, "getaip");
await copyRealDirectory(resolve(root, "packages/getaip-cli"), scopedDirectory);
await copyRealDirectory(resolve(root, "packages/getaip"), shortDirectory);

const scoped = await readJson(resolve(scopedDirectory, "package.json"));
if (
  scoped.name !== "@getaip/cli" ||
  scoped.version !== nativeVersion ||
  scoped.getaipNativeVersion !== nativeVersion
) {
  throw new Error("reviewed scoped package identity is invalid");
}
scoped.version = bootstrapVersion;
await writeJson(resolve(scopedDirectory, "package.json"), scoped);

const short = await readJson(resolve(shortDirectory, "package.json"));
if (
  short.name !== "getaip" ||
  short.version !== nativeVersion ||
  short.dependencies?.["@getaip/cli"] !== nativeVersion
) {
  throw new Error("reviewed short package identity is invalid");
}
short.version = bootstrapVersion;
short.dependencies = { "@getaip/cli": bootstrapVersion };
await writeJson(resolve(shortDirectory, "package.json"), short);

process.stdout.write(
  `${JSON.stringify(
    {
      bootstrap_version: bootstrapVersion,
      native_version: nativeVersion,
      scoped_directory: scopedDirectory,
      short_directory: shortDirectory,
    },
    null,
    2,
  )}\n`,
);

async function copyRealDirectory(source, destination) {
  const metadata = await lstat(source);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`source package is not a real directory: ${source}`);
  }
  await cp(source, destination, {
    recursive: true,
    dereference: false,
    errorOnExist: true,
    force: false,
  });
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "w",
    mode: 0o600,
  });
}
