"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/main.ts
var core = __toESM(require("@actions/core"), 1);
var tc = __toESM(require("@actions/tool-cache"), 1);
var ht = __toESM(require("@actions/http-client"), 1);
var fs = __toESM(require("fs"), 1);
var fsp = __toESM(require("fs/promises"), 1);
var path = __toESM(require("path"), 1);
var os = __toESM(require("os"), 1);
var child_process = __toESM(require("child_process"), 1);
function getLibcVersion() {
  try {
    const output = child_process.execSync("ldd --version").toString();
    if (output.includes("GNU libc")) {
      return "gnu";
    } else if (output.includes("musl libc")) {
      return "musl";
    }
  } catch (error) {
    console.error("Failed to determine libc version:", error);
  }
  return "";
}
function getBinaryType() {
  const platform2 = os.platform();
  const arch2 = os.arch();
  switch (platform2) {
    case "darwin": {
      if (arch2 === "x64") {
        return "bwenv-x86_64-apple-darwin.zip";
      } else if (arch2 === "arm64") {
        return "bwenv-aarch64-apple-darwin.zip";
      }
      break;
    }
    case "linux": {
      const libc = getLibcVersion();
      if (arch2 === "x64" && libc === "gnu") {
        return "bwenv-x86_64-unknown-linux-gnu.zip";
      } else if (arch2 === "x64" && libc === "musl") {
        return "bwenv-x86_64-unknown-linux-musl.zip";
      }
      break;
    }
  }
  throw new Error(`Unsupported platform/architecture: ${platform2}/${arch2}`);
}
function getReleaseURL(version = "latest", binaryType) {
  const _version = `v${version.replace("v", "")}`;
  return `https://github.com/titanom/bwenv/releases/download/${_version}/${binaryType ?? getBinaryType()}`;
}
async function downloadFile(fileURL, destination) {
  const httpClient = new ht.HttpClient("titanom/bwenv-setup");
  const response = await httpClient.get(fileURL);
  if (response.message.statusCode !== 200) {
    throw new Error(`Failed to download file. HTTP Status: ${response.message.statusCode}`);
  }
  const fileStream = fs.createWriteStream(destination);
  return new Promise(
    (resolve, reject) => response.message.pipe(fileStream).on("close", () => resolve(destination)).on("error", (error) => reject(error))
  );
}
async function unzipArchive(archive, destination = __dirname, deleteAfter = false) {
  const extract = (() => {
    if (archive.endsWith(".zip"))
      return tc.extractZip;
    if (archive.endsWith(".tar.gz"))
      return tc.extractTar;
    return tc.extractZip;
  })();
  const extracted = await extract(archive, destination);
  deleteAfter && await fsp.unlink(archive);
  return extracted;
}
async function run() {
  try {
    const version = core.getInput("version", { required: false });
    const releaseURL = getReleaseURL(version);
    await downloadFile(releaseURL, path.join(__dirname, "bwenv.zip")).then(
      (archive) => unzipArchive(archive, __dirname, true)
    );
    const toolDir = await tc.cacheFile(path.join(__dirname, "bwenv"), "bwenv", "bwenv", version);
    core.addPath(toolDir);
  } catch (error) {
    core.setFailed(error.message);
  }
}
run();
