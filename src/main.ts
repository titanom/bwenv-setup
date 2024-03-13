import * as core from '@actions/core';
import * as tc from '@actions/tool-cache';
import * as ht from '@actions/http-client';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import * as child_process from 'node:child_process';
import { parse as parseYaml } from 'yaml';
import { parse as parseToml } from 'toml';
import * as z from 'zod';
import * as semver from 'semver';

// @ts-expect-error __dirname does not exist in ESM
if (typeof __dirname === 'undefined') {
  var __dirname = path.resolve();
}

const configFileSchema = z.object({
  version: z.coerce.string(),
});

async function getVersionFromConfigFile() {
  const files = ['bwenv.yaml', 'bwenv.yml', 'bwenv.toml'];

  let filepath: string | undefined = undefined;

  for (const file of files) {
    const currentPath = path.join(process.env.GITHUB_WORKSPACE ?? process.cwd(), file);
    try {
      const stat = await fsp.stat(currentPath);
      if (stat.isFile()) {
        filepath = currentPath;
        break;
      }
    } catch {}
  }

  if (!filepath) throw new Error('Could not find configuration file in root directory.');
  const raw = await fsp.readFile(filepath, 'utf8');

  const parse = filepath.endsWith('toml') ? parseToml : parseYaml;
  const parsed = parse(raw);
  const config = configFileSchema.parse(parsed);
  return config.version;
}

function findLatestMatchingVersion(versions: string[], targetVersion: string): string | undefined {
  const matchingVersions = versions.filter((version) => semver.satisfies(version, targetVersion));
  matchingVersions.sort((a, b) => semver.rcompare(a, b));
  return matchingVersions[0];
}

async function getAvailableVersions() {
  const releaseURL = `https://api.github.com/repos/titanom/bwenv/releases`;

  const http = new ht.HttpClient('titanom/bwenv-setup');
  const response = await http.getJson<{ tag_name: string }[]>(releaseURL);

  if (response.result) {
    const versions = response.result.map((result) => result.tag_name);
    return versions;
  } else {
    throw new Error(`Failed to get release information for titanom/bwenv`);
  }
}

function getLibcVersion(): string {
  try {
    const output = child_process.execSync('ldd --version').toString();
    if (output.includes('GNU libc')) {
      return 'gnu';
    } else if (output.includes('musl libc')) {
      return 'musl';
    }
  } catch (error) {
    console.error('Failed to determine libc version:', error);
  }
  return '';
}

function getBinaryType(): string {
  const platform = os.platform();
  const arch = os.arch();

  core.info(`Platform: ${platform}`);
  core.info(`Arch: ${arch}`);

  let binary = '';

  switch (platform) {
    case 'darwin': {
      if (arch === 'x64') {
        binary = 'bwenv-x86_64-apple-darwin.zip';
      } else if (arch === 'arm64') {
        binary = 'bwenv-aarch64-apple-darwin.zip';
      }
      break;
    }
    case 'linux': {
      const libc = getLibcVersion();
      if (arch === 'x64' && libc === 'gnu') {
        binary = 'bwenv-x86_64-unknown-linux-gnu.zip';
      } else if (arch === 'x64') {
        binary = 'bwenv-x86_64-unknown-linux-musl.zip';
      }
      break;
    }
  }

  if (!binary) {
    throw new Error(`Unsupported platform/architecture: ${platform}/${arch}`);
  }

  core.info(`Binary: ${binary}`);

  return binary;
}

async function getLatestVersion(): Promise<string> {
  const releaseURL = `https://api.github.com/repos/titanom/bwenv/releases/latest`;

  const http = new ht.HttpClient('titanom/bwenv-setup');
  const response = await http.getJson<any>(releaseURL);

  if (response.result) {
    const tag = response.result.tag_name;
    return tag;
  } else {
    throw new Error(`Failed to get the latest release information for titanom/bwenv`);
  }
}

async function getReleaseURL(version = 'latest', binaryType?: string): Promise<string> {
  const _version = version === 'latest' ? await getLatestVersion() : `v${version.replace('v', '')}`;
  return `https://github.com/titanom/bwenv/releases/download/${_version}/${
    binaryType ?? getBinaryType()
  }`;
}

async function downloadFile(fileURL: string, destination: string): Promise<string> {
  const httpClient = new ht.HttpClient('titanom/bwenv-setup');

  const response = await httpClient.get(fileURL);

  if (response.message.statusCode !== 200) {
    throw new Error(`Failed to download file. HTTP Status: ${response.message.statusCode}`);
  }

  const fileStream = fs.createWriteStream(destination);
  return new Promise((resolve, reject) =>
    response.message
      .pipe(fileStream)
      .on('close', () => resolve(destination))
      .on('error', (error) => reject(error)),
  );
}

async function unzipArchive(
  archive: string,
  destination: string = __dirname,
  deleteAfter = false,
): Promise<string> {
  const extract = (() => {
    if (archive.endsWith('.zip')) return tc.extractZip;
    if (archive.endsWith('.tar.gz')) return tc.extractTar;
    return tc.extractZip;
  })();
  const extracted = await extract(archive, destination);
  deleteAfter && (await fsp.unlink(archive));
  return extracted;
}

async function run() {
  try {
    const version =
      core.getInput('version', { required: false }) ||
      ((await (async () => {
        const configVersion = await getVersionFromConfigFile();
        const availableVersions = await getAvailableVersions();
        const matchingVersion = findLatestMatchingVersion(availableVersions, configVersion);
        return matchingVersion;
      })()) ??
        'latest');

    core.info(`Using Version: ${version}`);

    const releaseURL = await getReleaseURL(version);

    await downloadFile(releaseURL, path.join(__dirname, 'bwenv.zip')).then((archive) =>
      unzipArchive(archive, __dirname, true),
    );

    const toolDir = await tc.cacheFile(path.join(__dirname, 'bwenv'), 'bwenv', 'bwenv', version);
    const binaryPath = path.join(toolDir, 'bwenv');
    await fsp.chmod(binaryPath, '755');

    core.addPath(toolDir);
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
