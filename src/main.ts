import * as core from '@actions/core';
import * as tc from '@actions/tool-cache';
import * as ht from '@actions/http-client';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import * as child_process from 'node:child_process';

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

  switch (platform) {
    case 'darwin': {
      if (arch === 'x64') {
        return 'bwenv-x86_64-apple-darwin.zip';
      } else if (arch === 'arm64') {
        return 'bwenv-aarch64-apple-darwin.zip';
      }
      break;
    }
    case 'linux': {
      const libc = getLibcVersion();
      if (arch === 'x64' && libc === 'gnu') {
        return 'bwenv-x86_64-unknown-linux-gnu.zip';
      } else if (arch === 'x64' && libc === 'musl') {
        return 'bwenv-x86_64-unknown-linux-musl.zip';
      }
      break;
    }
  }

  throw new Error(`Unsupported platform/architecture: ${platform}/${arch}`);
}

function getReleaseURL(version = 'latest', binaryType?: string) {
  const _version = `v${version.replace('v', '')}`;
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
    const version = core.getInput('version', { required: false });

    const releaseURL = getReleaseURL(version);

    await downloadFile(releaseURL, path.join(__dirname, 'bwenv.zip')).then((archive) =>
      unzipArchive(archive, __dirname, true),
    );

    const toolDir = await tc.cacheFile(path.join(__dirname, 'bwenv'), 'bwenv', 'bwenv', version);

    core.addPath(toolDir);
  } catch (error) {
    // @ts-expect-error I don't care
    core.setFailed(error.message);
  }
}

run();
