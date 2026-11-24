// Excellent Books plugin launcher (Node, no npm dependencies).
//
// Installs the uv release pinned in uv-pins.json (next to this file, and ONLY that file) into the
// person's private data folder, verifies it on every start, and runs the connector with it:
//   uv run --frozen --no-dev --python-preference only-managed --python <.python-version>
//          --project <plugin root> <plugin root>/plugin_main.py
// Python, the virtual environment, the caches and Python's bytecode live in the data folder, never
// in the plugin folder (Codex replaces that on an update). stdout belongs to MCP: every message
// here goes to stderr.
// Design: docs/superpowers/specs/2026-11-23-chatgpt-codex-plugin-design.md (review point 4).
//
// What this protects against, and what it does not:
// - Every folder it uses lies below the person's own profile folder (%LOCALAPPDATA% or the home
//   folder) and is checked on every start: a plain folder, no link, junction or other redirect on
//   the way (its real path must be the expected one). A folder that fails is refused, never followed
//   and never removed. What else is checked, exactly:
//   macOS/Linux: each folder's owner is this user; the launcher's own folders are set to mode 0700,
//   the folders above them (~/.local, Library) must not be group- or world-writable. Contents that
//   were already in a folder before it was tightened are not re-checked (only uv itself is: by hash).
//   Windows: the access list (ACL) is NOT read. The folder is trusted because it is created inside
//   %LOCALAPPDATA% and inherits that folder's access list, which on a standard profile lets only the
//   person, SYSTEM and administrators in. A folder given other permissions by hand is not detected.
// - The uv program runs only after its SHA-256 matched the pin, and the file that is started is the
//   file that was hashed (same identity, checked right before the start).
// - A malicious program already running as the same Windows/macOS/Linux user is OUTSIDE this
//   guarantee: it could change this launcher, the plugin folder or the data folder directly.

import { spawn, execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PLUGIN_ROOT = path.dirname(HERE);
const APP = 'ExcellentBooksMCP-Plugin';
const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 120 * 1000;
// A start that sees another start's download hint waits this long at most, then downloads itself
// (correctness never depends on the hint). Short enough that the wait, its own download and uv's
// Python and package downloads all fit the host's 300 s startup limit (.mcp.json) - Astra recheck of
// ca91a3c: 150 s + 120 s left about 30 s for everything else.
const HINT_WAIT_MS = 60 * 1000;
// A hint older than this is ignored (never removed by anyone but its creator).
const HINT_FRESH_MS = HINT_WAIT_MS;
// A hint with no readable owner yet is being written; one older than this was abandoned mid-write.
const HINT_UNREADABLE_MS = 10 * 1000;
const HINT_MAX_BYTES = 4096;
// tmp-* folders older than this are removed at start: no install takes that long.
const LEFTOVER_MS = 60 * 60 * 1000;
const POLL_MS = 250;
export const LIMITS = { DOWNLOAD_TIMEOUT_MS, HINT_WAIT_MS, HINT_FRESH_MS, LEFTOVER_MS };
const MAX_REDIRECTS = 5;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const HEX64 = /^[0-9a-f]{64}$/;
// The tests' transport: a fake release on this computer. It allows plain http from a loopback start
// and refuses every address off this computer, so no test can reach the internet. Codex never sets it
// (the host passes its default environment plus the names in .mcp.json only).
const TEST_TRANSPORT = process.env.EBMCP_PLUGIN_TEST_TRANSPORT === '1';

class LaunchError extends Error {}

// Always exactly one line: a failure's line is the last thing written, so the host shows it.
function say(line) {
  process.stderr.write(`Excellent Books: ${String(line).replace(/\s+/g, ' ').trim()}\n`);
}

// --- where things live -----------------------------------------------------------------------

// The trusted root (the person's own profile folder) and the names below it.
export function dataPlace(env = process.env, platform = process.platform, home = os.homedir()) {
  if (platform === 'win32') {
    if (!env.LOCALAPPDATA || !path.isAbsolute(env.LOCALAPPDATA)) {
      throw new LaunchError('LOCALAPPDATA is not set, so there is no private data folder.');
    }
    return { root: env.LOCALAPPDATA, parts: [APP] };
  }
  if (!home || !path.isAbsolute(home)) throw new LaunchError('there is no home folder for the data folder.');
  if (platform === 'darwin') return { root: home, parts: ['Library', 'Application Support', APP] };
  return { root: home, parts: ['.local', 'state', APP] };
}

export function dataDir(env = process.env, platform = process.platform, home = os.homedir()) {
  const { root, parts } = dataPlace(env, platform, home);
  return path.join(root, ...parts);
}

function sameName(a, b) {
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function unsafe(dir) {
  return new LaunchError(`${dir} is not a private plain folder (a link, a redirect, or not yours); `
    + 'refusing to use it. Remove it and start again.');
}

// Walks root/parts[0]/parts[1]/... and returns the last folder, or null when `create` is false and a
// folder is missing. Folders from index `ownFrom` on are the launcher's own: created 0700 and kept so.
// Folders before it (~/.local, Library) may exist already but must be the person's and not writable
// by others.
export function secureDir(root, parts, ownFrom, { create = true } = {}) {
  let real;
  try {
    real = fs.realpathSync.native(root);
  } catch {
    throw new LaunchError(`${root} does not exist, so there is no private data folder.`);
  }
  let current = root;
  let expected = real;
  for (let i = 0; i < parts.length; i += 1) {
    current = path.join(current, parts[i]);
    expected = path.join(expected, parts[i]);
    let info;
    try {
      info = fs.lstatSync(current);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (!create) return null;
      try {
        fs.mkdirSync(current, { mode: 0o700 });
      } catch (made) {
        if (made.code !== 'EEXIST') throw made;
      }
      info = fs.lstatSync(current);
    }
    if (!info.isDirectory() || info.isSymbolicLink()) throw unsafe(current);
    let resolved;
    try {
      resolved = fs.realpathSync.native(current);
    } catch {
      throw unsafe(current);
    }
    if (!sameName(resolved, expected)) throw unsafe(current);
    if (process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && info.uid !== process.getuid()) throw unsafe(current);
      if (i >= ownFrom) {
        if ((info.mode & 0o777) !== 0o700) fs.chmodSync(current, 0o700);
      } else if (info.mode & 0o022) {
        throw unsafe(current);
      }
    }
  }
  return current;
}

export function platformKey() {
  return `${process.platform}-${process.arch}`;
}

function readPins() {
  let pins;
  try {
    pins = JSON.parse(fs.readFileSync(path.join(HERE, 'uv-pins.json'), 'utf8'));
  } catch {
    throw new LaunchError('the plugin package is damaged (uv-pins.json is missing or unreadable); reinstall it.');
  }
  const asset = pins && pins.assets && pins.assets[platformKey()];
  if (!asset) throw new LaunchError(`this computer (${platformKey()}) is not supported by the plugin.`);
  const ok = /^\d+\.\d+\.\d+$/.test(pins.uv_version || '')
    && typeof pins.base_url === 'string'
    && /^[A-Za-z0-9._-]+$/.test(asset.archive || '')
    && /\.(zip|tar\.gz)$/.test(asset.archive)
    && HEX64.test(asset.archive_sha256 || '') && HEX64.test(asset.exe_sha256 || '')
    && /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/.test(asset.member || '')
    && !asset.member.split('/').some((part) => part === '.' || part === '..');
  if (!ok) throw new LaunchError('the plugin package is damaged (uv-pins.json is not valid); reinstall it.');
  return { version: pins.uv_version, url: new URL(asset.archive, pins.base_url), ...asset };
}

// The Python the package was tested with (.python-version, "3.12" or "3.12.7").
export function pythonPin(root = PLUGIN_ROOT) {
  let text;
  try {
    text = fs.readFileSync(path.join(root, '.python-version'), 'utf8').trim();
  } catch {
    throw new LaunchError('the plugin package is damaged (.python-version is missing); reinstall it.');
  }
  if (!/^3\.\d{1,2}(\.\d{1,3})?$/.test(text)) {
    throw new LaunchError('the plugin package is damaged (.python-version is not valid); reinstall it.');
  }
  return text;
}

// --- verifying -------------------------------------------------------------------------------

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function identity(info) {
  return { dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs };
}

function sameIdentity(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs;
}

// Read-only: { state: 'ok' | 'missing' | 'bad', id }. 'ok' only for a regular file whose SHA-256,
// read through one open handle that is the file the path names, is the pin. Nothing is removed here.
// A file that exists but cannot be opened is 'bad' with `unreadable` (maybe only for a moment).
async function inspect(target, expected) {
  let before;
  try {
    before = await fsp.lstat(target);
  } catch (error) {
    if (error.code === 'ENOENT') return { state: 'missing' };
    throw error;
  }
  if (!before.isFile() || before.isSymbolicLink()) return { state: 'bad' };
  let handle;
  try {
    handle = await fsp.open(target, 'r');
  } catch (error) {
    if (error.code === 'ENOENT') return { state: 'missing' };
    return { state: 'bad', unreadable: true };
  }
  try {
    const info = await handle.stat();
    if (!info.isFile() || !sameIdentity(identity(info), identity(before))) return { state: 'bad' };
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    return hash.digest('hex') === expected ? { state: 'ok', id: identity(info) } : { state: 'bad' };
  } finally {
    await handle.close();
  }
}

// --- downloading -----------------------------------------------------------------------------

function allowed(url, allowLoopbackHttp) {
  if (TEST_TRANSPORT && !LOOPBACK.has(url.hostname)) return false;
  if (url.protocol === 'https:') return true;
  return allowLoopbackHttp && url.protocol === 'http:' && LOOPBACK.has(url.hostname);
}

function refusal(url) {
  if (url.protocol !== 'https:') {
    return `refused to download uv from a location that is not https (${url.protocol}//${url.host}).`;
  }
  return `refused to download uv from ${url.host}: the test transport allows only this computer.`;
}

function download(start) {
  // Plain http only in the test transport, and only when the release itself is on this computer.
  const allowLoopbackHttp = TEST_TRANSPORT && start.protocol === 'http:' && LOOPBACK.has(start.hostname);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => fail(new LaunchError('downloading uv took too long; check the internet connection and try again.')), DOWNLOAD_TIMEOUT_MS);
    let request = null;
    let done = false;
    function fail(error) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (request) request.destroy();
      reject(error);
    }
    function get(url, hops) {
      if (!allowed(url, allowLoopbackHttp)) {
        fail(new LaunchError(refusal(url)));
        return;
      }
      const client = url.protocol === 'https:' ? https : http;
      request = client.get(url, { headers: { 'user-agent': 'excellent-books-plugin-launcher' } }, (response) => {
        const status = response.statusCode || 0;
        if ([301, 302, 303, 307, 308].includes(status)) {
          // The superseded response is closed, not read: its body is never accepted.
          response.destroy();
          if (hops >= MAX_REDIRECTS || !response.headers.location) {
            fail(new LaunchError('the uv download was redirected too often.'));
            return;
          }
          let next;
          try {
            next = new URL(response.headers.location, url);
          } catch {
            fail(new LaunchError('the uv download was redirected to an invalid address.'));
            return;
          }
          get(next, hops + 1);
          return;
        }
        if (status !== 200) {
          response.destroy();
          fail(new LaunchError(`downloading uv failed (HTTP ${status}); try again later.`));
          return;
        }
        if (Number(response.headers['content-length'] || 0) > MAX_ARCHIVE_BYTES) {
          response.destroy();
          fail(new LaunchError('the uv download is larger than expected; refused.'));
          return;
        }
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          if (done) return;
          size += chunk.length;
          if (size > MAX_ARCHIVE_BYTES) {
            response.destroy();
            fail(new LaunchError('the uv download is larger than expected; refused.'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve(Buffer.concat(chunks));
        });
        response.on('error', (error) => fail(new LaunchError(`downloading uv failed (${error.code || 'connection lost'}); try again.`)));
      });
      request.on('error', (error) => fail(new LaunchError(`could not download uv from ${url.host} (${error.code || 'network error'}); check the internet connection and try again.`)));
    }
    get(start, 0);
  });
}

// --- unpacking -------------------------------------------------------------------------------

function tarProgram() {
  if (process.platform === 'win32') {
    // The system bsdtar reads zip; a GNU tar earlier on the PATH (Git for Windows) does not.
    const root = process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows';
    const tar = path.join(root, 'System32', 'tar.exe');
    if (!fs.existsSync(tar)) throw new LaunchError('Windows tar.exe was not found, so uv cannot be unpacked.');
    return tar;
  }
  for (const tar of ['/usr/bin/tar', '/bin/tar']) if (fs.existsSync(tar)) return tar;
  throw new LaunchError('tar was not found in /usr/bin or /bin, so uv cannot be unpacked.');
}

function run(program, args) {
  return new Promise((resolve, reject) => {
    execFile(program, args, { windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

// Every member name must stay inside the folder, use no '.' or empty parts, and the expected
// program must be listed exactly once (also counting a different-case spelling of it).
export function checkMembers(names, member) {
  let count = 0;
  for (const raw of names) {
    const name = raw.replace(/\r$/, '');
    if (!name) continue;
    const posix = name.replace(/\\/g, '/');
    const parts = posix.replace(/\/$/, '').split('/');
    if (posix.startsWith('/') || /^[A-Za-z]:/.test(posix)
        || parts.some((part) => part === '' || part === '.' || part === '..')) {
      throw new LaunchError('the uv archive holds a path outside its folder; refused.');
    }
    if (parts.join('/').toLowerCase() === member.toLowerCase()) count += 1;
  }
  if (count !== 1) {
    throw new LaunchError(count ? 'the uv archive lists the program more than once; refused.'
      : 'the uv archive does not hold the expected program; refused.');
  }
}

// Streams the one member out of the archive (tar -O: nothing is unpacked into a folder) into a new,
// exclusively created file, hashing it on the way. A link or other non-file member yields no bytes or
// the wrong ones, and fails the hash.
async function extractMember(tar, archive, zip, member, file) {
  const handle = await fsp.open(file, 'wx', 0o700);
  const hash = createHash('sha256');
  try {
    await new Promise((resolve, reject) => {
      const child = spawn(tar, [zip ? '-xOf' : '-xzOf', archive, member],
        { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
      let size = 0;
      let failed = false;
      let writing = Promise.resolve();
      child.stdout.on('data', (chunk) => {
        if (failed) return;
        size += chunk.length;
        if (size > MAX_ARCHIVE_BYTES) {
          failed = true;
          child.kill();
          reject(new LaunchError('the program in the uv archive is larger than expected; refused.'));
          return;
        }
        hash.update(chunk);
        child.stdout.pause();
        writing = writing.then(() => handle.write(chunk)).then(() => child.stdout.resume(), (error) => {
          failed = true;
          child.kill();
          reject(error);
        });
      });
      child.on('error', () => {
        if (!failed) {
          failed = true;
          reject(new LaunchError('could not unpack the uv archive; refused.'));
        }
      });
      child.on('close', (code) => {
        writing.then(() => {
          if (failed) return;
          if (code !== 0) reject(new LaunchError('could not unpack the uv archive; refused.'));
          else resolve();
        });
      });
    });
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

// --- installing ------------------------------------------------------------------------------
// Correctness needs no lock. The install folder is named after the pin: uv/<version>-<first 16 hex
// of the program's SHA-256> (the "plain" name), so launchers with different pins (x64 and ARM64 on
// one profile) never share a folder. Published folders are never renamed, moved or changed: at start
// the plain folder and then its suffixed siblings uv/<plain>-<16 hex>, in name order, are checked
// against the pin and the first valid one is used. When none is valid, the start installs in its own
// new folder, uv/tmp-<pid>-<random>: it downloads there, checks the archive's SHA-256, streams out
// the one program, checks its SHA-256, and publishes with one rename of that folder to the plain
// name, or, when that name exists (valid or not), to <plain>-<random>. Then it uses what it
// published. A start only ever runs a program it checked itself.
// uv/downloading-<plain> is only a HINT that saves parallel starts a second download: its creator
// makes it exclusively and removes it. Nobody else removes, moves or renames it. A start that finds a
// fresh hint whose owner is alive waits for a valid folder (HINT_WAIT_MS at most); an old or abandoned
// hint, or a wait that runs out, is ignored and the start downloads itself. No hard links anywhere.
// Cleanup at start, best effort: tmp-* folders older than LEFTOVER_MS. A published folder is NEVER
// removed, moved or renamed, even one whose program fails its check: a repair is published beside it
// (Astra recheck of ca91a3c: a delayed cleaner could delete a fresh repair that reused the name).

function pinFolder(pins) {
  return uvFolder(pins.version, pins.exe_sha256);
}

// The plain install folder name of a pin.
export function uvFolder(version, exeSha256) {
  return `${version}-${exeSha256.slice(0, 16)}`;
}

function programName() {
  return process.platform === 'win32' ? 'uv.exe' : 'uv';
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The tests stop a start at a named step, then kill it (a crash there) or let it go on (a race).
// Only with the test transport, which Codex never sets.
async function testPause(step) {
  if (!TEST_TRANSPORT || process.env.EBMCP_PLUGIN_TEST_PAUSE !== step) return;
  process.stderr.write(`Excellent Books: test pause at ${step}\n`);
  const resume = process.env.EBMCP_PLUGIN_TEST_RESUME;
  for (;;) {
    await sleep(50);
    if (resume && fs.existsSync(resume)) return;
  }
}

function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

// The published folders of this pin: the plain one first, then the suffixed ones in name order.
async function published(uvDir, plain) {
  let entries;
  try {
    entries = await fsp.readdir(uvDir);
  } catch {
    return [];
  }
  const suffixed = entries
    .filter((entry) => entry.startsWith(`${plain}-`) && /^[0-9a-f]{16}$/.test(entry.slice(plain.length + 1)))
    .sort();
  return entries.includes(plain) ? [plain, ...suffixed] : suffixed;
}

function folderIdentity(info) {
  return { dev: info.dev, ino: info.ino, mtimeMs: info.mtimeMs };
}

// The first published folder whose program is valid: { state: 'ok', target, id, failed }. Otherwise
// { state: 'absent' } (none published) or { state: 'bad', failed }. `failed` lists the folders whose
// program failed, for the cleanup; names in `skip` (failed before: a published folder never changes)
// are not read again. A redirected or foreign folder is refused (secureDir), never followed or moved.
async function installed(place, ownFrom, pins, uvDir, skip = new Set()) {
  const failed = [];
  let seen = false;
  for (const name of await published(uvDir, pinFolder(pins))) {
    seen = true;
    if (skip.has(name)) continue;
    const dir = secureDir(place.root, [...place.parts, 'uv', name], ownFrom, { create: false });
    if (!dir) continue;                             // removed since the listing
    const folder = folderIdentity(fs.lstatSync(dir));
    const target = path.join(dir, programName());
    const result = await inspect(target, pins.exe_sha256);
    if (result.state === 'ok') return { state: 'ok', target, id: result.id, failed };
    failed.push({ name, folder, unreadable: Boolean(result.unreadable) });
  }
  return seen ? { state: 'bad', failed } : { state: 'absent', failed };
}

async function taken(file) {
  try {
    await fsp.lstat(file);
    return true;
  } catch (error) {
    return error.code !== 'ENOENT';
  }
}

// Publishes this start's verified folder under a name nobody uses: the plain name when it is free,
// otherwise <plain>-<random>. Only this start's own folder is renamed; a published folder is never
// renamed, moved or replaced. Returns the published name.
async function publish(folder, uvDir, plain) {
  await testPause('rename');
  let failure = null;
  const names = [plain, ...Array.from({ length: 3 }, () => `${plain}-${randomBytes(8).toString('hex')}`)];
  for (const name of names) {
    const final = path.join(uvDir, name);
    if (await taken(final)) continue;
    try {
      await fsp.rename(folder, final);
      return name;
    } catch (error) {
      failure = error;                              // taken meanwhile, or refused: the next name
    }
  }
  throw new LaunchError(`could not put uv in place in ${uvDir} (${failure ? failure.code || 'error' : 'no free name'}); close Codex and try again.`);
}

async function install(pins, uvDir) {
  const temp = await fsp.mkdtemp(path.join(uvDir, `tmp-${process.pid}-`));
  try {
    if (process.platform !== 'win32') await fsp.chmod(temp, 0o700);
    const bytes = await download(pins.url);
    if (sha256(bytes) !== pins.archive_sha256) {
      throw new LaunchError('the downloaded uv archive failed its SHA-256 check; nothing was unpacked or run.');
    }
    const zip = pins.archive.endsWith('.zip');
    const archive = path.join(temp, zip ? 'archive.zip' : 'archive.tar.gz');
    await fsp.writeFile(archive, bytes, { mode: 0o600, flag: 'wx' });
    const tar = tarProgram();
    let listing;
    try {
      listing = await run(tar, [zip ? '-tf' : '-tzf', archive]);
    } catch {
      throw new LaunchError('could not read the uv archive; refused.');
    }
    checkMembers(listing.split('\n'), pins.member);
    const folder = path.join(temp, pinFolder(pins));
    await fsp.mkdir(folder, { mode: 0o700 });
    const program = path.join(folder, programName());
    const hash = await extractMember(tar, archive, zip, pins.member, program);
    await testPause('extracted');
    if (hash !== pins.exe_sha256) {
      throw new LaunchError('the program in the uv archive failed its SHA-256 check; nothing was run.');
    }
    if (process.platform !== 'win32') await fsp.chmod(program, 0o755);
    return await publish(folder, uvDir, pinFolder(pins));
  } finally {
    await fsp.rm(temp, { recursive: true, force: true }).catch(() => {});
  }
}

// tmp-* folders older than LEFTOVER_MS: an install is long over by then. Best effort.
async function removeLeftovers(uvDir) {
  let entries;
  try {
    entries = await fsp.readdir(uvDir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!/^tmp-/.test(entry)) continue;
    const folder = path.join(uvDir, entry);
    try {
      const info = await fsp.lstat(folder);
      if (Date.now() - info.mtimeMs <= LEFTOVER_MS) continue;
      if (info.isDirectory() && !info.isSymbolicLink()) {
        await fsp.rm(folder, { recursive: true, force: true });
      } else {
        await fsp.unlink(folder);
      }
    } catch {
      // gone already, or in use: the next start tries again
    }
  }
}

// True when this start created the hint, and so must remove it. Never throws.
function takeHint(hintPath) {
  let fd;
  try {
    fd = fs.openSync(hintPath, 'wx', 0o600);
  } catch {
    return false;
  }
  try {
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, time: Date.now() }));
  } catch {
    // an unreadable hint is ignored after HINT_UNREADABLE_MS
  } finally {
    fs.closeSync(fd);
  }
  return true;
}

// True while another start's hint says it is downloading: a small file, fresh, its owner alive.
// Only read here, never changed.
function hintBusy(hintPath) {
  let info;
  try {
    info = fs.lstatSync(hintPath);
  } catch {
    return false;
  }
  const age = Date.now() - info.mtimeMs;
  if (!info.isFile() || info.size > HINT_MAX_BYTES || age > HINT_FRESH_MS) return false;
  let body = null;
  try {
    body = JSON.parse(fs.readFileSync(hintPath, 'utf8'));
  } catch {
    // being written, or damaged
  }
  if (!body || typeof body !== 'object') return age < HINT_UNREADABLE_MS;
  return alive(body.pid);
}

export async function ensureUv(place, ownFrom) {
  const pins = readPins();
  const uvDir = secureDir(place.root, [...place.parts, 'uv'], ownFrom);
  const plain = pinFolder(pins);
  // Folders found failing are not read again while waiting: a published folder never changes.
  const skip = new Set();
  const check = async () => {
    const result = await installed(place, ownFrom, pins, uvDir, skip);
    for (const { name, unreadable } of result.failed) if (!unreadable) skip.add(name);
    return result;
  };
  const found = (result) => ({ pins, target: result.target, id: result.id });
  await removeLeftovers(uvDir);
  let checked = await check();
  if (checked.state === 'ok') return found(checked);
  const firstVerdict = checked.state;
  await testPause('judged');
  const hintPath = path.join(uvDir, `downloading-${plain}`);
  const deadline = Date.now() + HINT_WAIT_MS;
  let own = false;
  for (;;) {
    if (takeHint(hintPath)) {
      own = true;
      break;
    }
    // An old or abandoned hint, or a wait that ran out: download anyway, hint left alone.
    if (!hintBusy(hintPath) || Date.now() >= deadline) break;
    await sleep(POLL_MS);
    checked = await check();
    if (checked.state === 'ok') return found(checked);
  }
  try {
    if (own) {
      await testPause('hint');
      // Published while this start waited for the hint: nothing to download.
      checked = await check();
      if (checked.state === 'ok') return found(checked);
    }
    if (firstVerdict !== 'absent') say('the saved uv program failed its check; installing it again.');
    say(`downloading uv ${pins.version} (once; about 20 MB).`);
    const name = await install(pins, uvDir);
    // What this start published, checked again before it is used.
    const dir = secureDir(place.root, [...place.parts, 'uv', name], ownFrom, { create: false });
    const target = dir ? path.join(dir, programName()) : null;
    const result = target ? await inspect(target, pins.exe_sha256) : { state: 'missing' };
    if (result.state !== 'ok') throw new LaunchError('the installed uv program failed its check; nothing was run.');
    return { pins, target, id: result.id };
  } finally {
    if (own) {
      try {
        fs.rmSync(hintPath, { force: true });
      } catch {
        // left behind: later starts ignore it once it is old
      }
    }
  }
}

// --- running the connector -------------------------------------------------------------------

export function runCommand({ uv, root, data, lockHash, python, env }) {
  const clean = {};
  for (const [key, value] of Object.entries(env)) {
    const upper = key.toUpperCase();
    // uv and Python settings from the person's environment could point uv at other indexes or
    // folders, or Python at other code (PYTHONPATH, PYTHONHOME, PYTHONSTARTUP).
    if (upper.startsWith('UV_') || upper.startsWith('PYTHON') || upper === 'VIRTUAL_ENV') continue;
    clean[key] = value;
  }
  clean.UV_PROJECT_ENVIRONMENT = path.join(data, 'venv', lockHash);
  clean.UV_CACHE_DIR = path.join(data, 'uv-cache');
  clean.UV_PYTHON_INSTALL_DIR = path.join(data, 'python');
  clean.UV_NO_CONFIG = '1';
  // Bytecode goes to the data folder, never into the plugin's own ebmcp/ folder.
  clean.PYTHONPYCACHEPREFIX = path.join(data, 'pycache');
  clean.PYTHONNOUSERSITE = '1';
  return {
    command: uv,
    // --project, not --directory: the connector runs from the data folder, so the plugin folder
    // is never its working directory and Codex can replace it on an update. --python: uv does not
    // read the package's .python-version from there (it picked 3.14 in the first end-to-end run).
    args: ['run', '--frozen', '--no-dev', '--python-preference', 'only-managed', '--python', python,
      '--project', root, path.join(root, 'plugin_main.py')],
    cwd: data,
    env: clean,
  };
}

async function main() {
  const installOnly = process.argv.slice(2).includes('--install-only');
  const place = dataPlace();
  const ownFrom = place.parts.length - 1;
  const data = secureDir(place.root, place.parts, ownFrom);
  const python = pythonPin();
  const lockHash = sha256(Buffer.concat([
    await fsp.readFile(path.join(PLUGIN_ROOT, 'uv.lock')), Buffer.from(`\npython ${python}\n`),
  ])).slice(0, 12);
  // Every folder uv and Python will write to is checked (or made) before anything runs.
  for (const name of ['venv', 'uv-cache', 'python', 'pycache']) {
    secureDir(place.root, [...place.parts, name], ownFrom);
  }
  secureDir(place.root, [...place.parts, 'venv', lockHash], ownFrom, { create: false });
  const { pins, target, id } = await ensureUv(place, ownFrom);
  if (installOnly) {
    say(`uv ${pins.version} verified: ${target}`);
    return 0;
  }
  const command = runCommand({ uv: target, root: PLUGIN_ROOT, data, lockHash, python, env: process.env });
  // The file started is the file that was hashed: same identity, checked with nothing in between.
  let now;
  try {
    now = fs.lstatSync(target);
  } catch {
    now = null;
  }
  if (!now || !now.isFile() || now.isSymbolicLink() || !sameIdentity(identity(now), id)) {
    throw new LaunchError('the uv program changed after its check; nothing was run. Start again.');
  }
  const child = spawn(command.command, command.args,
    { stdio: 'inherit', env: command.env, cwd: command.cwd, windowsHide: true });
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    try {
      process.on(signal, () => child.kill(signal));
    } catch {
      // not available on this system
    }
  }
  return new Promise((resolve) => {
    child.on('error', (error) => {
      say(`could not start the connector (${error.code || error.message}).`);
      resolve(1);
    });
    child.on('exit', (code, signal) => {
      resolve(code !== null ? code : 128 + (os.constants.signals[signal] || 1));
    });
  });
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    const invoked = fs.realpathSync(process.argv[1]);
    const self = fs.realpathSync(fileURLToPath(import.meta.url));
    return process.platform === 'win32' ? invoked.toLowerCase() === self.toLowerCase() : invoked === self;
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main().then(
    (code) => process.exit(code),
    (error) => {
      say(error instanceof LaunchError ? error.message : `could not start (${error.code || error.message}).`);
      process.exit(1);
    },
  );
}
