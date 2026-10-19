// Copies shared protocol code (src/protocol, src/network, tests/network) into the server repo.
// Usage: node scripts/sync-protocol.mjs <server-repo-path> [--check]
import { cpSync, readdirSync, readFileSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const [target, flag, ...rest] = process.argv.slice(2);
if (!target || (flag && flag !== '--check') || rest.length) { console.error('usage: sync-protocol.mjs <server-repo-path> [--check]'); process.exit(2); }
const source = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destination = resolve(target);
if (!existsSync(join(destination, 'package.json'))) { console.error('not a repo: ' + destination); process.exit(2); }
const shared = ['src/protocol', 'src/network', 'tests/network'];
const list = dir => existsSync(dir) ? readdirSync(dir, { recursive: true, withFileTypes: true }).filter(e => e.isFile()).map(e => relative(dir, join(e.parentPath, e.name)).split(sep).join('/')).sort() : [];
// Compare ignoring CRLF: git checkouts convert line endings per worktree.
const text = file => readFileSync(file).toString('latin1').replaceAll('\r\n', '\n');

const drift = [];
for (const dir of shared) {
  const from = join(source, dir), to = join(destination, dir);
  const a = list(from), b = list(to);
  for (const file of new Set([...a, ...b])) if (!a.includes(file) || !b.includes(file) || text(join(from, file)) !== text(join(to, file))) drift.push(`${dir}/${file}`);
}
if (flag === '--check') {
  if (drift.length) { console.error('protocol drift:\n' + drift.join('\n')); process.exit(1); }
  console.log('protocol in sync'); process.exit(0);
}
for (const dir of shared) { rmSync(join(destination, dir), { recursive: true, force: true }); mkdirSync(dirname(join(destination, dir)), { recursive: true }); cpSync(join(source, dir), join(destination, dir), { recursive: true }); }
console.log(drift.length ? `synced ${drift.length} changed files` : 'already in sync');
