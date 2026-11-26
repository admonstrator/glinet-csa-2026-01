// Turns a list of files known as malware into SQL for D1, for the fingerprint check.
//   node tools/bad-hashes-sql.mjs bad-hashes.json > bad-hashes.sql
//   node tools/bad-hashes-sql.mjs --script ../gl-helper-triage.sh > bad-hashes.sql
//   npx wrangler d1 execute csa-2026-01 --remote --file=bad-hashes.sql
// The list is JSON: [{ "sha256": "<64 lowercase hex>", "note": "what it is", "answer": 0 or 1 }, ...],
// optionally with "by" (who) and "at" (ISO time). answer 1: the check answers known_bad;
// answer 0: the entry waits and counts as not known, but its counter runs. The note is
// for the maintainers and never sent. Loading an entry again changes its note, answer, by
// and at, and never its counter: that is how an entry is released (answer 0, later 1).
// --script reads the fingerprints that the script itself carries in public (GLH_SHAS,
// BD_INIT_SHA, BD_ULOGD_SHAS) and adds each with answer 1, so the first fill needs no list
// made by hand. A file name and --script can be given together.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BAD_HASHES_TABLE } from '../src/index.js';

const FIELDS = new Set(['sha256', 'note', 'answer', 'by', 'at']);

export function badHashesSql(list, { by = 'maintainers', at = new Date().toISOString() } = {}) {
  if (!Array.isArray(list)) throw new Error('not a list');
  const q = (s) => "'" + String(s).replace(/'/g, "''") + "'";
  const lines = [BAD_HASHES_TABLE + ';'];
  const seen = new Set();
  for (const e of list) {
    if (e === null || typeof e !== 'object' || Array.isArray(e)) throw new Error('an entry is not an object');
    const name = typeof e.sha256 === 'string' ? e.sha256.slice(0, 80) : '(no sha256)';
    for (const k of Object.keys(e)) if (!FIELDS.has(k)) throw new Error(`unknown field ${k.slice(0, 32)}: ${name}`);
    if (!(typeof e.sha256 === 'string' && /^[0-9a-f]{64}$/.test(e.sha256))) throw new Error('bad sha256 (64 lowercase hex characters): ' + name);
    if (!(typeof e.note === 'string' && /^[\x20-\x7e]{1,200}$/.test(e.note))) throw new Error('bad note (1 to 200 printable ASCII characters): ' + name);
    if (e.answer !== 0 && e.answer !== 1) throw new Error('bad answer (0 or 1): ' + name);
    if (seen.has(e.sha256)) throw new Error('twice: ' + name);
    seen.add(e.sha256);
    const who = e.by === undefined ? by : e.by, when = e.at === undefined ? at : e.at;
    if (!(typeof who === 'string' && /^[\x20-\x7e]{1,80}$/.test(who))) throw new Error('bad by: ' + name);
    if (!(typeof when === 'string' && /^[\x20-\x7e]{1,40}$/.test(when) && !Number.isNaN(Date.parse(when)))) throw new Error('bad at: ' + name);
    lines.push(
      `INSERT INTO bad_hashes (sha256, note, answer, by, at) VALUES (${q(e.sha256)}, ${q(e.note)}, ${e.answer}, ${q(who)}, ${q(when)}) ` +
        'ON CONFLICT (sha256) DO UPDATE SET note = excluded.note, answer = excluded.answer, by = excluded.by, at = excluded.at;',
    );
  }
  return lines.join('\n') + '\n';
}

// The fingerprints of known malware that gl-helper-triage.sh carries, as entries with
// answer 1. Throws when one of the three lists is missing or holds something else.
const SCRIPT_LISTS = [
  ['GLH_SHAS', 'gl-helper malware: a program or installer posted on the forum (GLH_SHAS in the script)'],
  ['BD_INIT_SHA', 'older backdoor: the changed /etc/init.d/urandom_seed (BD_INIT_SHA in the script)'],
  ['BD_ULOGD_SHAS', 'older backdoor: a loader /bin/ulogd as posted (BD_ULOGD_SHAS in the script)'],
];
export function scriptHashes(sh) {
  const out = [];
  for (const [name, note] of SCRIPT_LISTS) {
    const m = new RegExp(`^${name}=('([0-9a-f\\n]+)'|([0-9a-f]+))$`, 'm').exec(String(sh));
    const hashes = m ? (m[2] || m[3]).split('\n').filter(Boolean) : [];
    if (!hashes.length || !hashes.every((h) => /^[0-9a-f]{64}$/.test(h))) throw new Error(`${name} not found in the script, or not a list of SHA-256`);
    for (const h of hashes) out.push({ sha256: h, note, answer: 1, by: 'gl-helper-triage.sh' });
  }
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2), list = [];
  try {
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--script' && args[i + 1]) list.push(...scriptHashes(readFileSync(args[++i], 'utf8')));
      else if (!args[i].startsWith('-')) {
        const more = JSON.parse(readFileSync(args[i], 'utf8'));
        if (!Array.isArray(more)) throw new Error('not a list: ' + args[i]);
        list.push(...more);
      } else throw new Error('unknown option ' + args[i]);
    }
    if (!list.length) throw new Error('nothing to load');
    process.stdout.write(badHashesSql(list));
  } catch (e) {
    console.error(String((e && e.message) || e));
    console.error('usage: node tools/bad-hashes-sql.mjs [bad-hashes.json] [--script ../gl-helper-triage.sh] > bad-hashes.sql');
    process.exit(2);
  }
}
