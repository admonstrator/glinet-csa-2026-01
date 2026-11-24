// Turns a list of suggestions into SQL for D1. The list stays outside the repository:
// its paths and fingerprints come from the reports.
//   node tools/suggestions-sql.mjs suggestions.json > suggestions.sql
//   npx wrangler d1 execute csa-2026-01 --remote --file=suggestions.sql
// The list is JSON: [{ "key": "kind path", "note": "why", "hashes": ["<sha256>", ...] }, ...],
// optionally with "by" (who or what made the suggestion) and "at" (ISO time). Each entry is
// checked as the dashboard checks a label. A key that is already suggested, or was
// declined, stays as it is; so does a key that already has a label: the dashboard shows
// the label, not the suggestion.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { SUGGESTIONS_TABLE, validLabel } from '../src/index.js';

export function suggestionsSql(list, { by = 'analysis of the reports', at = new Date().toISOString() } = {}) {
  if (!Array.isArray(list)) throw new Error('not a list');
  const q = (s) => "'" + String(s).replace(/'/g, "''") + "'";
  const lines = [SUGGESTIONS_TABLE + ';'];
  const keys = new Set();
  for (const s of list) {
    const bad = validLabel({ key: s.key, verdict: 'safe', note: s.note, hashes: s.hashes });
    if (bad) throw new Error(`${bad}: ${String(s.key).slice(0, 80)}`);
    if (keys.has(s.key)) throw new Error('twice: ' + s.key);
    keys.add(s.key);
    const who = s.by || by, when = s.at || at;
    if (!/^[\x20-\x7e]{1,80}$/.test(who) || Number.isNaN(Date.parse(when))) throw new Error('bad by or at: ' + s.key);
    lines.push(`INSERT OR IGNORE INTO suggestions (key, note, hashes, by, at) VALUES (${q(s.key)}, ${q(s.note)}, ${q(JSON.stringify(s.hashes))}, ${q(who)}, ${q(when)}) ;`);
  }
  return lines.join('\n') + '\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const file = process.argv[2];
  if (!file) { console.error('usage: node tools/suggestions-sql.mjs suggestions.json > suggestions.sql'); process.exit(2); }
  process.stdout.write(suggestionsSql(JSON.parse(readFileSync(file, 'utf8'))));
}
