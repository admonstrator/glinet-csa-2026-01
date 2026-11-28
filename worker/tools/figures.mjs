// The figures for the advisory (docs/figures.md) from an export of the reports, worked out
// the way the worker works them out: through src/figures.js, folded in chunks of 500
// reports that overlap by 50, as the worker reads them with an overlap. as_of is the newest
// time of receipt in the export. To check the worker against a count by other means.
//   node tools/figures.mjs reports.ndjson > figures.json
// The export holds no ids; a report without a device ID then counts by its time of receipt
// and size, as on the dashboard. The size of the state and the time the fold took go to
// stderr.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { foldFigures, figuresOf } from '../src/figures.js';

// text: the export, one { received, report } per line
export function exportFigures(text, { chunk = 500, overlap = 50 } = {}) {
  const rows = [];
  let unreadable = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try { rows.push(JSON.parse(line)); } catch { unreadable++; }
  }
  const t0 = performance.now();
  let state = null, chunks = 0;
  for (let i = 0; ; i += chunk - overlap) {
    state = foldFigures(state, rows.slice(i, i + chunk));
    chunks++;
    if (i + chunk >= rows.length) break;
  }
  const ms = performance.now() - t0;
  const newest = rows.reduce((m, x) => Math.max(m, Date.parse(x.received)), -Infinity);
  return { figures: figuresOf(state, newest), state, rows: rows.length, unreadable, chunks, ms };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const file = process.argv[2];
  if (!file) { console.error('usage: node tools/figures.mjs reports.ndjson > figures.json'); process.exit(2); }
  const got = exportFigures(readFileSync(file, 'utf8'));
  process.stdout.write(JSON.stringify(got.figures, null, 2) + '\n');
  console.error(`${got.rows} reports${got.unreadable ? `, ${got.unreadable} unreadable lines left out` : ''}, ${got.chunks} chunks, fold ${got.ms.toFixed(0)} ms, state ${JSON.stringify(got.state).length} bytes as JSON (${got.state.dev.length} devices with an ID, ${got.state.one.length} reports without)`);
}
