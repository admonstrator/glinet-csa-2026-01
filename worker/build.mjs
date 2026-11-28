// Turns src/dashboard.html into src/dashboard.js, the module the worker imports.
// Run it after every change to the page:  node build.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const dir = new URL('./src/', import.meta.url);
// the list of known release files (tools/known-hashes.sh) goes into the page as it is
const known = JSON.stringify(JSON.parse(readFileSync(new URL('known-hashes.json', dir), 'utf8')));
const page = readFileSync(new URL('dashboard.html', dir), 'utf8');
if (!page.includes('/*KNOWN_HASHES*/{}')) throw new Error('dashboard.html has no place for the known hashes');
const html = page.replace('/*KNOWN_HASHES*/{}', () => known);
writeFileSync(
  new URL('dashboard.js', dir),
  '// Generated from dashboard.html by build.mjs. Do not edit; change the HTML and run "node build.mjs".\n' +
    `export const DASHBOARD = ${JSON.stringify(html)};\n`,
);
console.log(`dashboard.js written (${html.length} characters)`);

// The part of the page that shapes a report for counting, as a module of its own: the
// figures for the advisory (figures.js) count with this very code, so that the page and the
// dashboard can never count differently. It runs in the worker as it is, so it must not
// touch the document. Its SHA-256 goes with it: the worker reads all reports again when
// the counting changes.
const starts = page.split('\nconst ts = (s) =>').length - 1, ends = page.split('\nconst count = (rows, key) =>').length - 1;
if (starts !== 1 || ends !== 1) throw new Error('dashboard.html must have exactly one line "const ts = (s) =>" and one "const count = (rows, key) =>": they mark the code for shape.js');
const block = page.slice(page.indexOf('\nconst ts = (s) =>') + 1, page.indexOf('\nconst count = (rows, key) =>') + 1);
if (!block.startsWith('const ts = (s) =>')) throw new Error('dashboard.html: "const count = (rows, key) =>" comes before "const ts = (s) =>"');
writeFileSync(
  new URL('shape.js', dir),
  '// Generated from dashboard.html by build.mjs. Do not edit; change the HTML and run "node build.mjs".\n' +
    '// The code of the dashboard that shapes a report, from "const ts = (s) =>" up to "const count = (rows, key) =>".\n' +
    block +
    `export { shape, ts };\nexport const SHAPE_SHA256 = '${createHash('sha256').update(block).digest('hex')}';\n`,
);
console.log(`shape.js written (${block.length} characters)`);

// The page that explains a result of the script (csa.gl-i.net/2026-01/), the same way.
const result = readFileSync(new URL('result.html', dir), 'utf8');
writeFileSync(
  new URL('result.js', dir),
  '// Generated from result.html by build.mjs. Do not edit; change the HTML and run "node build.mjs".\n' +
    `export const RESULT = ${JSON.stringify(result)};\n`,
);
console.log(`result.js written (${result.length} characters)`);

// The fingerprints of the known release files once more, for the fingerprint check in
// index.js (POST .../lookup): the hashes only, sorted, without the names, since the
// answer names no source. A module, because the worker cannot import JSON as it is.
const hashes = Object.keys(JSON.parse(readFileSync(new URL('known-hashes.json', dir), 'utf8'))).sort();
if (!hashes.every((h) => /^[0-9a-f]{64}$/.test(h))) throw new Error('known-hashes.json has a key that is not a SHA-256');
writeFileSync(
  new URL('known.js', dir),
  '// Generated from known-hashes.json by build.mjs. Do not edit; change the JSON and run "node build.mjs".\n' +
    `export const KNOWN_RELEASE_HASHES = new Set(${JSON.stringify(hashes)});\n`,
);
console.log(`known.js written (${hashes.length} fingerprints)`);
