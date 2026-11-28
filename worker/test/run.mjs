// node worker/test/run.mjs          run the tests
// node worker/test/run.mjs serve    serve the worker on 127.0.0.1:8787 with a KV and a D1 in memory
// node worker/test/run.mjs serve seed.json    the same, with marks and bad hashes for the
//                                             fingerprint check (see "serve" below)
import worker, { validate, validLabel, reportedTable, firstTraces, TRACE_SQL, REPORT_FIELDS, UPDATE_KEYS, LABELS_TABLE, BAD_HASHES_TABLE, badHashes, lookupRequest, markCache, kvMemo } from '../src/index.js';
import { suggestionsSql } from '../tools/suggestions-sql.mjs';
import { badHashesSql, scriptHashes } from '../tools/bad-hashes-sql.mjs';
import nodeCrypto from 'node:crypto';
import http from 'node:http';
import { execFileSync } from 'node:child_process';

import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
// The worker keeps KV values in memory for a minute; the tests change KV behind its back,
// so every change makes it forget.
const store = new (class extends Map { set(k, v) { kvMemo.clear(); return super.set(k, v); } delete(k) { kvMemo.clear(); return super.delete(k); } })(), meta = new Map();
// D1 as the worker sees it, backed by a real SQLite database with the real schema
function d1() {
  const db = new DatabaseSync(':memory:'); db.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  const stmt = (sql, args = []) => ({
    bind: (...a) => stmt(sql, a),
    run: async () => void db.prepare(sql).run(...args),
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    first: async (col) => { const r = db.prepare(sql).get(...args); return r ? (col ? r[col] : r) : null; },
  });
  return { prepare: (sql) => stmt(sql), batch: async (list) => { for (const s of list) await s.run(); }, raw: db };
}
const env = {
  EXPORT_TOKEN: 'test-token',
  REPORTS: {
    put: async (k, v, o) => { store.set(k, v); if (o && o.metadata) meta.set(k, o.metadata); },
    get: async (k) => store.get(k) ?? null,
    list: async ({ prefix }) => ({ keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name, metadata: meta.get(name) })), list_complete: true }),
  },
};
const good = {
  schema: 1, tool: '2.1', platform: 'openwrt', model: 'GL-AXT1800', firmware: '4.8.3',
  checked_at: '2026-11-21 16:40:00 UTC', uptime_s: 86400, ioc: 3, persist: 0, review: 2,
  findings: ['process', 'pipe /tmp/f', 'connection 170.39.226.0/24'], quick_check: false,
  shell_started: '2026-11-20 21:40:24 UTC', shell_ports: [42499], pipe_time: '',
};
const file = { path: '/etc/config/.gl/gl-helper', sha256: 'a'.repeat(64), size: 123456, mtime: '2026-11-20 21:40:30 UTC' };
const good2 = { ...good, schema: 2, tool: '2.2', state_file_time: '2026-11-20 22:15:18 UTC', files: [file] };
const good3 = {
  ...good2, schema: 3, tool: '2.3',
  persistence: [{ path: '/etc/rc.local', lines: ['/etc/config/.gl/gl-helper -d >/dev/null 2>&1 &'] }],
  fw_rules: ['nat: -A SDWAN_IP_MAPPING -d 127.0.0.1/32 -j DNAT --to-destination 127.0.0.1'],
  commands: ['sh -c iptables -t nat -A SDWAN_IP_MAPPING -d 127.0.0.1 -j DNAT --to-destination 127.0.0.1;(while true;do rm -f /tmp/f;done) "x" \\ &'],
};
const posted = [];
const call = (method, body, headers = {}, path = '/csa-2026-01-report') =>
  (method === 'POST' && path === '/csa-2026-01-report' && typeof body === 'string' && posted.push(body), 0) ||
  worker.fetch(new Request(`https://example.org${path}`, { method, body, headers }), env, { waitUntil() {} });

if (process.argv[2] === 'serve') {
  // With a D1 in memory and the fingerprint check switched on, so that the script can be
  // run against the real worker: point it at http://127.0.0.1:8787/csa-2026-01-report/lookup.
  // A seed file fills the check:
  //   { "labels": { "<kind> <path>": { "hashes": ["<sha256>", ...] } },
  //     "bad_hashes": [{ "sha256": "<sha256>", "answer": 1 }] }
  // each mark set as "probably safe", each entry checked as tools/bad-hashes-sql.mjs does.
  env.DB = d1(); env.LOOKUP = 'on';
  if (process.argv[3]) {
    const seed = JSON.parse(readFileSync(process.argv[3], 'utf8')), at = new Date().toISOString();
    env.DB.raw.exec(LABELS_TABLE);
    const put = env.DB.raw.prepare('INSERT OR REPLACE INTO labels (key, verdict, note, hashes, by, at) VALUES (?, ?, ?, ?, ?, ?)');
    for (const [key, l] of Object.entries(seed.labels || {})) {
      const label = { key, verdict: 'safe', note: (l && l.note) || 'seed', hashes: (l && l.hashes) || [] }, bad = validLabel(label);
      if (bad) throw new Error(`seed, label ${key.slice(0, 80)}: ${bad}`);
      put.run(key, 'safe', label.note, JSON.stringify(label.hashes), 'seed', at);
    }
    const bad = seed.bad_hashes || [];
    if (bad.length) env.DB.raw.exec(badHashesSql(bad.map((e) => ({ note: 'seed', by: 'seed', ...e }))));
    console.log(`seed: ${Object.keys(seed.labels || {}).length} marks, ${bad.length} bad hashes`);
  }
  // the newest report, as the KV entry looked: what serve printed before there was a D1
  const lastReport = () => { const r = env.DB.raw.prepare('SELECT received, report FROM reports ORDER BY received DESC, id DESC LIMIT 1').get(); return r ? JSON.stringify({ received: r.received, report: JSON.parse(r.report) }) : ''; };
  http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const r = await call(req.method, req.method === 'POST' ? Buffer.concat(chunks) : undefined, req.headers, req.url);
    const body = await r.text();
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(body);
    // the check: the answer (the worker itself logs nothing of a request)
    if (new URL(req.url, 'http://x').pathname.endsWith('/csa-2026-01-report/lookup')) console.log(`lookup ${r.status}\n${body}`);
    else if (req.method === 'POST') console.log(r.status, lastReport());
  }).listen(8787, '127.0.0.1');
  console.log('serving on http://127.0.0.1:8787/');
} else {
  let failed = 0;
  const expect = (name, ok) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}`); if (!ok) failed++; };
  // openapi.json: the schema Cloudflare checks a report against before the worker sees it.
  // It must let through every report the worker takes, or reports get lost unseen.
  const oas = JSON.parse(readFileSync(new URL('../openapi.json', import.meta.url), 'utf8')), top = oas.components.schemas.Report;
  const fits = (s, v) => {
    if (s.$ref) s = oas.components.schemas[s.$ref.split('/').pop()];
    if (s.enum) return s.enum.includes(v);
    if (s.type === 'string') return typeof v === 'string' && v.length <= s.maxLength && new RegExp(s.pattern).test(v);
    if (s.type === 'integer') return Number.isInteger(v) && v >= s.minimum && v <= s.maximum;
    if (s.type === 'boolean') return typeof v === 'boolean';
    if (s.type === 'array') return Array.isArray(v) && v.length <= s.maxItems && v.every((x) => fits(s.items, x));
    if (s.type === 'object') return v !== null && typeof v === 'object' && !Array.isArray(v) && s.required.every((k) => k in v) && Object.keys(v).every((k) => k in s.properties && fits(s.properties[k], v[k]));
    return false;
  };
  globalThis.fitsOpenApi = (v) => fits(top, v);
  expect('the schema for Cloudflare knows every field of a report and every schema version', Object.keys(top.properties).sort().join() === [...REPORT_FIELDS].sort().join() && top.properties.schema.enum.every((n) => validate({ ...good, schema: n }) !== 'bad or missing field schema') && validate({ ...good, schema: top.properties.schema.enum.length + 1 }) === 'bad or missing field schema');
  const v10 = { ...good3, schema: 10, device_id: '', goodcloud: 'on', cloud_client: '', astrowarp: 'off', state_file_size: -1, review_items: [], cloud_bound: 'unknown', rtty_ssh: 'off', rtty_web: 'off', note: '', state_file_first: '', vendor_cleanup: 'on', files: [{ ...file, ctime: file.mtime }] };
  expect('schema 10 says whether the firmware cleans up by itself; the worker and the schema for Cloudflare both take it', validate(v10) === null && fits(top, v10) && validate({ ...v10, vendor_cleanup: 'yes' }) !== null && !fits(top, { ...v10, vendor_cleanup: 'yes' }) && validate((({ vendor_cleanup, ...r }) => r)(v10)) !== null);
  expect('it lets the reports of schema 1, 2 and 3 through', fits(top, good) && fits(top, good2) && fits(top, good3));
  expect('it stops an unknown field, a missing one, markup and a wrong type', !fits(top, { ...good, hostname: 'x' }) && !fits(top, { ...good, tool: undefined }) && !fits(top, (({ ioc, ...r }) => r)(good)) && !fits(top, { ...good, model: '<script>' }) && !fits(top, { ...good, ioc: '3' }) && !fits(top, { ...good2, files: [{ ...file, extra: 1 }] }));
  expect('a complete report is valid', validate(good) === null);
  expect('stores a good report', (await call('POST', JSON.stringify(good), { 'cf-connecting-ip': '203.0.113.9' })).status === 200 && store.size === 2);
  expect('stored value has only the report and a time', (() => { const v = JSON.parse([...store.values()][0]); return Object.keys(v).join() === 'received,report' && !JSON.stringify(v).includes('203.0.113.9'); })());
  expect('refuses an unknown field', (await call('POST', JSON.stringify({ ...good, hostname: 'x' }))).status === 400);
  expect('refuses a missing field', (await call('POST', JSON.stringify({ ...good, model: undefined }))).status === 400);
  expect('refuses odd characters', (await call('POST', JSON.stringify({ ...good, model: '<script>' }))).status === 400);
  expect('refuses a long list', (await call('POST', JSON.stringify({ ...good, findings: Array(41).fill('x') }))).status === 400);
  expect('refuses a large body', (await call('POST', 'x'.repeat(50000))).status === 413);
  expect('a schema 3 report is valid', validate(good3) === null && validate({ ...good3, persistence: [], fw_rules: [], commands: [] }) === null);
  expect('schema 2 must not carry schema 3 fields', validate({ ...good2, commands: [] }) !== null);
  expect('refuses control characters in free text', validate({ ...good3, commands: ['a\u0007b'] }) !== null && validate({ ...good3, fw_rules: ['a\nb'] }) !== null);
  expect('refuses non-ASCII in free text', validate({ ...good3, commands: ['caf\u00e9'] }) !== null);
  expect('refuses long lines and long lists', validate({ ...good3, fw_rules: ['x'.repeat(301)] }) !== null && validate({ ...good3, persistence: [{ path: '/x', lines: Array(61).fill('a') }] }) !== null && validate({ ...good3, persistence: [{ path: '/etc/rc.local', lines: Array(60).fill('a') }] }) === null);
  expect('refuses an extra field in a persistence entry', validate({ ...good3, persistence: [{ path: '/x', lines: [], mode: 1 }] }) !== null);
  expect('a schema 2 report is valid', validate(good2) === null && validate({ ...good2, files: [] }) === null);
  expect('schema 1 must not carry schema 2 fields', validate({ ...good, files: [] }) !== null);
  expect('schema 2 needs its fields', validate({ ...good, schema: 2 }) !== null);
  expect('refuses a bad hash', validate({ ...good2, files: [{ ...file, sha256: 'xyz' }] }) !== null);
  expect('refuses an extra field in a file', validate({ ...good2, files: [{ ...file, content: 'x' }] }) !== null);
  expect('refuses more than 12 files', validate({ ...good2, files: Array(13).fill(file) }) !== null);
  expect('refuses text that is not JSON', (await call('POST', 'hello')).status === 400);
  expect('nothing but the good report and the marker was stored', store.size === 2 && store.has('meta/csa-2026-01-latest'));
  expect('export needs the token', (await call('GET', undefined, {}, '/csa-2026-01-report/export')).status === 404);
  const exp = await call('GET', undefined, { authorization: 'Bearer test-token' }, '/csa-2026-01-report/export');
  expect('export returns the report', exp.status === 200 && (await exp.text()).includes('GL-AXT1800'));
  expect('GET explains the address', (await (await call('GET')).text()).includes('anonymous reports'));

  // dashboard: only with a valid Cloudflare Access token
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', publicKey)), kid: 'k1' };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u) => new Response(JSON.stringify({ keys: String(u).startsWith('https://team.cloudflareaccess.com/') ? [jwk] : [] }));
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const token = async (claims, key = privateKey) => {
    const data = `${enc({ alg: 'RS256', kid: 'k1' })}.${enc(claims)}`;
    return `${data}.${Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, Buffer.from(data))).toString('base64url')}`;
  };
  const claims = { iss: 'https://team.cloudflareaccess.com', aud: ['aud-1'], exp: Date.now() / 1000 + 600, email: 'a@example.org' };
  const dash = (jwt, path = '/csa-2026-01-report/dashboard') => call('GET', undefined, jwt ? { 'cf-access-jwt-assertion': jwt } : {}, path);
  expect('dashboard does not exist while Access is not configured', (await dash(await token(claims))).status === 404);
  env.ACCESS_TEAM_DOMAIN = 'team.cloudflareaccess.com'; env.ACCESS_AUD = 'aud-1';
  expect('dashboard without a token: not found', (await dash()).status === 404);
  expect('dashboard with a valid token', (await dash(await token(claims))).status === 200);
  expect('wrong audience is refused', (await dash(await token({ ...claims, aud: ['other'] }))).status === 404);
  expect('expired token is refused', (await dash(await token({ ...claims, exp: Date.now() / 1000 - 5 }))).status === 404);
  expect('wrong issuer is refused', (await dash(await token({ ...claims, iss: 'https://evil.example' }))).status === 404);
  const other = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  expect('token signed with another key is refused', (await dash(await token(claims, other.privateKey))).status === 404);
  const forged = (await token(claims)).split('.'); forged[0] = enc({ alg: 'none', kid: 'k1' });
  expect('alg none is refused', (await dash(forged.join('.'))).status === 404);
  const data = await dash(await token(claims), '/csa-2026-01-report/dashboard/data');
  expect('data needs the token too', (await dash(undefined, '/csa-2026-01-report/dashboard/data')).status === 404);
  const first = (await data.json()).items[0];
  expect('data returns the reports, each with an id', data.status === 200 && first.report.model === 'GL-AXT1800' && first.id.startsWith('csa-2026-01/'));
  // live view
  const tok = await token(claims), live = (path) => dash(tok, '/csa-2026-01-report/dashboard/' + path);
  expect('latest needs the token', (await dash(undefined, '/csa-2026-01-report/dashboard/latest')).status === 404);
  const mark = (await (await live('latest')).json()).latest;
  expect('latest gives the time of the newest report', mark === first.received);
  expect('nothing is newer than the newest', (await (await live('data?since=' + mark)).json()).items.length === 0);
  await new Promise((r) => setTimeout(r, 5));
  await call('POST', JSON.stringify({ ...good, model: 'GL-MT6000' }));
  const fresh = (await (await live('data?since=' + mark)).json()).items;
  expect('a new report shows up after "since", and only that one', fresh.length === 1 && fresh[0].report.model === 'GL-MT6000');
  expect('latest moves on', (await (await live('latest')).json()).latest === fresh[0].received);
  expect('a bad since is refused', (await live('data?since=yesterday')).status === 400);
  globalThis.fetch = realFetch;

  // the script, served from the worker
  const SH = (n) => '#!/bin/sh\n# version ' + n + '\n' + 'x'.repeat(1200);
  // the question about the newest commit carries the time, so that no cache can answer it
  const gh = { commit: 'a'.repeat(40), calls: 0, down: false };
  const before = globalThis.fetch;
  globalThis.fetch = async (u) => {
    gh.calls++;
    if (gh.down) return new Response('rate limited', { status: 403 });
    if (!gh.norefs && /^https:\/\/github\.com\/admonstrator\/glinet-csa-2026-01\.git\/info\/refs\?service=git-upload-pack&t=\d+$/.test(String(u)))
      return new Response(`001e# service=git-upload-pack\n0000015a${'f'.repeat(40)} HEAD\0multi_ack symref=HEAD:refs/heads/main\n003d${'e'.repeat(40)} refs/heads/feature\n003f${gh.commit} refs/heads/main\n0000`);
    if (gh.norefs && String(u).includes('/info/refs')) return new Response('slow down', { status: 429 });
    if (/^https:\/\/api\.github\.com\/repos\/admonstrator\/glinet-csa-2026-01\/commits\/main\?t=\d+$/.test(String(u)) && gh.api) return new Response(gh.commit + '\n');
    if (String(u) === `https://raw.githubusercontent.com/admonstrator/glinet-csa-2026-01/${gh.commit}/gl-helper-triage.sh`) return new Response(SH(gh.commit[0]));
    return new Response('not found', { status: 404 });
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const fix = (method = 'GET', path = '/csa-2026-01-fix') => worker.fetch(new Request(`https://example.org${path}`, { method }), env, ctx);
  const age = (ms) => { const v = JSON.parse(store.get('script/csa-2026-01-fix')); v.checked -= ms; store.set('script/csa-2026-01-fix', JSON.stringify(v)); store.delete('script/csa-2026-01-fix.tried'); };
  let r = await fix();
  expect('first download fetches the script from main', r.status === 200 && (await r.text()).startsWith('#!/bin/sh\n# version a') && r.headers.get('x-script-commit') === gh.commit);
  expect('it is not cached by clients', r.headers.get('cache-control') === 'no-store');
  const calls = gh.calls; await fix();
  expect('later downloads come from the store, no call to GitHub', gh.calls === calls);
  gh.commit = 'b'.repeat(40);
  r = await fix('POST', '/csa-2026-01-fix/refresh');
  expect('refresh within 30 seconds does nothing', (await r.text()).trim() === 'a'.repeat(40));
  age(31_000); r = await fix('POST', '/csa-2026-01-fix/refresh');
  expect('refresh picks up the new commit', r.status === 200 && (await r.text()).trim() === gh.commit && (await (await fix()).text()).includes('# version b'));
  gh.commit = 'c'.repeat(40); age(601_000); r = await fix(); await Promise.all(waits);
  expect('an old copy is served at once and renewed in the background', (await r.text()).includes('# version b') && (await (await fix()).text()).includes('# version c'));
  gh.norefs = true; gh.commit = 'd'.repeat(40); age(31_000); r = await fix('POST', '/csa-2026-01-fix/refresh');
  expect('git’s way fails and nothing else answers: the copy stays, and the answer says why', (await r.text()).trim() === 'c'.repeat(40) && /refs: 429.*api: 404/.test(r.headers.get('x-refresh-error') || '') && JSON.parse(store.get('script/csa-2026-01-fix')).commit === 'c'.repeat(40));
  gh.api = true; age(31_000); r = await fix('POST', '/csa-2026-01-fix/refresh');
  expect('git’s way fails: the commit comes from GitHub’s API', (await r.text()).trim() === gh.commit && !r.headers.get('x-refresh-error') && (await (await fix()).text()).includes('# version d'));
  gh.norefs = false; gh.api = false; gh.commit = 'c'.repeat(40); age(31_000); await fix('POST', '/csa-2026-01-fix/refresh');
  gh.down = true; age(601_000); r = await fix(); await Promise.all(waits);
  expect('GitHub down: the stored copy keeps being served', r.status === 200 && (await r.text()).includes('# version c') && (await fix()).status === 200);
  store.delete('script/csa-2026-01-fix'); r = await fix();
  expect('nothing stored and GitHub down: redirect to GitHub', r.status === 302 && r.headers.get('location').includes('raw.githubusercontent.com'));
  gh.down = false;
  expect('a report cannot be posted to the script address', (await worker.fetch(new Request('https://example.org/csa-2026-01-fix', { method: 'POST', body: JSON.stringify(good) }), env, ctx)).status === 405);
  expect('the stored script is not listed as a report', !(await (await call('GET', undefined, { authorization: 'Bearer test-token' }, '/csa-2026-01-report/export')).text()).includes('#!/bin/sh'));
  expect('reports still work', (await call('POST', JSON.stringify(good))).status === 200);
  {
    const before = store.size;
    const elsewhere = await Promise.all(['/', '/x', '/csa-2026-01-report/x', '/csa-2026-01-reports', '/2026-01/'].map((p) => call('POST', JSON.stringify(good), {}, p)));
    expect('a report sent to any other address is refused and not stored', elsewhere.every((r) => r.status === 405) && store.size === before);
    expect('the report address with a trailing slash still works', (await call('POST', JSON.stringify(good), {}, '/csa-2026-01-report/')).status === 200);
  }
  globalThis.fetch = before;

  // device id (schema 4)
  const good4 = { ...good3, schema: 4, tool: '2.9', device_id: '0123456789abcdef' };
  const lastReport = () => JSON.parse([...store.entries()].filter(([k]) => k.startsWith('csa-2026-01/')).at(-1)[1]).report;
  expect('a schema 4 report is valid, with or without an id', validate(good4) === null && validate({ ...good4, device_id: '' }) === null);
  expect('refuses a device id that is not 16 hex characters', validate({ ...good4, device_id: 'aa:bb:cc:dd:ee:ff' }) !== null && validate({ ...good4, device_id: '0123456789ABCDEF' }) !== null);
  expect('schema 3 must not carry a device id', validate({ ...good3, device_id: '' }) !== null);
  // ctime of the files (schema 5)
  const good5 = { ...good4, schema: 5, tool: '2.13', files: [{ ...file, ctime: '2026-11-20 21:40:31 UTC' }] };
  expect('a schema 5 report is valid, with or without a ctime', validate(good5) === null && validate({ ...good5, files: [{ ...file, ctime: '' }] }) === null);
  expect('schema 5 needs the ctime, schema 4 must not carry it', validate({ ...good5, files: [file] }) !== null && validate({ ...good4, files: good5.files }) !== null);
  expect('refuses a ctime that is not a time', validate({ ...good5, files: [{ ...file, ctime: '<b>' }] }) !== null);
  // the dashboard's own script must at least parse: a syntax error leaves an empty page
  { const { DASHBOARD } = await import('../src/dashboard.js'); let ok = true; try { for (const m of DASHBOARD.matchAll(/<script>([\s\S]*?)<\/script>/g)) new Function(m[1]); } catch { ok = false; } expect('the dashboard script parses', ok); }
  // the layout of the dashboard: templates, a saved layout made whole, the layout of before taken over
  { const { DASHBOARD } = await import('../src/dashboard.js'); const m = /\/\* layout:begin \*\/([\s\S]*?)\/\* layout:end \*\//.exec(DASHBOARD);
    const { PAGES, TPL, tplItems, normalize, migrate } = new Function(m[1] + '\nreturn { PAGES, TPL, tplItems, normalize, migrate };')();
    const keys = (t) => tplItems(t).map((i) => i.k).sort().join();
    expect('every template has the same cards, each once, inside the grid', Object.keys(TPL).every((t) => keys(t) === keys('standard') && new Set(tplItems(t).map((i) => i.k)).size === tplItems(t).length && tplItems(t).every((i) => i.w >= 2 && i.w <= 12 && i.h >= 2 && i.h <= 16 && PAGES.some((p) => p[0] === i.p))));
    const fresh = normalize(null), n = fresh.items.length;
    expect('without a saved layout: the standard template', fresh.tpl === 'standard' && !fresh.custom && JSON.stringify(fresh.items) === JSON.stringify(tplItems('standard')) && fresh.hidden.length === 0);
    const kept = normalize({ tpl: 'compact', custom: true, items: [{ k: 'reports', p: 'overview', w: 30, h: 1 }, { k: 'gone', p: 'overview', w: 4, h: 4 }, { k: 'when', p: 'nowhere', w: 5.4, h: 'x' }], hidden: ['ports', 'gone'] });
    const at = (l, k) => l.items.find((i) => i.k === k);
    expect('a saved layout: unknown cards out, new cards in, sizes inside the grid', kept.tpl === 'compact' && kept.custom && kept.items.length === n && !at(kept, 'gone') && at(kept, 'reports').p === 'overview' && at(kept, 'reports').w === 12 && at(kept, 'reports').h === 2 && at(kept, 'when').p === 'overview' && at(kept, 'when').w === 5 && at(kept, 'when').h === 5 && JSON.stringify(kept.hidden) === '["ports"]');
    expect('cards stay grouped by page in page order', kept.items.map((i) => PAGES.findIndex((p) => p[0] === i.p)).every((x, i, a) => !i || a[i - 1] <= x) && kept.items.filter((i) => i.p === 'overview').at(-1).k === 'again' && kept.items[0].k === 'reports');
    const plain = normalize({ tpl: 'large', custom: false, items: [{ k: 'when', p: 'overview', w: 3, h: 3 }], hidden: ['ports'] });
    expect('a saved layout nobody changed: its template as it is now, hidden cards kept', plain.tpl === 'large' && !plain.custom && JSON.stringify(plain.items) === JSON.stringify(tplItems('large')) && JSON.stringify(plain.hidden) === '["ports"]');
    const old = migrate({ order: ['Reports', 'Is it still going on', 'Ports of the remote shells', 'Malware files', 'When it started', 'What each kind of evidence means'], hidden: ['Ports of the remote shells', 'What each kind of evidence means'], sizes: { 'When it started': 'half', 'Models and firmware': 'full', 'Devices': 'odd' } });
    const ov = old.items.filter((i) => i.p === 'overview').map((i) => i.k).join(' '), atk = old.items.filter((i) => i.p === 'attack').map((i) => i.k).join(' ');
    expect('the layout of before: its order on each page, its hidden cards and widths', ov === 'total hit shell back restart gc going when course healed days again' && atk === 'evidence ports files left' && JSON.stringify(old.hidden) === '["ports"]' && at(old, 'when').w === 6 && at(old, 'matrix').w === 12 && at(old, 'devices').w === 4 && old.custom && old.items.length === n);
    expect('nothing to take over: the standard template', JSON.stringify(migrate(null).items) === JSON.stringify(fresh.items) && !migrate('x').custom); }
  // the list of known release files is built into the page, and every entry is a SHA-256 with a name
  { const { DASHBOARD } = await import('../src/dashboard.js'); const m = /const KNOWN = (\{.*?\});/.exec(DASHBOARD); let known = {}; try { known = JSON.parse(m[1]); } catch { /* stays empty */ }
    expect('the known release files are in the built page', !DASHBOARD.includes('/*KNOWN_HASHES*/') && Object.keys(known).length > 100 && Object.entries(known).every(([h, n]) => /^[0-9a-f]{64}$/.test(h) && /^[\w .,-]{5,80}$/.test(n))); }
  // the page that explains a result: served to anyone, the same for everyone, with the
  // version of the script that is served now; its texts are complete in every language
  {
    const { RESULT } = await import('../src/result.js');
    let ok = true; try { for (const m of RESULT.matchAll(/<script>([\s\S]*?)<\/script>/g)) new Function(m[1]); } catch { ok = false; }
    expect('the result page\'s script parses', ok);
    const pick = (name, end) => { const i = RESULT.indexOf(`const ${name} = {`), j = RESULT.indexOf(end, i); return new Function('GC_OFF', 'return ' + RESULT.slice(i + `const ${name} = `.length, j + 2))('x'); };
    const T = pick('T', '\n};\n'), NAMES = pick('NAMES', '\n};\n'), PLAN = pick('PLAN', '\n};\n');
    const keys = (o) => Object.keys(o).sort().join(' '), langs = Object.keys(T);
    expect('the result page has English, German and Chinese', keys(T) === 'de en zh');
    expect('every language has the same results, findings, steps and choices', langs.every((l) => ['results', 'kinds', 'steps', 'pickItems', 'dev', 'gc', 'rs'].every((part) => keys(T[l][part]) === keys(T.en[part])) && keys(T[l]) === keys(T.en)));
    expect('no text is empty or left in a half-written state', langs.every((l) => JSON.stringify(T[l]).length > 5000 && !/TODO|undefined|""/.test(JSON.stringify(T[l]))));
    expect('every finding code has a name and a text', keys(T.en.kinds) === keys(NAMES));
    const steps = new Set(Object.values(PLAN).flatMap((p) => Object.values(p).flat()));
    expect('every step of every plan has a text, and every result has a plan', [...steps].every((s) => s === 'gc' || T.en.steps[s]) && ['router', 'kvm'].every((p) => keys(PLAN[p]) === keys(T.en.results)));
    // the script's own table of codes: each one must be known to the page
    const sh = readFileSync(new URL('../../gl-helper-triage.sh', import.meta.url), 'utf8'), table = (/^RESULT_CODES='([^']+)'$/m.exec(sh) || [])[1];
    if (table) expect('every code the script can put into the address is known to the page', table.split(' ').every((x) => NAMES[x.split('=')[1]]) && new Set(table.split(' ').map((x) => x.split('=')[1])).size === table.split(' ').length);
    // the nine-character code: read the page's own functions and try them
    const src = RESULT.slice(RESULT.indexOf('const B32 = '), RESULT.indexOf('function read() {'));
    const { decode, encode, parse, ORDER, MODELS, encodeExt, fwState } = new Function(src + '; return { decode, encode, parse, ORDER, MODELS, encodeExt, fwState };')();
    const sample = { minor: 41, p: 'r', k: ['cc', 'fw'], g: '1', n: '0', f: '0', rv: 4 }, code = encode(sample), back = decode(code);
    expect('a code is nine characters and comes back as the result it was made from', /^[0-9A-HJKMNP-TV-Z]{9}$/.test(code) && back.v === '2.41' && back.p === 'r' && back.k.join('.') === 'fw.cc' && back.g === '1' && back.n === '0' && back.f === '0' && back.rv === -1);
    expect('capitals, dashes and spaces do not matter, and a typed O, I or L is read as 0 or 1', decode(code.toLowerCase()) !== null && decode(code.slice(0, 4) + '-' + code.slice(4) + ' ') !== null && decode(encode({ ...sample, minor: 32 }).replace(/0/g, 'o').replace(/1/g, 'l')) !== null);
    const others = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; let caught = 0, tried = 0;
    for (let i = 0; i < 9; i++) for (const ch of others) { if (ch === code[i]) continue; tried++; if (decode(code.slice(0, i) + ch + code.slice(i + 1)) === null) caught++; }
    expect('a single wrong character is caught in at least 98 of 100 cases', caught / tried >= 0.98);
    let swaps = 0, swapped = 0; for (let i = 0; i < 8; i++) { if (code[i] === code[i + 1]) continue; swaps++; if (decode(code.slice(0, i) + code[i + 1] + code[i] + code.slice(i + 2)) === null) swapped++; }
    expect('two neighbouring characters typed the wrong way round are caught', swaps > 0 && swapped === swaps);
    expect('every kind of finding has its place in the code, each once', ORDER.length <= 24 && new Set(ORDER).size === ORDER.length && ORDER.every((k) => NAMES[k]));
    const all = decode(encode({ minor: 127, p: 'k', k: ORDER, g: '0', n: '1', f: '3', rv: 1 }));
    expect('the largest code holds everything', all.v === '2.127' && all.p === 'k' && all.k.length === ORDER.length && all.g === '0' && all.n === '1' && all.f === '3');
    expect('the page reads a code after "#", a code typed as the path, and the long form of 2.39', parse('#' + code, '/').k.length === 2 && parse('', '/' + code.toLowerCase()).v === '2.41' && parse('#v=2.39&p=r&r=a&k=cc.fw&g=1&n=0', '/2026-01/').k.join('.') === 'cc.fw');
    expect('nothing in the address is the list to tick, a wrong code says so', parse('', '/').v === '' && !parse('', '/').bad && !parse('', '/2026-01/').bad && parse('#' + code.slice(0, 8) + (code[8] === 'A' ? 'B' : 'A'), '/').bad === true && parse('#%3Cscript%3Ealert(1)', '/').v === '');
    // the second part of the code: model and firmware version
    const ext = encodeExt({ model: 'mt6000', ver: [4, 9, 1], test: false }, code[8]), longer = decode(code + '-' + ext);
    expect('the longer code adds the model and its firmware version, the short one still works', ext.length === 5 && longer.dev.model === 'mt6000' && longer.dev.ver.join('.') === '4.9.1' && longer.dev.test === false && longer.k.join('.') === 'fw.cc' && decode(code).dev.model === undefined);
    expect('a slip in the second part is caught too, and it belongs to its first part', decode(code + ext.slice(0, 4) + (ext[4] === 'A' ? 'B' : 'A')) === null && decode(encode({ ...sample, n: '1' }) + ext) === null && decode(code + ext.slice(0, 3)) === null);
    const kvm = decode(encode({ minor: 45, p: 'k', k: ['mk'], g: '1', n: '0', f: '0', rv: 0 }) + encodeExt({ model: 'rm1pe', ver: [1, 10, 2], test: true }, encode({ minor: 45, p: 'k', k: ['mk'], g: '1', n: '0', f: '0', rv: 0 })[8]));
    expect('a KVM with a test build comes back as such', kvm.dev.model === 'rm1pe' && kvm.dev.ver.join('.') === '1.10.2' && kvm.dev.test === true);
    const fwl = { asof: '2026-11-22 16:26 UTC', models: { mt6000: { r: ['4.8.3', '2026-08-01'], b: ['4.11.1', '2026-11-06'] }, be9300: { r: ['4.10.1', '2026-09-20'] } } };
    expect('the firmware list says: newer release, up to date, ahead, and names a newer beta', fwState({ model: 'mt6000', ver: [4, 7, 13] }, fwl).state === 'new' && fwState({ model: 'mt6000', ver: [4, 8, 3] }, fwl).state === 'ok' && fwState({ model: 'mt6000', ver: [4, 8, 3] }, fwl).beta[0] === '4.11.1' && fwState({ model: 'mt6000', ver: [4, 11, 1] }, fwl).state === 'ahead' && fwState({ model: 'mt6000', ver: [4, 11, 1] }, fwl).beta === null && fwState({ model: 'be9300', ver: [4, 10, 1] }, fwl).beta === null);
    expect('versions are compared as numbers, not as text (4.10 is newer than 4.9)', fwState({ model: 'be9300', ver: [4, 9, 12] }, fwl).state === 'new' && fwState({ model: 'be9300', ver: [4, 10, 2] }, fwl).state === 'ahead');
    expect('no model in the code, an unknown model or no list: nothing is said about firmware', fwState({}, fwl) === null && fwState({ model: 'zz9', ver: [1, 0, 0] }, fwl) === null && fwState({ model: 'mt6000', ver: [4, 8, 3] }, null) === null && fwState(undefined, fwl) === null);
    const shModels = (/^RESULT_MODELS='([^']+)'$/m.exec(readFileSync(new URL('../../gl-helper-triage.sh', import.meta.url), 'utf8')) || [])[1];
    if (shModels) expect('the script numbers the models in the same order as the page', shModels === MODELS.join(' ') && MODELS.length <= 127 && new Set(MODELS).size === MODELS.length);
    const shKinds = (/^RESULT_KINDS='([^']+)'$/m.exec(readFileSync(new URL('../../gl-helper-triage.sh', import.meta.url), 'utf8')) || [])[1];
    if (shKinds) expect('the script puts the kinds of findings into the code in the order of the page; the page may know more, at the end', (ORDER.join(' ') + ' ').startsWith(shKinds + ' '));
    const front = await worker.fetch(new Request('https://csa.example.org/'), env, { waitUntil() {} }), typed = await worker.fetch(new Request('https://csa.example.org/' + code), env, { waitUntil() {} });
    expect('on the csa host the page is the front door, also for a code typed without "#"', front.status === 200 && (await front.text()).includes('const B32') && typed.status === 200 && (await call('GET', undefined, {}, '/' + code)).headers.get('content-type').startsWith('text/plain'));
    console.log('sample code: ' + code + '-' + ext);
    // the firmware list: fetched from the archive, kept, put into the page; only what has
    // the expected shape gets in
    const netFetch = globalThis.fetch; let asked = 0, answer = 'fail';
    const archive = { mt6000: { release: { version: '4.8.3', release_time: '2026-08-01 10:00:00', download: 'https://x/' }, beta: { version: '4.11.1', release_time: '2026-11-06 18:44:00' } }, 'bad name!': { release: { version: '1.0.0', release_time: '2026-01-01' } }, evil: { release: { version: '</script><script>alert(1)', release_time: '2026-01-01' } }, be9300: { release: { version: '4.10.1', release_time: '2026-09-20 18:00:31' } }, a1: { release: { version: '4.0.0', release_time: '2026-01-01' } }, a2: { release: { version: '4.0.0', release_time: '2026-01-01' } }, a3: { release: { version: '4.0.0', release_time: '2026-01-01' } } };
    globalThis.fetch = async (u) => { if (String(u).startsWith('https://firmware.gl-i.net/')) { asked++; return answer === 'fail' ? new Response('no', { status: 503 }) : new Response(JSON.stringify(archive), { headers: { 'last-modified': 'Sun, 22 Nov 2026 16:26:50 GMT' } }); } return netFetch(u); };
    await env.REPORTS.put('firmware/list', 'null');
    expect('without the archive the page gets no firmware list and is served all the same', (await (await call('GET', undefined, {}, '/2026-01/')).text()).includes('const FIRMWARE = null;') && asked === 1);
    answer = 'ok';
    const withList = await (await call('GET', undefined, {}, '/2026-01/')).text(), put = (/const FIRMWARE = (\{.*?\});\n/.exec(withList) || [])[1], got = put ? JSON.parse(put) : null;
    expect('the list in the page holds release and beta per model, with the time of the archive', got && got.asof === '2026-11-22 16:26 UTC' && got.models.mt6000.r.join() === '4.8.3,2026-08-01' && got.models.mt6000.b[0] === '4.11.1' && got.models.be9300.b === undefined);
    expect('entries that do not look like a model and a version stay out', got && !('bad name!' in got.models) && !('evil' in got.models) && !withList.includes('alert(1)'));
    const again = asked; await call('GET', undefined, {}, '/2026-01/');
    expect('the list is kept: the next page does not ask the archive again', asked === again);
    const page = await call('GET', undefined, {}, '/2026-01/');
    const html = await page.text();
    expect('the result page is served without a login, as HTML that nothing may frame or extend', page.status === 200 && page.headers.get('content-type').startsWith('text/html') && /frame-ancestors 'none'/.test(page.headers.get('content-security-policy')) && html.includes('const T = {'));
    const long = await call('GET', undefined, {}, '/csa-2026-01/'), bare = await call('GET', undefined, {}, '/2026-01');
    expect('the long form and the form without the last slash lead to the short address', long.status === 302 && long.headers.get('location') === 'https://example.org/2026-01/' && bare.status === 302);
    expect('the result page takes no data', (await call('POST', '{}', {}, '/2026-01/')).status === 405);
    await env.REPORTS.put('script/csa-2026-01-fix', JSON.stringify({ commit: 'x', body: '#!/bin/sh\nVERSION=7.77\n', checked: Date.now() }));
    expect('the page is told the version of the script that is served now', (await (await call('GET', undefined, {}, '/2026-01/')).text()).includes("const CURRENT = '7.77'"));
    await env.REPORTS.put('script/csa-2026-01-fix', 'null');
    globalThis.fetch = netFetch;
  }
  const good6 = { ...good5, schema: 6, tool: '2.23', goodcloud: 'on', cloud_client: '1.2.3-4', astrowarp: 'off', state_file_size: 0, review_items: [{ kind: 'changed', path: '/etc/init.d/urandom_seed', sha256: 'b'.repeat(64) }, { kind: 'process', path: '', sha256: '' }] };
  expect('a schema 6 report is valid, also without a state file or review items', validate(good6) === null && validate({ ...good6, state_file_size: -1, review_items: [], goodcloud: 'unknown', cloud_client: '' }) === null);
  expect('schema 6 needs its fields, schema 5 must not carry them', validate({ ...good5, schema: 6 }) !== null && validate({ ...good5, review_items: [] }) !== null);
  expect('refuses review items with a description or with markup', validate({ ...good6, review_items: [{ kind: 'changed', path: '/x', sha256: '', detail: 'x' }] }) !== null && validate({ ...good6, review_items: [{ kind: 'changed', path: '<script>', sha256: '' }] }) !== null);
  expect('refuses more than 40 review items and an unknown GoodCloud state', validate({ ...good6, review_items: Array(41).fill(good6.review_items[0]) }) !== null && validate({ ...good6, goodcloud: 'maybe' }) !== null);
  // times of the review items (schema 7)
  const good7 = { ...good6, schema: 7, tool: '2.24', review_items: [{ kind: 'changed', path: '/etc/init.d/urandom_seed', sha256: 'b'.repeat(64), mtime: '2025-12-12 12:55:01 UTC', ctime: '2026-04-19 14:38:12 UTC' }, { kind: 'process', path: '', sha256: '', mtime: '', ctime: '' }] };
  expect('a schema 7 report is valid', validate(good7) === null);
  expect('schema 7 needs the times, schema 6 must not carry them', validate({ ...good7, review_items: good6.review_items }) !== null && validate({ ...good6, review_items: good7.review_items }) !== null);
  // bound to an account, remote access (schema 8)
  const good8 = { ...good7, schema: 8, tool: '2.28', cloud_bound: 'on', rtty_ssh: 'off', rtty_web: 'unknown' };
  expect('a schema 8 report is valid', validate(good8) === null);
  expect('schema 8 needs its three answers, and only on, off or unknown', validate({ ...good7, schema: 8 }) !== null && validate({ ...good8, cloud_bound: 'someone@example.org' }) !== null && validate({ ...good7, cloud_bound: 'on' }) !== null);
  // a note of the sender's own (schema 9)
  const good9 = { ...good8, schema: 9, tool: '2.35', note: 'fleet-a 2026-11-22 after clean-up (repeat)', state_file_first: '2026-03-02 08:14:55 UTC' };
  expect('a schema 9 report is valid, with a note and with an empty one', validate(good9) === null && validate({ ...good9, note: '' }) === null && validate({ ...good9, note: 'x'.repeat(120) }) === null);
  expect('schema 9 needs the note, and at most 120 characters', validate({ ...good8, schema: 9 }) !== null && validate({ ...good9, note: 'x'.repeat(121) }) !== null && validate({ ...good9, note: 42 }) !== null);
  expect('refuses a note with a control or non-ASCII character', validate({ ...good9, note: 'a\nb' }) !== null && validate({ ...good9, note: 'a\tb' }) !== null && validate({ ...good9, note: 'caf\u00e9' }) !== null && validate({ ...good9, note: 'a\u007fb' }) !== null);
  expect('the state file\'s first call is a time or empty, and only from schema 9 on', validate({ ...good9, state_file_first: '' }) === null && validate({ ...good9, state_file_first: '2026-03-02' }) !== null && validate({ ...good9, state_file_first: undefined }) !== null && validate({ ...good8, state_file_first: '' }) === 'unknown field state_file_first');
  expect('a time from a router whose clock was not set is kept as it is', validate({ ...good9, state_file_time: '1970-01-01 00:00:07 UTC', state_file_first: '1970-01-01 00:00:03 UTC' }) === null);
  expect('schema 8 must not carry a note', validate({ ...good8, note: 'x' }) === 'unknown field note' && validate({ ...good7, note: '' }) === 'unknown field note');
  await call('POST', JSON.stringify(good4));
  expect('without the secret the id is dropped', lastReport().device_id === '');
  env.DEVICE_SALT = 'test-salt';
  await call('POST', JSON.stringify(good4)); const sealed = lastReport().device_id;
  expect('with the secret a short sealed id is stored, not what was sent', /^[0-9a-f]{12}$/.test(sealed) && !'0123456789abcdef'.includes(sealed) && !JSON.stringify(lastReport()).includes('0123456789abcdef'));
  await call('POST', JSON.stringify({ ...good4, model: 'again' }));
  expect('the same device gets the same id', lastReport().device_id === sealed);
  await call('POST', JSON.stringify({ ...good4, device_id: 'fedcba9876543210' }));
  expect('another device gets another id', lastReport().device_id !== sealed && lastReport().device_id.length === 12);
  env.DEVICE_SALT = 'other-salt'; await call('POST', JSON.stringify(good4));
  expect('another secret gives another id', lastReport().device_id !== sealed); env.DEVICE_SALT = 'test-salt';

  // ---- the same worker on D1
  const kvReports = [...store.keys()].filter((k) => k.startsWith('csa-2026-01/')).length;
  const auth = { authorization: 'Bearer test-token' }, mig = (q = '') => call('POST', undefined, auth, '/csa-2026-01-report/migrate' + q);
  expect('migrate refuses without a database', (await mig()).status === 400);
  expect('migrate by GET says to use POST', (await call('GET', undefined, auth, '/csa-2026-01-report/migrate')).status === 405);
  expect('the reported table needs the database', (await call('GET', undefined, {}, '/2026-01/reported.json')).status === 503);
  env.DB = d1();
  expect('migrate needs the token', (await call('POST', undefined, {}, '/csa-2026-01-report/migrate')).status === 404);
  const m1 = await (await mig()).json();
  expect('migrate copies the KV reports', m1.copied === kvReports && m1.in_database === kvReports && m1.cursor === '');
  const m2 = await (await mig()).json();
  expect('migrate can be repeated without duplicates', m2.in_database === kvReports);
  expect('KV is left as it was', [...store.keys()].filter((k) => k.startsWith('csa-2026-01/')).length === kvReports);
  const dtok = await (async () => { globalThis.fetch = async () => new Response(JSON.stringify({ keys: [jwk] })); return token(claims); })();
  const d = (path) => call('GET', undefined, { 'cf-access-jwt-assertion': dtok }, '/csa-2026-01-report/dashboard/' + path);
  // labels: "probably safe", set by anyone who may open the dashboard
  const lab = (body, headers = { 'content-type': 'application/json', origin: 'https://example.org' }) => call('POST', JSON.stringify(body), { 'cf-access-jwt-assertion': dtok, ...headers }, '/csa-2026-01-report/dashboard/labels');
  const safe1 = { key: 'new-binary /usr/sbin/tailscaled', verdict: 'safe', note: 'Tailscale updater', hashes: ['a'.repeat(64)] };
  expect('no labels at first, and the reader is named', await (async () => { const j = await (await d('labels')).json(); return Object.keys(j.labels).length === 0 && j.you === claims.email; })());
  const set1 = await lab(safe1), got1 = (await set1.json()).labels[safe1.key];
  expect('a label is stored with who set it and when', set1.status === 200 && got1.verdict === 'safe' && got1.note === 'Tailscale updater' && got1.hashes.length === 1 && got1.by === claims.email && /^2\d{3}-/.test(got1.at));
  expect('it is there on the next read', (await (await d('labels')).json()).labels[safe1.key].note === 'Tailscale updater');
  expect('labels need the dashboard login', (await call('POST', JSON.stringify(safe1), { 'content-type': 'application/json', origin: 'https://example.org' }, '/csa-2026-01-report/dashboard/labels')).status === 404 && (await call('GET', undefined, {}, '/csa-2026-01-report/dashboard/labels')).status === 404);
  expect('a change from another site or as a form is refused', (await lab(safe1, { 'content-type': 'application/json', origin: 'https://evil.example' })).status === 403 && (await lab(safe1, { 'content-type': 'text/plain', origin: 'https://example.org' })).status === 403);
  expect('refuses markup in key or note, an unknown verdict and a bad fingerprint', (await lab({ ...safe1, key: '<b>' })).status === 400 && (await lab({ ...safe1, note: 'x\u0000' })).status === 400 && (await lab({ ...safe1, verdict: 'whatever' })).status === 400 && (await lab({ ...safe1, hashes: ['zz'] })).status === 400);
  expect('an empty verdict removes the label', Object.keys((await (await lab({ ...safe1, verdict: '' })).json()).labels).length === 0);
  // suggestions: loaded as SQL, answered on the dashboard
  {
    const h1 = 'b'.repeat(64), h2 = 'c'.repeat(64);
    const list = [{ key: 'changed /etc/init.d/samba4', note: 'Vendor pattern: same file on 1000 devices.', hashes: [h1] }, { key: 'new-link /usr/bin/login to=/bin/busybox', note: 'Link to busybox.', hashes: [] }, { key: 'hidden /lib/wifi/.first_time_boot', note: 'Empty marker file.', hashes: [h2] }];
    const sql = suggestionsSql(list, { by: 'test analysis', at: '2026-11-24T15:00:00.000Z' });
    env.DB.raw.exec(sql);
    const j0 = await (await d('labels')).json();
    expect('suggestions come with the labels and hide nothing', Object.keys(j0.suggestions).length === 3 && Object.keys(j0.labels).length === 0 && j0.suggestions['changed /etc/init.d/samba4'].hashes[0] === h1 && j0.suggestions['changed /etc/init.d/samba4'].by === 'test analysis' && j0.suggestions['changed /etc/init.d/samba4'].declined_by === '');
    const yes = await (await lab({ key: list[0].key, verdict: 'safe', note: list[0].note, hashes: list[0].hashes })).json();
    expect('a yes turns a suggestion into a label in the name of who said it', yes.labels[list[0].key].by === claims.email && yes.labels[list[0].key].hashes[0] === h1 && yes.labels[list[0].key].note === list[0].note && !yes.suggestions[list[0].key]);
    const no = await (await lab({ key: list[1].key, verdict: 'decline', note: '', hashes: [] })).json();
    expect('a no keeps the suggestion with who declined it, and sets no label', no.suggestions[list[1].key].declined_by === claims.email && /^2\d{3}-/.test(no.suggestions[list[1].key].declined_at) && !no.labels[list[1].key]);
    env.DB.raw.exec(suggestionsSql(list.map((s) => ({ ...s, note: 'again' })), { by: 'second run' }));
    const j1 = await (await d('labels')).json();
    expect('loading the same suggestions again changes none that is there or declined', j1.suggestions[list[1].key].declined_by === claims.email && j1.suggestions[list[2].key].note === 'Empty marker file.' && j1.suggestions[list[0].key].note === 'again' && j1.labels[list[0].key].note === list[0].note);
    expect('a no from another site is refused', (await lab({ key: list[2].key, verdict: 'decline', note: '', hashes: [] }, { 'content-type': 'application/json', origin: 'https://evil.example' })).status === 403);
    const db = env.DB; delete env.DB;
    expect('without the database there are no suggestions to answer', (await lab({ key: list[2].key, verdict: 'decline', note: '', hashes: [] })).status === 400 && Object.keys((await (await d('labels')).json()).suggestions).length === 0);
    env.DB = db;
    let thrown = 0;
    for (const bad of [[{ key: '<b>x</b>', note: 'n', hashes: [] }], [{ key: 'changed /etc/x', note: 'ü', hashes: [] }], [{ key: 'changed /etc/x', note: 'n', hashes: ['zz'] }], [{ key: 'changed /etc/x', note: 'n', hashes: [] }, { key: 'changed /etc/x', note: 'n', hashes: [] }]]) try { suggestionsSql(bad); } catch { thrown++; }
    expect('the SQL tool refuses what the dashboard would refuse, and a key twice', thrown === 4);
    expect('a quote in a note cannot end the SQL string', (() => { env.DB.raw.exec(suggestionsSql([{ key: 'changed /etc/quote', note: "it's fine'); DROP TABLE labels; --", hashes: [] }])); return env.DB.raw.prepare('SELECT note FROM suggestions WHERE key = ?').get('changed /etc/quote').note.startsWith("it's") && env.DB.raw.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name = 'labels'").get().n === 1; })());
    env.DB.raw.exec('DELETE FROM labels; DELETE FROM suggestions');
  }
  // the other verdicts, a mark for every file at its path, and files put on the community list
  {
    const hA = 'd'.repeat(64), hB = 'e'.repeat(64);
    const mal = { key: 'odd-file /etc/config/.gl/run.sh', verdict: 'malware', note: 'per-device variants', hashes: [hA], every: true };
    const j1 = await (await lab(mal)).json(), l1 = j1.labels[mal.key];
    expect('"known malware" is stored with every file at its path', l1.verdict === 'malware' && l1.every === true && l1.by === claims.email && l1.hashes[0] === hA);
    const j2 = await (await lab({ key: 'changed /etc/sysupgrade.conf', verdict: 'unsafe', note: '', hashes: [hB] })).json();
    expect('"probably not safe" is stored; without "every" a mark holds for its files only', j2.labels['changed /etc/sysupgrade.conf'].verdict === 'unsafe' && j2.labels['changed /etc/sysupgrade.conf'].every === false);
    expect('"every" must be true or false', (await lab({ ...mal, every: 'yes' })).status === 400 && (await lab({ ...mal, every: 1 })).status === 400);
    env.DB.raw.exec('DELETE FROM labels');
    // the community list from the dashboard: POST .../dashboard/bad-hashes
    const bh = (body, headers = { 'content-type': 'application/json', origin: 'https://example.org' }, tok = dtok) => call('POST', JSON.stringify(body), { ...(tok ? { 'cf-access-jwt-assertion': tok } : {}), ...headers }, '/csa-2026-01-report/dashboard/bad-hashes');
    const one = { sha256: hA, verdict: 'malware', note: 'run.sh of gl-helper' };
    expect('the list needs the dashboard login and the dashboard itself', (await bh(one, undefined, null)).status === 404 && (await bh(one, { 'content-type': 'application/json', origin: 'https://evil.example' })).status === 403 && (await bh(one, { 'content-type': 'text/plain', origin: 'https://example.org' })).status === 403);
    expect('refuses a bad fingerprint, verdict or note', (await bh({ ...one, sha256: 'zz' })).status === 400 && (await bh({ ...one, verdict: 'safe' })).status === 400 && (await bh({ ...one, note: 'x\u0000' })).status === 400);
    const put = await (await bh(one)).json();
    expect('a file put on the list answers known_bad (answer 1), with who and when, and comes with the labels', put.bad[hA].answer === 1 && put.bad[hA].by === claims.email && put.bad[hA].note === one.note && /^2\d{3}-/.test(put.bad[hA].at) && (await (await d('labels')).json()).bad[hA].answer === 1);
    env.DB.raw.exec(badHashesSql([{ sha256: hB, note: 'waiting', answer: 0 }]));
    env.DB.raw.prepare("UPDATE bad_hashes SET asked = 3, asked_last = '2026-11-20' WHERE sha256 = ?").run(hB);
    const rel = await (await bh({ sha256: hB, verdict: 'malware', note: '' })).json();
    expect('an entry that waited is released and keeps its counter; an empty note gets one', rel.bad[hB].answer === 1 && rel.bad[hB].asked === 3 && rel.bad[hB].asked_last === '2026-11-20' && rel.bad[hB].note === 'marked on the dashboard');
    const off = await (await bh({ sha256: hA, verdict: '', note: '' })).json();
    expect('an empty verdict takes a file off the list', !off.bad[hA] && off.bad[hB]);
    env.DB.raw.exec('DELETE FROM bad_hashes');
    const db = env.DB; delete env.DB;
    expect('without the database there is no list: a change is refused, the read says there is none (null), so the dashboard offers none', (await bh(one)).status === 400 && (await (await d('labels')).json()).bad === null);
    env.DB = db;
    // a table of labels from before "every": the worker adds the column, the old marks stay
    const old = d1();
    old.raw.exec('CREATE TABLE labels (key TEXT PRIMARY KEY, verdict TEXT NOT NULL, note TEXT NOT NULL, hashes TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL)');
    old.raw.prepare('INSERT INTO labels VALUES (?, ?, ?, ?, ?, ?)').run('changed /etc/old', 'safe', 'old mark', JSON.stringify([hA]), 'a@example.org', '2026-11-20T10:00:00Z');
    const fresh = (await import('../src/index.js?older-labels')).default, oenv = { ...env, DB: old };
    const ocall = (method, body, path) => fresh.fetch(new Request('https://example.org/csa-2026-01-report/dashboard/' + path, { method, body, headers: { 'cf-access-jwt-assertion': dtok, ...(body ? { 'content-type': 'application/json', origin: 'https://example.org' } : {}) } }), oenv, { waitUntil() {} });
    const o1 = await (await ocall('GET', undefined, 'labels')).json();
    const o2 = await (await ocall('POST', JSON.stringify({ key: 'changed /etc/sysupgrade.conf', verdict: 'safe', note: '', hashes: [], every: true }), 'labels')).json();
    // an ALTER that fails for a passing reason counts: the next request tries again (review of 2.61)
    const old2 = d1();
    old2.raw.exec('CREATE TABLE labels (key TEXT PRIMARY KEY, verdict TEXT NOT NULL, note TEXT NOT NULL, hashes TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL)');
    const p2 = old2.prepare; let fails = 1;
    old2.prepare = (sql) => (sql.startsWith('ALTER') && fails-- > 0 ? { ...p2(sql), run: async () => { throw new Error('D1 busy'); } } : p2(sql));
    const fresh2 = (await import('../src/index.js?older-labels-busy')).default, o2env = { ...env, DB: old2 };
    const o2call = () => fresh2.fetch(new Request('https://example.org/csa-2026-01-report/dashboard/labels', { headers: { 'cf-access-jwt-assertion': dtok } }), o2env, {}).then((r) => r.status, () => 'thrown');
    const busy1 = await o2call(), busy2 = await o2call();
    expect('an ALTER that fails once is tried again: the first request fails, the next one has the column', busy1 !== 200 && busy2 === 200 && old2.raw.prepare('PRAGMA table_info(labels)').all().some((c) => c.name === 'every'));
    expect('an older table of labels gets the column: its marks stay, without "every", and new ones can have it', o1.labels['changed /etc/old'].note === 'old mark' && o1.labels['changed /etc/old'].every === false && o2.labels['changed /etc/sysupgrade.conf'].every === true && o2.labels['changed /etc/old'].hashes[0] === hA);
  }
  expect('a label is not taken for a report', (await (await d('data')).json()).items.length === kvReports);
  const all1 = (await (await d('data')).json());
  expect('dashboard reads the moved reports from D1', all1.items.length === kvReports && all1.cursor === '' && all1.items[0].report.model === 'GL-AXT1800');
  const writesBefore = store.size;
  expect('a new report goes to D1', (await call('POST', JSON.stringify({ ...good3, model: 'GL-D1' }))).status === 200 && store.size === writesBefore);
  const latest1 = (await (await d('latest')).json()).latest, newer = (await (await d('data?since=' + all1.items.at(-1).received)).json()).items;
  expect('latest and since work on D1', newer.length === 1 && newer[0].report.model === 'GL-D1' && newer[0].received === latest1 && newer[0].report.persistence.length === 1);
  expect('nothing newer than the newest on D1', (await (await d('data?since=' + latest1)).json()).items.length === 0);
  const ins = env.DB.raw.prepare('INSERT INTO reports (id, received, report) VALUES (?, ?, ?)');
  for (let i = 0; i < 1100; i++) ins.run('bulk' + String(i).padStart(5, '0'), '2026-11-22T10:00:00.' + String(i % 1000).padStart(3, '0') + 'Z', JSON.stringify(good));
  let cur = '', got = 0, pages = 0; const ids = new Set();
  do { const pg = await (await d('data' + (cur ? '?cursor=' + encodeURIComponent(cur) : ''))).json(); pg.items.forEach((x) => ids.add(x.id)); got += pg.items.length; cur = pg.cursor; pages++; } while (cur && pages < 10);
  expect('paging on D1 returns every report once, also with equal times', got === kvReports + 1 + 1100 && ids.size === got && pages === 3);
  const allRes = await call('GET', undefined, { authorization: 'Bearer test-token' }, '/csa-2026-01-report/export?all=1');
  expect('export with all=1 returns every report in one answer', (await allRes.text()).trim().split('\n').length === got && allRes.headers.get('x-next-cursor') === '');
  const ex = await call('GET', undefined, auth, '/csa-2026-01-report/export');
  expect('export works on D1', ex.status === 200 && (await ex.text()).split('\n').filter(Boolean).length === 500 && ex.headers.get('x-next-cursor') !== '');
  expect('a bad report is still refused on D1', (await call('POST', JSON.stringify({ ...good, hostname: 'x' }))).status === 400);
  // ---- the table for the advisory: models and firmware versions with traces
  {
    let n = 0;
    const rep = (dev, o = {}, received = '2026-11-22T12:00:00.000Z') => ins.run('rep' + String(n++).padStart(4, '0'), received, JSON.stringify({ schema: 9, platform: 'openwrt', model: 'mt6000', firmware: '4.8.3 release2 build 540 2026-10-02', ioc: 2, findings: ['marker /etc/config/.gl', 'fw-rule nat'], astrowarp: 'off', state_file_size: -1, state_file_time: '', ...(dev ? { device_id: dev } : {}), ...o }));
    const five = (tag, o, received) => { for (let i = 0; i < 5; i++) rep(tag + i, o, received); };
    five('a');                                                                          // listed
    for (let i = 0; i < 3; i++) rep('b' + i, { model: 'be9300', firmware: '4.10.1' });  // three devices ...
    for (let i = 0; i < 5; i++) rep('b9', { model: 'be9300', firmware: '4.10.1' });     // ... and a fourth, five times
    for (let i = 0; i < 5; i++) rep('', { model: 'be9300', firmware: '4.9.0' });        // no device id
    five('c', { model: 'zz9' });                                                        // not a model of the archive
    five('d', { firmware: '4.7.13', findings: ['backdoor-file /bin/ulogd', 'backdoor-init /etc/init.d/urandom_seed'] }); // the older backdoor only
    five('e', { firmware: '4.10.0 release1', ioc: 0, findings: [], state_file_size: 0, state_file_time: '2026-11-21 00:10:00 UTC' }); // the state file alone
    five('f', { firmware: '4.12.0 release1 build 700 2026-11-21' });                    // built after the attack
    five('g', { firmware: '4.8.2' }, '2026-11-21T09:00:00.000Z');                       // checked ...
    five('g', { firmware: '4.9.9' }, '2026-11-22T15:00:00.000Z');                       // ... upgraded, checked again
    five('h', { firmware: '<script>' }); five('i', { platform: 'unknown', firmware: '4.6.0' });
    const tab = (ctx = { waitUntil() {} }) => worker.fetch(new Request('https://csa.example.org/2026-01/reported.json'), env, ctx);
    const r1 = await tab(), raw1 = await r1.text(), t1 = JSON.parse(raw1);
    expect('the reported table is open to all, as JSON that any page may read', r1.status === 200 && r1.headers.get('content-type').startsWith('application/json') && r1.headers.get('access-control-allow-origin') === '*');
    expect('it names the advisory, the time and the threshold', t1.advisory === 'CSA-2026-01' && /^\d{4}-\d\d-\d\dT\d\d:\d\dZ$/.test(t1.as_of) && t1.min_devices === 5);
    expect('a model and firmware are listed from five devices on, versions in the order of their numbers', t1.models.length === 1 && t1.models[0].model === 'mt6000' && t1.models[0].sku === 'GL-MT6000' && t1.models[0].kind === 'Router' && t1.models[0].firmware.join() === '4.8.2,4.8.3,4.10.0');
    expect('four devices are not enough, however often one of them reports; reports without an id do not count', !raw1.includes('be9300'));
    expect('unknown models, the older backdoor alone, odd versions and firmware built after the attack stay out', !/zz9|4\.7\.13|4\.12\.0|script|4\.6\.0/.test(raw1));
    expect('a device counts for the firmware of its first report with traces', !raw1.includes('4.9.9'));
    expect('the table holds nothing but model, kind and versions', Object.keys(t1).join() === 'advisory,as_of,min_devices,models' && Object.keys(t1.models[0]).join() === 'model,sku,kind,firmware' && !/a0|rep00/.test(raw1));
    const devices = () => JSON.parse(store.get('reported/csa-2026-01-devices'));
    const upto = devices().upto;
    expect('it keeps the first report with traces of each device and how far it has read', /^[0-9a-f]{64}$/.test(devices().rules) && upto === env.DB.raw.prepare('SELECT max(received) AS m FROM reports').get().m && devices().devices.some((d) => d.join() === 'a0,openwrt,mt6000,4.8.3 release2 build 540 2026-10-02'));
    // stored a moment after a later report: the overlap still catches it
    rep('b4', { model: 'be9300', firmware: '4.10.1' }, new Date(Date.parse(upto) - 60_000).toISOString());
    expect('the table is kept: a new report does not change it at once', !(await (await tab()).text()).includes('be9300'));
    const stale = async () => { const kept = JSON.parse(store.get('reported/csa-2026-01')); store.set('reported/csa-2026-01', JSON.stringify({ ...kept, checked: 0 })); let later; const t = await (await tab({ waitUntil(p) { later = p; } })).text(); await later; return t; };
    expect('after a quarter of an hour it is worked out again, behind the answer', !(await stale()).includes('be9300') && (await (await tab()).text()).includes('"sku":"GL-BE9300","kind":"Router","firmware":["4.10.1"]'));
    const plan = env.DB.raw.prepare('EXPLAIN QUERY PLAN ' + TRACE_SQL).all('a', 'b').map((r) => r.detail).join();
    expect('it reads the reports through the index on the time of receipt', /^SEARCH reports USING INDEX reports_received \(received>\? AND received<\?\)$/.test(plan));
    // the older reports are not read again: a change to them shows only once the rules change
    env.DB.raw.exec("UPDATE reports SET report = json_set(report, '$.ioc', 0, '$.findings', json('[]')) WHERE json_extract(report, '$.device_id') LIKE 'a_'");
    await stale();
    expect('a later run reads only the reports received since', (await (await tab()).text()).includes('"firmware":["4.8.2","4.8.3","4.10.0"]'));
    store.set('reported/csa-2026-01-devices', JSON.stringify({ ...devices(), rules: 'older rules' })); await stale();
    expect('when the rules change, all reports are read again', (await (await tab()).text()).includes('"firmware":["4.8.2","4.10.0"]'));
    expect('the table cannot be written to', (await worker.fetch(new Request('https://csa.example.org/2026-01/reported.json', { method: 'POST', body: '{}' }), env, { waitUntil() {} })).status === 405);
    // ---- live.json: the version of the script and the table, for the pages on gl-i.net
    {
      const live = (path = '/2026-01/live.json', init) => worker.fetch(new Request('https://csa.example.org' + path, init), env, { waitUntil() {} });
      await env.REPORTS.put('script/csa-2026-01-fix', JSON.stringify({ commit: 'lv', body: "#!/bin/sh\nVERSION=7.80\nRELEASED='2026-11-25 08:41 UTC'\n", checked: Date.now() }));
      // the figures are worked out behind the first answer; once they are there, the answers compared here are alike
      { let later; await worker.fetch(new Request('https://csa.example.org/2026-01/live.json'), env, { waitUntil(p) { later = p; } }); await later; }
      const r = await live(), raw = await r.text(), j = JSON.parse(raw), table = await (await tab()).json();
      expect('live.json gives the version, its release time and the reported table in one answer', r.status === 200 && Object.keys(j).join() === 'script,reported,figures' && j.script.version === '7.80' && j.script.released === '2026-11-25T08:41:00Z' && JSON.stringify(j.reported) === JSON.stringify(table));
      expect('any page may read it, it is kept a minute and read as JSON only', r.headers.get('access-control-allow-origin') === '*' && r.headers.get('cache-control') === 'public, max-age=60' && r.headers.get('x-content-type-options') === 'nosniff' && r.headers.get('content-type').startsWith('application/json'));
      const odd = await (await live('/2026-01/live.json?script=<b>&reported=1', { headers: { cookie: 'x=<b>', 'x-forwarded-for': '<b>' } })).text();
      expect('live.json takes nothing from the request: parameters and headers change nothing', odd === raw);
      expect('nothing can be sent to it', (await live('/2026-01/live.json', { method: 'POST', body: '{"script":1}' })).status === 405 && (await live('/2026-01/live.json', { method: 'PUT', body: 'x' })).status === 405 && (await live('/2026-01/live.json', { method: 'DELETE' })).status === 405);
      await env.REPORTS.put('script/csa-2026-01-fix', JSON.stringify({ commit: 'lv', body: '#!/bin/sh\nVERSION=<b>\n', checked: Date.now() }));
      expect('a version of an odd shape is not handed on', JSON.parse(await (await live()).text()).script === null);
      await env.REPORTS.put('script/csa-2026-01-fix', 'null');
    }
    const kvm = (v, i) => ({ dev: 'k' + v + i, platform: 'glkvm-RM1', model: 'rm1', firmware: 'V' + v + ' release1', ioc: 1, findings: ['process implant'] });
    const rows = [...[0, 1, 2, 3, 4].map((i) => kvm('1.10.1', i)), ...[0, 1, 2, 3, 4].map((i) => kvm('1.10.3', i))];
    const k = reportedTable(firstTraces(rows), { rm1: { r: ['1.10.3', '2026-11-22'] } });
    expect('where the report gives no build day, the archive does: a release from after the attack stays out', k.length === 1 && k[0].kind === 'KVM' && k[0].sku === 'GL-RM1' && k[0].firmware.join() === '1.10.1');
  }
  // every report these tests posted: what the worker took, the schema must let through
  let took = 0, lost = 0;
  for (const body of posted) { let r; try { r = JSON.parse(body); } catch { continue; } if (validate(r) === null) { took++; if (!globalThis.fitsOpenApi(r)) lost++; } }
  expect(`the schema for Cloudflare lets through all ${took} reports of these tests that the worker takes`, took >= 5 && lost === 0);
  // ---- the signature of the script, for its --update
  {
    const pair = () => { const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519'), num = nodeCrypto.randomBytes(8); return { num, privateKey, pub: Buffer.concat([Buffer.from('Ed'), num, publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)]).toString('base64') }; };
    const sign = (k, body) => 'untrusted comment: signature\n' + Buffer.concat([Buffer.from('Ed'), k.num, nodeCrypto.sign(null, Buffer.from(body), k.privateKey)]).toString('base64') + '\n';
    const k1 = pair(), k2 = pair(), other = pair(), v1 = '#!/bin/sh\nVERSION=7.77\n# naïve: not only ASCII\n', v2 = '#!/bin/sh\nVERSION=7.78\n';
    const serve = (body) => env.REPORTS.put('script/csa-2026-01-fix', JSON.stringify({ commit: 'c-' + body.length, body, checked: Date.now() }));
    const sig = (method, body) => call(method, body, {}, '/csa-2026-01-fix.sig');
    await serve(v1); env.UPDATE_PUBLIC_KEYS = k1.pub + ' ' + k2.pub;
    expect('no signature is handed out before one was handed in', (await sig('GET')).status === 404);
    expect('a signature made with another key, or for another text, is refused', (await sig('POST', sign(other, v1))).status === 400 && (await sig('POST', sign(k1, v2))).status === 400 && (await sig('POST', 'junk')).status === 400 && (await sig('GET')).status === 404);
    const put = await sig('POST', sign(k1, v1)), got = await sig('GET');
    expect('a signature that fits the script served now is taken and handed out as it came', put.status === 200 && (await put.text()).trim() === 'c-' + v1.length && got.status === 200 && (await got.text()) === sign(k1, v1));
    expect('the spare key signs as well', (await sig('POST', sign(k2, v1))).status === 200);
    await serve(v2);
    expect('once another script is served, the old signature is no longer handed out', (await sig('GET')).status === 404 && (await sig('POST', sign(k1, v2))).status === 200 && (await sig('GET')).status === 200);
    delete env.UPDATE_PUBLIC_KEYS;
    const shKeys = (/^UPDATE_KEYS='([^']*)'$/m.exec(readFileSync(new URL('../../gl-helper-triage.sh', import.meta.url), 'utf8')) || [null, null])[1];
    expect('the worker checks signatures with the keys the script carries', shKeys !== null && shKeys.split(/\s+/).filter(Boolean).join(' ') === UPDATE_KEYS.join(' ') && (UPDATE_KEYS.length > 0 || (await sig('POST', sign(k1, v2))).status === 400));
    await env.REPORTS.put('script/csa-2026-01-fix', 'null'); await env.REPORTS.put('script/csa-2026-01-fix.sig', 'null');
  }
  // ---- the fingerprint check: POST .../lookup (docs/lookup.md)
  {
    const LK = '/csa-2026-01-report/lookup', NONCE = '0123456789abcdef0123456789abcdef';
    const sha = (s) => nodeCrypto.createHash('sha256').update(s).digest('hex');
    const HEAD = ['csa-2026-01-lookup 1', 'version 2.60', 'nonce ' + NONCE];
    const ask = (items, head = HEAD) => [...head, ...items.map((x) => (Array.isArray(x) ? x.join(' ') : x))].join('\n') + '\n';
    // the check, waiting for what it hands to waitUntil (the counter) before the test reads on
    const look = async (body, headers = {}, method = 'POST', path = LK) => {
      const later = [];
      const r = await worker.fetch(new Request('https://example.org' + path, { method, body, headers }), env, { waitUntil(p) { later.push(p); } });
      await Promise.all(later);
      return r;
    };
    const reportCount = () => env.DB.raw.prepare('SELECT count(*) AS n FROM reports').get().n + [...store.keys()].filter((k) => k.startsWith('csa-2026-01/')).length;
    const reportsBefore = reportCount(), postedBefore = posted.length;
    const row = (h) => env.DB.raw.prepare('SELECT * FROM bad_hashes WHERE sha256 = ?').get(h);
    const today = () => new Date().toISOString().slice(0, 10);
    const h = (c) => c.repeat(64);
    // the check's data: two marks, an open and a declined suggestion, three entries of bad_hashes
    const markKey = 'new-binary /usr/sbin/tailscaled', markKey2 = 'changed /etc/init.d/dropbear', sugKey = 'hidden /lib/wifi/.marker', noKey = 'changed /etc/hotplug.d/iface/99-x';
    const putLabel = env.DB.raw.prepare('INSERT OR REPLACE INTO labels (key, verdict, note, hashes, by, at) VALUES (?, ?, ?, ?, ?, ?)');
    putLabel.run(markKey, 'safe', 'Tailscale updater', JSON.stringify([h('1'), h('2')]), 'a@example.org', '2026-11-24T10:00:00Z');
    putLabel.run(markKey2, 'safe', 'marked, and later found to be malware', JSON.stringify([h('7')]), 'a@example.org', '2026-11-24T10:00:00Z');
    env.DB.raw.exec(suggestionsSql([{ key: sugKey, note: 'open', hashes: [h('3')] }, { key: noKey, note: 'declined', hashes: [h('4')] }]));
    env.DB.raw.prepare("UPDATE suggestions SET declined_by = 'b@example.org', declined_at = '2026-11-24T11:00:00Z' WHERE key = ?").run(noKey);
    env.DB.raw.exec(badHashesSql([{ sha256: h('7'), note: 'released', answer: 1 }, { sha256: h('8'), note: 'waiting', answer: 0 }, { sha256: h('9'), note: 'released, never asked', answer: 1 }], { at: '2026-11-24T12:00:00Z' }));
    const release = Object.keys(JSON.parse(readFileSync(new URL('../src/known-hashes.json', import.meta.url), 'utf8')))[0];
    markCache.map = null;

    // switched off: every method gets 404, and a POST there is never a report
    expect('the check is off without LOOKUP = "on": 404 for every method, with a fixed text', await (async () => { for (const m of ['POST', 'GET', 'PUT', 'DELETE']) { const r = await look(m === 'GET' || m === 'DELETE' ? undefined : ask([[sha(markKey), h('1')]]), {}, m); if (r.status !== 404 || (await r.text()) !== 'not found\n') return false; } return true; })());
    expect('switched off, a report posted to it is not stored', (await look(JSON.stringify(good))).status === 404 && reportCount() === reportsBefore);
    env.LOOKUP = 'yes';
    expect('only the exact value "on" switches it on', (await look(ask([[sha(markKey), h('1')]]))).status === 404);
    env.LOOKUP = 'on';
    expect('anything but POST: 405 with a fixed text', await (async () => { for (const m of ['GET', 'PUT', 'DELETE', 'PATCH']) { const r = await look(m === 'GET' || m === 'DELETE' ? undefined : 'x', {}, m); if (r.status !== 405 || (await r.text()) !== 'method not allowed\n') return false; } return true; })());

    // a valid request and its answer, byte for byte
    const items = [
      [sha(markKey), h('1')],    // a mark with this fingerprint
      [sha(markKey), h('5')],    // the same mark, another file
      [sha(noKey), h('7')],      // in bad_hashes, released
      [sha(markKey2), h('7')],   // the same file under a mark: bad wins
      [sha(noKey), h('8')],      // in bad_hashes, waiting
      [sha(sugKey), h('3')],     // an open suggestion
      [sha(noKey), h('4')],      // a declined suggestion
      [sha('changed /x'), release], // a release file, at any path
      [sha('changed /x'), h('6')],  // nothing known
    ];
    const words = ['known_safe', 'unknown', 'known_bad', 'known_bad', 'unknown', 'unknown', 'unknown', 'known_safe', 'unknown'];
    const r1 = await look(ask(items)), body1 = await r1.text(), at1 = body1.split('\n')[2];
    const want1 = ['csa-2026-01-lookup-answer 1', 'nonce ' + NONCE, at1, ...items.map((x, i) => `${x[0]} ${x[1]} ${words[i]}`)].join('\n') + '\n';
    const atTime = Date.parse(at1.slice(3, 19).replace(' ', 'T') + 'Z');
    expect('a valid request gets its answer, byte for byte: nonce, time to the minute, one line per line asked, in order', r1.status === 200 && body1 === want1 && /^at \d{4}-\d\d-\d\d \d\d:\d\d UTC$/.test(at1) && Math.abs(Date.now() - atTime) < 120_000);
    expect('the answer is plain text that nothing may sniff, cache or read from another site', r1.headers.get('content-type') === 'text/plain; charset=utf-8' && r1.headers.get('cache-control') === 'no-store' && r1.headers.get('x-content-type-options') === 'nosniff' && !r1.headers.has('access-control-allow-origin'));
    expect('known_safe by a mark: the SHA-256 of its key and one of its fingerprints; another file at the same key is unknown', words[0] === 'known_safe' && body1.includes(`${sha(markKey)} ${h('1')} known_safe\n`) && body1.includes(`${sha(markKey)} ${h('5')} unknown\n`));
    expect('suggestions never count, open or declined', body1.includes(`${sha(sugKey)} ${h('3')} unknown\n`) && body1.includes(`${sha(noKey)} ${h('4')} unknown\n`));
    expect('a release file is known_safe at any path', body1.includes(`${sha('changed /x')} ${release} known_safe\n`));
    expect('known_bad for an entry with answer 1, also where a mark covers the same file; unknown for answer 0', body1.includes(`${sha(noKey)} ${h('7')} known_bad\n`) && body1.includes(`${sha(markKey2)} ${h('7')} known_bad\n`) && body1.includes(`${sha(noKey)} ${h('8')} unknown\n`));
    expect('a request counts a day for each entry it asks about, released or not, however many of its lines name it; an entry not asked for stays as it was', row(h('7')).asked === 1 && row(h('7')).asked_last === today() && row(h('8')).asked === 1 && row(h('8')).asked_last === today() && row(h('9')).asked === 0 && row(h('9')).asked_last === '');
    const rows0 = env.DB.raw.prepare('SELECT count(*) AS n FROM bad_hashes').get().n;
    // a database that notes its writes: the same day, a request writes nothing at all
    let batches = 0;
    const spy = { ...env, DB: new Proxy(env.DB, { get(t, k) { if (k === 'batch') return (...a) => { batches++; return t.batch(...a); }; const v = t[k]; return typeof v === 'function' ? v.bind(t) : v; } }) };
    const spyLook = async (body) => { const later = []; const r = await worker.fetch(new Request('https://example.org' + LK, { method: 'POST', body }), spy, { waitUntil(p) { later.push(p); } }); await Promise.all(later); return r; };
    for (let i = 0; i < 5; i++) await spyLook(ask([[sha('a'), h('6')], [sha('b'), h('8')], [sha(noKey), h('7')]]));
    expect('a file that is not in the table leaves no trace; the same day, more requests write nothing and count nothing', env.DB.raw.prepare('SELECT count(*) AS n FROM bad_hashes').get().n === rows0 && !row(h('6')) && row(h('8')).asked === 1 && row(h('7')).asked === 1 && batches === 0);
    // the next day: one more, however many lines and requests
    env.DB.raw.prepare("UPDATE bad_hashes SET asked_last = '2026-11-01' WHERE sha256 = ?").run(h('8'));
    await look(ask(Array.from({ length: 40 }, (_, i) => [sha('same file ' + i), h('8')])));
    await look(ask([[sha('b'), h('8')]]));
    expect('a new day: one file under 40 keys and another request, one more, not 41', row(h('8')).asked === 2 && row(h('8')).asked_last === today());
    // the answer does not wait for the counter: with a database whose writes never end, it comes all the same
    env.DB.raw.prepare("UPDATE bad_hashes SET asked_last = '2026-11-01' WHERE sha256 = ?").run(h('8'));
    let stuckWrites = 0;
    const stuck = { ...env, DB: new Proxy(env.DB, { get(t, k) { if (k === 'batch') return () => { stuckWrites++; return new Promise(() => {}); }; const v = t[k]; return typeof v === 'function' ? v.bind(t) : v; } }) };
    const notWaiting = await Promise.race([worker.fetch(new Request('https://example.org' + LK, { method: 'POST', body: ask([[sha(noKey), h('8')]]) }), stuck, { waitUntil() {} }).then((r) => r.status), new Promise((r) => setTimeout(() => r('waited'), 2000))]);
    expect('the answer does not wait for the counter: a write that never ends does not hold it', notWaiting === 200 && stuckWrites === 1);
    env.DB.raw.prepare('UPDATE bad_hashes SET asked_last = ? WHERE sha256 = ?').run(today(), h('8'));
    // two workers that both saw yesterday: the second write changes nothing
    env.DB.raw.prepare("UPDATE bad_hashes SET asked_last = '2026-11-01' WHERE sha256 = ?").run(h('9'));
    const before9 = row(h('9')).asked;
    await badHashes.count(env, [h('9')], today()); await badHashes.count(env, [h('9')], today());
    expect('two workers counting the same new day: one more, not two', row(h('9')).asked === before9 + 1);
    const forty = Array.from({ length: 40 }, (_, i) => [sha('k' + i), sha('f' + i)]);
    const r40 = await look(ask(forty));
    expect('40 lines are taken, in order', r40.status === 200 && (await r40.text()).trim().split('\n').slice(3).every((l, i) => l === `${forty[i][0]} ${forty[i][1]} unknown`));
    const elsewhere = await Promise.all(['/x/csa-2026-01-report/lookup', '/csa-2026-01-report/lookup/', '/csa-2026-01-reportx/csa-2026-01-report/lookup'].map((p) => look(ask([[sha(noKey), h('7')]]), {}, 'POST', p)));
    expect('the check answers only at its own address: anywhere else a POST is refused and counts nothing', elsewhere.every((r) => r.status === 405) && row(h('7')).asked === 1);
    expect('a version of up to three digits and one line are taken', (await look(ask([[sha('k'), h('6')]], ['csa-2026-01-lookup 1', 'version 2.123', 'nonce ' + NONCE]))).status === 200);

    // "known malware" for its files or every file at its path, "probably not safe" never, and
    // "probably safe" for every file at its path still only for its files
    {
      const putEvery = env.DB.raw.prepare('INSERT OR REPLACE INTO labels (key, verdict, note, hashes, every, by, at) VALUES (?, ?, ?, ?, ?, ?, ?)');
      const kM = 'odd-file /etc/config/.gl/run.sh', kE = 'tmp-file /tmp/.x', kU = 'changed /etc/rc.local', kS = 'changed /etc/sysupgrade.conf';
      putEvery.run(kM, 'malware', 'its files', JSON.stringify([h('a')]), 0, 'a@example.org', '2026-11-26T10:00:00Z');
      putEvery.run(kE, 'malware', 'every file', JSON.stringify([h('a')]), 1, 'a@example.org', '2026-11-26T10:00:00Z');
      putEvery.run(kU, 'unsafe', 'odd', JSON.stringify([h('b')]), 1, 'a@example.org', '2026-11-26T10:00:00Z');
      putEvery.run(kS, 'safe', 'every device has its own', JSON.stringify([h('c')]), 1, 'a@example.org', '2026-11-26T10:00:00Z');
      markCache.map = null;
      // a mark for one odd file at the path of a release, saved with the release file too
      const kR = 'new-binary /usr/sbin/adguardhome';
      putEvery.run(kR, 'malware', 'one odd file', JSON.stringify([release, h('f')]), 0, 'a@example.org', '2026-11-26T10:00:00Z');
      const q = [[sha(kM), h('a')], [sha(kM), h('d')], [sha(kE), h('d')], [sha(kE), release], [sha(kU), h('b')], [sha(kS), h('c')], [sha(kS), h('d')], [sha('changed /y'), h('a')], [sha(kR), release], [sha(kR), h('f')]];
      const got = (await (await look(ask(q))).text()).trim().split('\n').slice(3).map((l) => l.split(' ')[2]).join();
      expect('known malware: its files known_bad, another file at its path unknown; for every file: any file but a release file; probably not safe: unknown; probably safe for every file: known_safe only for its files; the same file at another path: unknown; a release file in a malware mark stays known_safe (review of 2.61)', got === 'known_bad,unknown,known_bad,known_safe,unknown,known_safe,unknown,unknown,known_safe,known_bad');
      env.DB.raw.prepare('DELETE FROM labels WHERE key IN (?, ?, ?, ?, ?)').run(kM, kE, kU, kS, kR);
      // set on the dashboard, a mark or a file on the list counts at once in this worker
      markCache.map = null; const t1 = Date.now(); markCache.now = () => t1;
      const word = async (k, f) => (await (await look(ask([[sha(k), f]]))).text()).trim().split(' ').at(-1);
      const w0 = await word(kM, h('d'));
      await lab({ key: kM, verdict: 'malware', note: '', hashes: [h('d')] });
      const w1 = await word(kM, h('d'));
      await call('POST', JSON.stringify({ sha256: h('e'), verdict: 'malware', note: '' }), { 'cf-access-jwt-assertion': dtok, 'content-type': 'application/json', origin: 'https://example.org' }, '/csa-2026-01-report/dashboard/bad-hashes');
      const w2 = await word('changed /z', h('e'));
      expect('a mark set on the dashboard counts at once in the same worker, not only after a minute; a file put on the list too', w0 === 'unknown' && w1 === 'known_bad' && w2 === 'known_bad');
      // a check that read the marks while one was set keeps nothing of what it read (review of 2.61)
      env.DB.raw.prepare('DELETE FROM labels WHERE key = ?').run(kM); markCache.map = null;
      const realPrepare = env.DB.prepare; let open; const gate = new Promise((r) => { open = r; });
      env.DB.prepare = (sql) => { const st = realPrepare(sql); if (!sql.startsWith('SELECT key, verdict')) return st; env.DB.prepare = realPrepare; return { ...st, all: async () => { const r = await st.all(); await gate; return r; } }; };
      const pending = word(kM, h('d'));
      await new Promise((r) => setTimeout(r, 20));
      await lab({ key: kM, verdict: 'malware', note: '', hashes: [h('d')] });
      open(); const w3 = await pending, w4 = await word(kM, h('d'));
      env.DB.prepare = realPrepare;
      expect('a check that read the marks while one was set keeps none of them: the next check has the new mark at once', w3 === 'unknown' && w4 === 'known_bad');
      markCache.now = () => Date.now(); markCache.map = null;
      env.DB.raw.prepare('DELETE FROM labels WHERE key = ?').run(kM); env.DB.raw.prepare('DELETE FROM bad_hashes WHERE sha256 = ?').run(h('e'));
    }
    // a mark removed on the dashboard counts no more after a minute
    const t0 = Date.now(); markCache.now = () => t0; markCache.map = null;
    const one = async () => (await (await look(ask([[sha(markKey), h('1')]]))).text()).trim().split(' ').at(-1);
    const before = await one();
    env.DB.raw.prepare('DELETE FROM labels WHERE key = ?').run(markKey);
    markCache.now = () => t0 + 59_000; const cached = await one();
    markCache.now = () => t0 + 60_000; const after = await one();
    expect('the marks are kept for a minute: a removed mark is unknown after that', before === 'known_safe' && cached === 'known_safe' && after === 'unknown');
    markCache.now = () => Date.now(); markCache.map = null;

    // without D1: no bad_hashes, the marks from KV
    const db = env.DB; delete env.DB;
    await env.REPORTS.put('meta/csa-2026-01-labels', JSON.stringify({ [markKey]: { verdict: 'safe', note: 'n', hashes: [h('1')], by: 'x', at: 'y' }, [noKey]: { verdict: '', note: '', hashes: [h('4')], by: 'x', at: 'y' } }));
    const kvItems = [[sha(markKey), h('1')], [sha(noKey), h('7')], [sha(noKey), h('4')], [sha('changed /x'), release]];
    const rkv = await (await look(ask(kvItems))).text();
    expect('without D1 the answer holds only known_safe and unknown: marks from KV and release files, no bad_hashes', rkv.trim().split('\n').slice(3).map((l) => l.split(' ')[2]).join() === 'known_safe,unknown,unknown,known_safe');
    env.DB = db; markCache.map = null; await env.REPORTS.put('meta/csa-2026-01-labels', '{}');

    // a counter that cannot be written does not cost the answer; a database that cannot be
    // read gives no answer rather than one that misses an entry
    env.DB = { prepare: db.prepare, batch: async () => { throw new Error('D1 busy'); } };
    const rc = await look(ask([[sha(noKey), h('7')]]));
    expect('a failing counter update does not fail the answer', rc.status === 200 && (await rc.text()).endsWith(' known_bad\n'));
    env.DB = { prepare: () => { throw new Error('D1 down'); }, batch: db.batch };
    const rd = await look(ask([[sha(noKey), h('7')]]));
    expect('a database that cannot be read: 503 with a fixed text, not an answer without bad_hashes', rd.status === 503 && (await rd.text()) === 'not available\n');
    env.DB = db;

    // hostile input: each a fixed text, never a part of the request
    const bad400 = async (body, headers) => { const r = await look(body, headers); return r.status === 400 && (await r.text()) === 'bad request\n'; };
    const L = (i) => [sha('k' + i), sha('f' + i)];
    expect('41 lines are refused', await bad400(ask(Array.from({ length: 41 }, (_, i) => L(i)))));
    expect('no line to check is refused', await bad400(ask([])));
    expect('the same line twice is refused, the same file under two keys is not', await bad400(ask([L(1), L(2), L(1)])) && (await look(ask([[sha('a'), h('6')], [sha('b'), h('6')]]))).status === 200);
    expect('a wrong first line, version or nonce is refused', await bad400(ask([L(1)], ['csa-2026-01-lookup 2', HEAD[1], HEAD[2]])) && await bad400(ask([L(1)], ['csa-2026-01-lookup  1', HEAD[1], HEAD[2]])) && await bad400(ask([L(1)], [HEAD[0], 'version 3.1', HEAD[2]])) && await bad400(ask([L(1)], [HEAD[0], 'version 2.1234', HEAD[2]])) && await bad400(ask([L(1)], [HEAD[0], 'version 2.', HEAD[2]])) && await bad400(ask([L(1)], [HEAD[0], HEAD[1], 'nonce ' + NONCE.slice(1)])) && await bad400(ask([L(1)], [HEAD[0], HEAD[1], 'nonce ' + NONCE.toUpperCase()])) && await bad400(ask([L(1)], [HEAD[1], HEAD[0], HEAD[2]])) && await bad400(ask([L(1)], [HEAD[0], HEAD[2]])));
    expect('uppercase hex, a short hash, a third field or a missing space is refused', await bad400(ask([[sha('k').toUpperCase(), sha('f')]])) && await bad400(ask([[sha('k'), sha('f').slice(0, 63) + 'A']])) && await bad400(ask([[sha('k'), sha('f').slice(0, 63)]])) && await bad400(ask([[sha('k'), sha('f'), 'known_safe']])) && await bad400(ask([sha('k') + sha('f')])) && await bad400(ask([sha('k') + '  ' + sha('f')])));
    const valid = ask([L(1), L(2)]);
    expect('an empty line, \\r\\n, a missing or an extra final \\n, a space before or after a line are refused', await bad400(valid.replace('\n', '\n\n')) && await bad400(valid + '\n') && await bad400('\n' + valid) && await bad400(valid.replace(/\n/g, '\r\n')) && await bad400(valid.slice(0, -1)) && await bad400(valid.replace('\n', ' \n')) && await bad400(' ' + valid) && await bad400(''));
    // every byte outside 0x0a and 0x20-0x7e, in the first line, in the middle of a hash, at
    // the end of the last line: always the fixed text
    const enc = (s) => Buffer.from(s, 'latin1');
    const spots = [5, valid.indexOf('\n', 60) + 30, valid.length - 1];
    let byteFails = 0, byteTried = 0;
    for (let b = 0; b < 256; b++) {
      if (b === 0x0a || (b >= 0x20 && b <= 0x7e)) continue;
      for (const at of spots) {
        byteTried++;
        const raw = Buffer.concat([enc(valid.slice(0, at)), Buffer.from([b]), enc(valid.slice(at))]);
        const r = await look(raw), t = await r.text();
        if (r.status !== 400 || t !== 'bad request\n') byteFails++;
      }
    }
    expect(`every byte outside 0x0a and 0x20-0x7e is refused with the fixed text (${byteTried} requests)`, byteTried === 160 * 3 && byteFails === 0);
    expect('the byte check comes before any decoding: an emoji, U+2028, an umlaut, broken UTF-8, NUL and a BOM are refused', await bad400(valid.replace('version', 'version\u{1F600}')) && await bad400(valid.replace('\n', '\u2028')) && await bad400(valid.replace('lookup', 'l\u00f6okup')) && await bad400(Buffer.concat([enc(valid.slice(0, 20)), Buffer.from([0xc3]), enc(valid.slice(20))])) && await bad400(Buffer.concat([Buffer.from([0xff, 0xfe]), enc(valid)])) && await bad400(valid.replace('1\n', '1\u0000\n')) && await bad400('\ufeff' + valid) && await bad400(valid.replace('version 2.60', 'version 2.\u0666\u0660')));
    expect('the parser itself takes only the exact form', lookupRequest(enc(valid)) && lookupRequest(enc(valid)).nonce === NONCE && lookupRequest(enc(valid)).items.length === 2 && lookupRequest(enc(valid.replace('\n', '\t'))) === null && lookupRequest(new Uint8Array(0)) === null);
    expect('a body that is not a request at all: JSON, HTML, a report', await bad400(JSON.stringify(good)) && await bad400('<script>alert(1)</script>\n') && await bad400("'; DROP TABLE bad_hashes; --\n") && env.DB.raw.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name = 'bad_hashes'").get().n === 1);

    // size: content-length first, then the stream with a hard cap
    expect('8192 bytes are read, 8193 are too large', await bad400('a'.repeat(8192)) && (await look('a'.repeat(8193))).status === 413);
    const r413 = await look('a'.repeat(8193));
    expect('too large: 413 with a fixed text', r413.status === 413 && (await r413.text()) === 'too large\n');
    // a body handed out in pieces as it is read: how much was taken shows whether it was all read
    const stream = (total, chunk = 1024) => { const s = { pulled: 0 }; s.body = new ReadableStream({ pull(c) { if (s.pulled >= total) return c.close(); s.pulled += chunk; c.enqueue(new Uint8Array(chunk).fill(0x61)); } }, { highWaterMark: 0 }); return s; };
    const send = (s, headers = {}, path = LK) => worker.fetch(new Request('https://example.org' + path, { method: 'POST', body: s.body, headers, duplex: 'half' }), env, { waitUntil() {} });
    let s = stream(10_000_000), r = await send(s);
    expect('10 MB without a content-length: 413 after reading little more than 8192 bytes', r.status === 413 && s.pulled <= 8192 + 1024);
    s = stream(9000); r = await send(s, { 'content-length': '10' });
    expect('a content-length that says less than comes: 413 all the same', r.status === 413 && s.pulled <= 8192 + 1024);
    s = stream(100); r = await send(s, { 'content-length': '8193' });
    expect('a content-length above 8192: 413 without reading the body', r.status === 413 && s.pulled === 0 && (await r.text()) === 'too large\n');
    expect('the check never stores a report', reportCount() === reportsBefore && posted.length === postedBefore);
    s = stream(10_000_000, 65536); r = await send(s, {}, '/csa-2026-01-report');
    expect('reports use the same capped reader: a large body is refused after 48 KiB and one piece', r.status === 413 && s.pulled <= 49152 + 65536 && (await r.text()) === 'too large\n');
    s = stream(100); r = await send(s, { 'content-length': '49153' }, '/csa-2026-01-report');
    expect('a report with a content-length above 48 KiB is refused without reading', r.status === 413 && s.pulled === 0);
    expect('reports still work as before', (await call('POST', JSON.stringify(good))).status === 200 && (await call('POST', 'x'.repeat(49152))).status === 400 && (await call('POST', 'x'.repeat(49153))).status === 413);

    // the table: in schema.sql and created by the worker, the same columns
    const cols = (sql) => { const x = new DatabaseSync(':memory:'); x.exec(sql); return JSON.stringify(x.prepare('PRAGMA table_info(bad_hashes)').all()); };
    expect('bad_hashes in schema.sql is the table the worker creates', cols(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')) === cols(BAD_HASHES_TABLE) && cols(BAD_HASHES_TABLE).includes('"asked_last"'));
  }
  // ---- tools/bad-hashes-sql.mjs
  {
    const H = (c) => c.repeat(64);
    let thrown = 0;
    const bads = [
      [{ sha256: H('A'), note: 'n', answer: 1 }], [{ sha256: H('a').slice(1), note: 'n', answer: 1 }], [{ sha256: H('g'), note: 'n', answer: 1 }], [{ note: 'n', answer: 1 }],
      [{ sha256: H('a'), note: '', answer: 1 }], [{ sha256: H('a'), note: 'x'.repeat(201), answer: 1 }], [{ sha256: H('a'), note: 'caf\u00e9', answer: 1 }], [{ sha256: H('a'), note: 'a\nb', answer: 1 }],
      [{ sha256: H('a'), note: 'n', answer: 2 }], [{ sha256: H('a'), note: 'n', answer: '1' }], [{ sha256: H('a'), note: 'n', answer: true }], [{ sha256: H('a'), note: 'n' }],
      [{ sha256: H('a'), note: 'n', answer: 1 }, { sha256: H('a'), note: 'm', answer: 0 }], [{ sha256: H('a'), note: 'n', answer: 1, anwser: 0 }], [{ sha256: H('a'), note: 'n', answer: 1, by: '' }], [{ sha256: H('a'), note: 'n', answer: 1, at: 'yesterday' }], [null], 'not a list',
    ];
    for (const b of bads) try { badHashesSql(b); } catch { thrown++; }
    expect('the bad-hashes tool refuses a bad fingerprint, note, answer, by or at, a fingerprint twice and an unknown field', thrown === bads.length && badHashesSql([{ sha256: H('a'), note: 'x'.repeat(200), answer: 0 }]).startsWith('CREATE TABLE IF NOT EXISTS bad_hashes'));
    const x = new DatabaseSync(':memory:'), get = (c) => x.prepare('SELECT * FROM bad_hashes WHERE sha256 = ?').get(H(c));
    x.exec(badHashesSql([{ sha256: H('a'), note: 'seen on two devices', answer: 0 }, { sha256: H('b'), note: "it's malware'); DROP TABLE bad_hashes; --", answer: 1, by: 'b@example.org', at: '2026-11-24T12:00:00Z' }], { by: 'a@example.org', at: '2026-11-24T10:00:00Z' }));
    expect('it writes entries with who and when, and a quote cannot end the SQL string', get('a').answer === 0 && get('a').by === 'a@example.org' && get('a').at === '2026-11-24T10:00:00Z' && get('a').asked === 0 && get('b').note === "it's malware'); DROP TABLE bad_hashes; --" && get('b').by === 'b@example.org');
    x.exec("UPDATE bad_hashes SET asked = 5, asked_last = '2026-11-23' WHERE sha256 = '" + H('a') + "'");
    x.exec(badHashesSql([{ sha256: H('a'), note: 'malware, confirmed', answer: 1 }], { by: 'c@example.org', at: '2026-11-24T13:00:00Z' }));
    expect('loading an entry again releases it: note, answer, by and at change, the counter stays', get('a').answer === 1 && get('a').note === 'malware, confirmed' && get('a').by === 'c@example.org' && get('a').at === '2026-11-24T13:00:00Z' && get('a').asked === 5 && get('a').asked_last === '2026-11-23' && x.prepare('SELECT count(*) AS n FROM bad_hashes').get().n === 2);
    // released through the tool, as the worker answers it
    env.DB.raw.exec(badHashesSql([{ sha256: H('c'), note: 'waiting', answer: 0 }]));
    const q = ['csa-2026-01-lookup 1', 'version 2.60', 'nonce ' + 'f'.repeat(32), 'e'.repeat(64) + ' ' + H('c')].join('\n') + '\n';
    // the check as the worker answers it, waiting for the counter it writes after the answer
    const look = async (body) => { const later = []; const r = await worker.fetch(new Request('https://example.org/csa-2026-01-report/lookup', { method: 'POST', body }), env, { waitUntil(p) { later.push(p); } }); await Promise.all(later); return r; };
    const w1 = (await (await look(q)).text()).trim().split(' ').at(-1);
    env.DB.raw.exec(badHashesSql([{ sha256: H('c'), note: 'confirmed', answer: 1 }]));
    const w2 = (await (await look(q)).text()).trim().split(' ').at(-1);
    expect('the worker answers unknown while an entry waits and known_bad once it is released; counted once that day', w1 === 'unknown' && w2 === 'known_bad' && env.DB.raw.prepare('SELECT asked FROM bad_hashes WHERE sha256 = ?').get(H('c')).asked === 1);
    // --script: the fingerprints the script carries in public
    const sh = readFileSync(new URL('../../gl-helper-triage.sh', import.meta.url), 'utf8');
    const listed = (name) => ((new RegExp(`^${name}='?([0-9a-f\\n]+)'?$`, 'm').exec(sh) || [])[1] || '').split('\n').filter(Boolean);
    const want = [...listed('GLH_SHAS'), ...listed('BD_INIT_SHA'), ...listed('BD_ULOGD_SHAS')], got = scriptHashes(sh);
    expect('--script takes GLH_SHAS, BD_INIT_SHA and BD_ULOGD_SHAS from the script, each with answer 1 and a note', want.length >= 10 && got.map((e) => e.sha256).join() === want.join() && got.every((e) => e.answer === 1 && /^[\x20-\x7e]{10,200}$/.test(e.note)));
    let missing = false; try { scriptHashes(sh.replace(/^BD_INIT_SHA=/m, 'XX=')); } catch { missing = true; }
    expect('--script stops when one of the lists is missing', missing);
    const cli = execFileSync(process.execPath, [new URL('../tools/bad-hashes-sql.mjs', import.meta.url).pathname, '--script', new URL('../../gl-helper-triage.sh', import.meta.url).pathname], { encoding: 'utf8' });
    const y = new DatabaseSync(':memory:'); y.exec(cli);
    expect('the command line with --script gives SQL that loads every one of them as released', y.prepare('SELECT count(*) AS n FROM bad_hashes WHERE answer = 1').get().n === want.length && y.prepare('SELECT by FROM bad_hashes LIMIT 1').get().by === 'gl-helper-triage.sh');
    env.DB.raw.exec(cli);
    const glh = listed('GLH_SHAS')[0], rs = await (await call('POST', q.replace(H('c'), glh), {}, '/csa-2026-01-report/lookup')).text();
    expect('after the first fill, a file of the malware is known_bad', rs.endsWith(`${glh} known_bad\n`));
  }
  // ---- the generated modules match their sources (CI diffs only dashboard.js)
  {
    const { KNOWN_RELEASE_HASHES } = await import('../src/known.js'), { RESULT } = await import('../src/result.js');
    const json = Object.keys(JSON.parse(readFileSync(new URL('../src/known-hashes.json', import.meta.url), 'utf8')));
    expect('known.js holds exactly the fingerprints of known-hashes.json (run "node build.mjs")', KNOWN_RELEASE_HASHES.size === json.length && json.every((x) => KNOWN_RELEASE_HASHES.has(x)));
    expect('result.js is result.html as it is (run "node build.mjs")', RESULT === readFileSync(new URL('../src/result.html', import.meta.url), 'utf8'));
  }
  // ---- the result page: the field for review, 0 none, 1 some, 2 known malware among them
  {
    const { RESULT } = await import('../src/result.js');
    const src = RESULT.slice(RESULT.indexOf('const B32 = '), RESULT.indexOf('function read() {'));
    const { decode, encode, parse, B32 } = new Function(src + '; return { decode, encode, parse, B32 };')();
    const consts = /^const MALWARE = .*$/m.exec(RESULT)[0];
    const classify = new Function(consts + '\n' + RESULT.slice(RESULT.indexOf('function classify(c) {'), RESULT.indexOf('function render() {')) + '; return classify;')();
    const typeOf = new Function('return ' + /const typeOf = (\(k\) => \(.*?\)), types =/.exec(RESULT)[1])();
    const pick = (name) => { const i = RESULT.indexOf(`const ${name} = {`), j = RESULT.indexOf('\n};\n', i); return new Function('GC_OFF', 'return ' + RESULT.slice(i + `const ${name} = `.length, j + 2))('x'); };
    const T = pick('T'), NAMES = pick('NAMES');
    // a code with the two bits of the field set as given, whatever encode() does
    const withRv = (code, rv) => { const v = [...code.slice(0, 8)].map((ch) => B32.indexOf(ch)); v[7] = (v[7] & ~3) | rv; let sum = 0; v.forEach((x, i) => { sum += (i + 1) * x; }); return v.map((x) => B32[x]).join('') + B32[sum % 31]; };
    const base = encode({ minor: 60, p: 'r', k: [], g: '0', n: '0', f: '0', rv: 0 });
    const c0 = decode(withRv(base, 0)), c1 = decode(withRv(base, 1)), c2 = decode(withRv(base, 2)), c3 = decode(withRv(base, 3));
    expect('the field for review: 0 none, 1 some, 2 some with known malware, 3 read as 1', c0.rv === 0 && !c0.lb && c1.rv === -1 && !c1.lb && c2.rv === -1 && c2.lb === true && c3.rv === -1 && !c3.lb && withRv(base, 0) === base);
    expect('encode writes 2 for known malware and 1 for some, so the hand form and its code keep working', encode({ minor: 60, p: 'r', k: [], g: '0', n: '0', f: '0', rv: -1, lb: true }) === withRv(base, 2) && encode({ minor: 60, p: 'r', k: [], g: '0', n: '0', f: '0', rv: 1 }) === withRv(base, 1) && decode(encode({ minor: 0, p: 'k', k: ['mk'], g: 'x', n: '0', f: '0', rv: 0 })).k.join() === 'mk');
    expect('nothing else on the device: 2 means infected by the community list, 1 and 3 nothing found', classify(c2).main === 'l' && classify(c1).main === 'c' && classify(c3).main === 'c' && classify(c0).main === 'c' && classify({ ...c1, n: '1' }).main === 'cr' && classify({ ...c2, n: '1' }).main === 'l');
    const kc = (k, lb) => classify({ ...decode(withRv(encode({ minor: 60, p: 'r', k, g: '0', n: '0', f: '0', rv: 0 }), lb ? 2 : 1)) });
    expect('with other traces: the malware, a remote shell and the older backdoor alone keep their result; a command or the installer becomes infected', kc(['mk'], true).main === 'm' && kc(['ps'], true).main === 's' && kc(['bi'], true).main === 'b' && kc(['cc'], true).main === 'l' && kc(['it'], true).main === 'l' && kc(['cc'], false).main === 'a' && kc(['mk', 'bi'], true).also === true && kc(['pe'], true).main === 'l');
    expect('a code with 1 reads exactly as before', JSON.stringify(classify(c1)) === JSON.stringify(classify({ ...c1, lb: undefined })) && parse('#' + withRv(base, 1), '/').rv === -1 && !parse('#' + withRv(base, 1), '/').lb && parse('#v=2.39&p=r&k=cc&rv=3', '/2026-01/').lb === undefined);
    expect('known malware is a finding of type ioc, listed as such, and the other changes stay listed for review', typeOf('lb') === 'ioc' && typeOf('rv') === 'review' && NAMES.lb === 'IOC  lookup-bad');
    expect('its texts are there in English, German and Chinese, and each says that --fix does not remove it', ['en', 'de', 'zh'].every((l) => T[l].kinds.lb && T[l].kinds.lb.every((x) => x.length > 8) && T[l].kinds.lb[1].includes('--fix') && T[l].results.l && T[l].results.l[3].length === 2 && T[l].results.l[3].some((x) => x.includes('--fix'))) && T.en.results.l[0] === 'INFECTED' && T.de.results.l[0] === 'INFIZIERT' && T.zh.results.l[0] === T.zh.results.m[0]);
  }
  // ---- KV read through memory, and KV that refuses reads
  {
    const kvRead = env.REPORTS.get; let reads = 0;
    await env.REPORTS.put('script/csa-2026-01-fix', JSON.stringify({ commit: 'kv', body: '#!/bin/sh\nVERSION=7.79\n', checked: Date.now() }));
    env.REPORTS.get = async (k) => { reads++; return kvRead(k); };
    for (let i = 0; i < 5; i++) { await call('GET', undefined, {}, '/2026-01/'); await call('GET', undefined, {}, '/csa-2026-01-fix'); await call('GET', undefined, {}, '/2026-01/reported.json'); }
    expect('fifteen calls to the public addresses read each key from KV once', reads === 3);
    env.REPORTS.get = async () => { throw new Error('KV GET failed: 429 Too Many Requests'); };
    const fromMemory = await call('GET', undefined, {}, '/csa-2026-01-fix');
    expect('when KV refuses reads, what is known stays served', fromMemory.status === 200 && (await fromMemory.text()).includes('VERSION=7.79'));
    kvMemo.clear();
    const scans = env.DB.prepare; let dbCalls = 0; env.DB.prepare = (sql) => { dbCalls++; return scans(sql); };
    const gone = await call('GET', undefined, {}, '/csa-2026-01-fix'), tab = await call('GET', undefined, {}, '/2026-01/reported.json'), page = await call('GET', undefined, {}, '/2026-01/');
    expect('with nothing known, the script download goes to GitHub', gone.status === 302 && gone.headers.get('location') === 'https://raw.githubusercontent.com/admonstrator/glinet-csa-2026-01/main/gl-helper-triage.sh');
    expect('the reported table answers 503 rather than reading all reports on every call', tab.status === 503 && dbCalls === 0);
    expect('the result page is still served, without a firmware list', page.status === 200 && (await page.text()).includes('const FIRMWARE = null;'));
    env.DB.prepare = scans; env.REPORTS.get = kvRead;
  }
  // ---- the figures of the advisory (docs/figures.md): src/figures.js, and in live.json
  {
    const { foldFigures, figuresOf, isFigureState } = await import('../src/figures.js');
    const { shape, ts, SHAPE_SHA256 } = await import('../src/shape.js');
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const page = readFileSync(new URL('../src/dashboard.html', import.meta.url), 'utf8'), shapeSrc = readFileSync(new URL('../src/shape.js', import.meta.url), 'utf8');
    const block = page.slice(page.indexOf('\nconst ts = (s) =>') + 1, page.indexOf('\nconst count = (rows, key) =>') + 1);
    expect('shape.js is the code of dashboard.html that shapes a report, as it is, with its SHA-256 (run "node build.mjs")', block.startsWith('const ts = (s) =>') && block.includes('\nfunction shape(x) {') && shapeSrc.includes('\n' + block + 'export { shape, ts };\n') && SHAPE_SHA256 === nodeCrypto.createHash('sha256').update(block).digest('hex'));

    // The plain count over all reports at once, the way the figures were worked out by hand
    // until 28 November: the reference of the lead, with only its input (rows instead of an
    // export file) and its output (a value instead of stdout) changed. It is the oracle.
    const oracle = (rows) => {
      const M = { shape, ts };
      const all = rows.map((x) => M.shape(x));
      const built = (r) => (/(\d{4}-\d\d-\d\d)\s*$/.exec(r.firmware || '') || [])[1] || '';
      const secFw = (r) => r.kvm ? (/V?1\.10\.3 release1\b/i.test(r.firmware) || (/^V?1\.8\.7/i.test(r.firmware) && /rmq1/i.test(r.model))) : r.type === 'Router' && built(r) >= '2026-11-22';
      const minute = (ms) => new Date(ms).toISOString().slice(0, 16) + 'Z';
      const pair = (a) => [a.filter((r) => r.ioc > 0).length, a.length];
      const best = new Map();
      for (const r of all) { if (!r.dev) continue; const b = best.get(r.dev); if (!b || r.ioc > b.ioc || (r.ioc === b.ioc && r.recv > b.recv)) best.set(r.dev, r); }
      const pool = all.filter((r) => (!r.dev || best.get(r.dev) === r) && !r.isTest);
      const nt = all.filter((r) => !r.isTest);
      const R = pool.filter((r) => r.type === 'Router'), K = pool.filter((r) => r.kvm);
      const Rn = R.filter((r) => !secFw(r)), Kn = K.filter((r) => !secFw(r));
      const f = { as_of: minute(Math.max(...all.map((r) => r.recv))) };
      f.devices = R.length + K.length; f.routers = R.length; f.kvm = K.length;
      f.updated = { routers: pair(R.filter(secFw)), kvm: pair(K.filter(secFw)) };
      f.open = { routers: pair(Rn), kvm: pair(Kn) };
      const byDev = new Map();
      for (const r of nt) if (r.dev) (byDev.get(r.dev) || byDev.set(r.dev, []).get(r.dev)).push(r);
      let cr = 0, ck = 0, still = 0;
      for (const list of byDev.values()) {
        list.sort((a, b) => a.recv - b.recv);
        const i = list.findIndex((r) => r.ioc > 0 && !secFw(r)); if (i < 0) continue;
        const later = list.slice(i + 1).filter(secFw); if (!later.length) continue;
        if (later[later.length - 1].kvm) ck++; else cr++;
        if (later.some((r) => r.ioc > 0)) still++;
      }
      f.cleaned = { routers: cr, kvm: ck, still };
      f.shell = pool.filter((r) => r.shell).length;
      f.goodcloud = { on: pair(Rn.filter((r) => r.goodcloud === 'on')), off: pair(Rn.filter((r) => r.goodcloud === 'off')) };
      const pipe = new Map();
      for (const r of nt) { if (secFw(r)) continue; const t = M.ts(r.pipe_time); if (t >= Date.parse('2026-11-22T00:00Z')) { const k = r.dev || r.id; pipe.set(k, Math.max(pipe.get(k) || 0, t)); } }
      f.pipe = { since22: pipe.size, since24: [...pipe.values()].filter((t) => t >= Date.parse('2026-11-24T00:00Z')).length, last: pipe.size ? minute(Math.max(...pipe.values())) : null };
      const cc = nt.filter((r) => !secFw(r) && r.kinds.includes('cloud-command')).map((r) => M.ts(r.state_file_time)).filter(isFinite);
      f.newest_command = cc.length ? minute(Math.max(...cc)) : null;
      const bd = new Map();
      for (const r of nt) if (r.bd) { const k = r.dev || r.id; (bd.get(k) || bd.set(k, []).get(k)).push(r); }
      f.backdoor = { devices: bd.size, mt2500: [...bd.values()].filter((v) => v[0].model === 'mt2500').length, after_update: [...bd.values()].filter((v) => v.some(secFw)).length };
      const rel = (re) => { const a = K.filter((r) => re.test(r.firmware)); return [...pair(a), a.filter((r) => r.kinds.includes('marker')).length]; };
      f.kvm_release = { rm10_release8: rel(/V1\.10\.3 release8/), rm10rc_release3: rel(/V1\.10\.3 release3/) };
      const ser = new Map();
      for (const r of Rn) { const m = /^(\d+)\.(\d+)/.exec(r.fw); if (!m) continue; const old = +m[1] < 4 || (+m[1] === 4 && +m[2] <= 6); const k = old ? '4.6 and older' : m[1] + '.' + m[2]; const s = ser.get(k) || { name: k, hit: 0, of: 0, o: old ? [0, 0] : [+m[1], +m[2]] }; s.of++; if (r.ioc > 0) s.hit++; ser.set(k, s); }
      f.series = [...ser.values()].sort((a, b) => a.o[0] - b.o[0] || a.o[1] - b.o[1]).map(({ name, hit, of }) => ({ name, hit, of }));
      const withT = Rn.filter((r) => r.ioc > 0 && isFinite(M.ts(r.state_file_time)));
      const W0 = Date.parse('2026-11-20T22:00Z'), W1 = Date.parse('2026-11-21T08:00Z');
      const byModel = {};
      for (const r of withT) (byModel[r.model] = byModel[r.model] || []).push(Math.floor(M.ts(r.state_file_time) / 60000));
      const sw = [];
      for (const [model, mins] of Object.entries(byModel)) {
        const inW = mins.filter((m) => m * 60000 >= W0 && m * 60000 < W1); if (!inW.length || mins.length < 5) continue;
        const c = {}; for (const m of inW) c[m] = (c[m] || 0) + 1;
        const top = +Object.entries(c).sort((a, b) => b[1] - a[1] || a[0] - b[0])[0][0];
        sw.push({ model: 'GL-' + model.toUpperCase(), at: minute(top * 60000), n: mins.filter((m) => Math.abs(m - top) <= 1).length, of: mins.length });
      }
      f.sweep = sw.sort((a, b) => a.at.localeCompare(b.at) || a.model.localeCompare(b.model));
      const hours = {}; let used = 0;
      for (const r of withT) { const t = M.ts(r.state_file_time); if (t < Date.parse('2026-11-19T00:00Z') || t >= Date.parse('2026-11-22T00:00Z')) continue; used++; const h = new Date(t).toISOString().slice(0, 13); hours[h] = (hours[h] || 0) + 1; }
      f.hours = Object.entries(hours).sort().map(([hour, n]) => ({ hour, n }));
      f.hours_routers = used;
      return f;
    };
    // the reference reads an export, which is ordered by the time of receipt
    const byTime = (rows) => [...rows].sort((a, b) => (a.received < b.received ? -1 : a.received > b.received ? 1 : a.id < b.id ? -1 : 1));
    const ref = (rows) => oracle(byTime(rows));

    // Made-up reports, a few for every rule of docs/figures.md. Device IDs as the worker
    // stores them: 16 hex characters.
    const D = (name) => nodeCrypto.createHash('sha256').update('figures ' + name).digest('hex').slice(0, 16);
    const base = {
      schema: 10, tool: '2.60', platform: 'openwrt', model: 'axt1800', firmware: '4.8.3 release2 build 540 2026-10-02', checked_at: '2026-11-25 10:00:00 UTC', uptime_s: 3600,
      ioc: 0, persist: 0, review: 0, findings: [], quick_check: false, shell_started: '', shell_ports: [], pipe_time: '', state_file_time: '', files: [], persistence: [], fw_rules: [], commands: [],
      device_id: '', goodcloud: 'unknown', cloud_client: '', astrowarp: 'off', state_file_size: -1, review_items: [], cloud_bound: 'unknown', rtty_ssh: 'off', rtty_web: 'off', note: '', state_file_first: '', vendor_cleanup: 'off',
    };
    const FX = [];
    const add = (dev, received, o = {}) => FX.push({ id: 'fx' + String(FX.length).padStart(4, '0'), received, report: { ...base, device_id: dev ? D(dev) : '', ...o } });
    const at = (day, hms) => `2026-11-${day}T${hms}.000Z`;
    const MK = ['marker /etc/config/.gl/gl-helper'], WATCH = ['marker /etc/glinet/.cache/watch.sh'], PIPE = ['pipe /tmp/f'], BDF = ['backdoor-file /bin/ulogd'];
    const FIXED = '4.8.4 release1 build 600 2026-11-22', TEST = { model: 'unknown', platform: 'unknown', firmware: 'unknown' };
    const kvm = (o) => ({ platform: 'glkvm-rm1', model: 'rm1', firmware: 'V1.10.2 release2', ...o });
    // the pool: most traces, then the newest; a device whose chosen report is a test drops out; each report without an ID counts
    add('a1', at(21, '10:00:00'), { ioc: 2, findings: [...MK, 'persist-ref /etc/rc.local'], goodcloud: 'on' });
    add('a1', at(23, '10:00:00'), { firmware: '4.9.1 release1 build 600 2026-10-20' });
    add('a1', at(22, '10:00:00'), { ioc: 2, findings: [...MK, 'persist-ref /etc/rc.local'], goodcloud: 'off' });
    add('a2', at(21, '10:00:00'));
    add('a2', at(23, '10:00:00'), { ...TEST, findings: PIPE });
    add('a3', at(21, '09:00:00'), TEST);
    add('a3', at(22, '09:00:00'), { firmware: '4.7.5' });
    add('', at(22, '11:00:00'), { firmware: '4.7.5' });
    add('', at(22, '11:05:00'), { firmware: '4.7.5' });
    add('', at(22, '11:10:00'), { ...TEST, findings: PIPE });
    // security firmware: routers by build date, KVMs on V1.10.3 release1, a GL-RMQ1 on 1.8.7
    add('b1', at(23, '08:00:00'), { firmware: FIXED });
    add('b2', at(23, '08:05:00'), { firmware: '4.8.4 release1 build 590 2026-11-21' });
    add('b3', at(23, '08:10:00'), kvm({ firmware: 'V1.10.3 release1' }));
    add('b4', at(23, '08:15:00'), kvm({ platform: 'glkvm-rmq1', model: 'rmq1', firmware: '1.8.7 release1' }));
    add('b5', at(23, '08:20:00'), kvm({ model: 'rm10', firmware: 'V1.8.7 release1' }));
    add('b6', at(23, '08:25:00'), kvm({ firmware: 'V1.10.3 release10' }));
    add('b7', at(23, '08:30:00'), { firmware: FIXED, ioc: 1, findings: MK });
    add('b8', at(23, '08:35:00'), kvm({ firmware: 'V1.10.3 release1', ioc: 1, findings: WATCH }));
    // cleaned: traces, then security firmware; security firmware before the traces does not count; still; by the last later report
    add('c1', at(21, '12:00:00'), { ioc: 1, findings: MK });
    add('c1', at(23, '12:00:00'), { firmware: FIXED });
    add('c2', at(21, '12:00:00'), kvm({ ioc: 1, findings: WATCH }));
    add('c2', at(23, '12:00:00'), kvm({ firmware: 'V1.10.3 release1' }));
    add('c3', at(22, '12:00:00'), { firmware: FIXED });
    add('c3', at(23, '12:00:00'), { ioc: 1, findings: MK });
    add('c4', at(21, '12:00:00'), { ioc: 1, findings: MK });
    add('c4', at(24, '12:00:00'), { firmware: FIXED, ioc: 1, findings: MK });
    add('c5', at(21, '13:00:00'), { ioc: 1, findings: MK });
    add('c5', at(22, '13:00:00'), kvm({ firmware: 'V1.10.3 release1' }));
    add('c5', at(24, '13:00:00'), { firmware: FIXED });
    add('c6', at(22, '14:00:00'), { firmware: FIXED, ioc: 1, findings: MK });
    add('c6', at(23, '14:00:00'), { ioc: 1, findings: MK });
    add('c6', at(24, '14:00:00'), { firmware: FIXED });
    add('c7', at(21, '15:00:00'), { ioc: 1, findings: MK });
    add('c7', at(22, '15:00:00'), { firmware: FIXED });
    add('c7', at(23, '15:00:00'), { ioc: 1, findings: MK });
    // the shell's pipe: from 22 November, from 24 November, by device, security firmware and tests left out, cut to the minute
    add('d1', at(22, '01:00:00'), { ioc: 1, findings: PIPE, pipe_time: '2026-11-21 23:59:59 UTC' });
    add('d2', at(24, '00:30:00'), { ioc: 1, findings: PIPE, pipe_time: '2026-11-23 23:59:59 UTC' });
    add('d2', at(24, '06:00:00'), { ioc: 1, findings: PIPE, pipe_time: '2026-11-24 00:00:00 UTC' });
    add('d3', at(22, '02:00:00'), { ioc: 1, findings: PIPE, pipe_time: '2026-11-22 00:00:00 UTC' });
    add('d4', at(25, '01:00:00'), { firmware: FIXED, ioc: 1, findings: PIPE, pipe_time: '2026-11-25 00:00:00 UTC' });
    add('', at(26, '08:00:00'), { ioc: 1, findings: PIPE, pipe_time: '2026-11-26 07:30:45 UTC' });
    add('d6', at(27, '08:00:00'), { ...TEST, pipe_time: '2026-11-27 00:00:00 UTC' });
    // the newest command from the cloud: shape() makes one of an empty state file with AstroWarp off, not with it on; security firmware left out
    add('e1', at(22, '03:00:00'), { state_file_size: 0, state_file_time: '2026-11-21 18:58:30 UTC' });
    add('e2', at(23, '03:00:00'), { astrowarp: 'on', state_file_size: 0, state_file_time: '2026-11-23 10:00:00 UTC' });
    add('e3', at(23, '04:00:00'), { firmware: FIXED, ioc: 1, findings: ['cloud-command /etc/mp_ip_mapping_info'], state_file_size: 0, state_file_time: '2026-11-21 20:00:00 UTC' });
    // the older backdoor: by the model of the first such report, on security firmware, a test left out
    add('f1', at(21, '14:00:00'), { model: 'mt2500', ioc: 1, findings: BDF });
    add('f1', at(24, '14:00:00'), { model: 'mt2500', firmware: FIXED, ioc: 1, findings: BDF });
    add('f2', at(21, '15:00:00'), { model: 'ax1800', ioc: 1, findings: BDF });
    add('f2', at(22, '15:00:00'), { model: 'mt2500', ioc: 1, findings: BDF });
    add('', at(22, '16:00:00'), { model: 'mt2500', ioc: 1, findings: BDF });
    add('f4', at(22, '17:00:00'), { ...TEST, ioc: 1, findings: BDF });
    // the KVM releases that keep the malware
    add('g1', at(24, '09:00:00'), kvm({ model: 'rm10', firmware: 'V1.10.3 release8', ioc: 1, findings: WATCH }));
    add('g2', at(24, '09:05:00'), kvm({ model: 'rm10', firmware: 'V1.10.3 release8' }));
    add('g3', at(24, '09:10:00'), kvm({ model: 'rm10', firmware: 'V1.10.3 release3', ioc: 1, findings: ['installer-trace /bin/netstat'] }));
    // the series: 4.6 and older as one, a firmware without a version left out, 4.12 after 4.8
    add('h1', at(24, '10:00:00'), { firmware: '4.5.8', ioc: 1, findings: MK });
    add('h2', at(24, '10:05:00'), { firmware: '4.6.2 release1' });
    add('h3', at(24, '10:10:00'), { firmware: '4.12.1 release1 build 700 2026-11-21', ioc: 1, findings: MK });
    add('h4', at(24, '10:15:00'), { firmware: 'unknown', ioc: 1, findings: MK });
    add('h5', at(24, '10:20:00'), { firmware: '3.215' });
    // GoodCloud on open routers only, and a remote shell on a device that is neither router nor KVM
    add('i1', at(24, '11:00:00'), { goodcloud: 'on', ioc: 1, findings: MK });
    add('i2', at(24, '11:05:00'), { goodcloud: 'on' });
    add('i3', at(24, '11:10:00'), { goodcloud: 'on', firmware: FIXED });
    add('i4', at(24, '11:15:00'), { platform: 'mystery', model: 'x1', firmware: '1.0', ioc: 1, findings: ['connection 170.39.226.0/24'] });
    // the sweep and the hours: routers with traces and a state file, by model
    const swept = (model, times, o = {}) => times.forEach((t, i) => add(`s ${model} ${i} ${o.firmware || ''}`, new Date(Date.parse('2026-11-25T12:00:00Z') + FX.length * 1000).toISOString(), { model, ioc: 1, findings: MK, state_file_time: t, ...o }));
    swept('mt3000', ['2026-11-20 22:15:10 UTC', '2026-11-20 22:15:40 UTC', '2026-11-20 22:16:05 UTC', '2026-11-20 22:14:59 UTC', '2026-11-20 23:30:00 UTC', '2026-11-21 09:00:00 UTC']);
    swept('be3600', ['2026-11-20 22:15:00 UTC', '2026-11-20 22:15:30 UTC', '2026-11-20 23:00:00 UTC', '2026-11-20 23:00:30 UTC', '2026-11-20 21:59:59 UTC']);
    swept('x3000', ['2026-11-20 22:00:00 UTC', '2026-11-21 08:00:00 UTC', '2026-11-21 08:00:00 UTC', '2026-11-21 08:00:00 UTC', '2026-11-21 07:59:59 UTC']);
    swept('ax1800', ['2026-11-20 23:00:00 UTC', '2026-11-20 23:00:00 UTC', '2026-11-20 23:00:00 UTC', '2026-11-20 23:00:00 UTC']);
    swept('ax1800', ['2026-11-20 23:00:00 UTC'], { firmware: FIXED });
    swept('mt6000', ['2026-11-19 00:00:00 UTC', '2026-11-18 23:59:59 UTC', '2026-11-22 00:00:00 UTC', '2026-11-21 12:00:00 UTC', '2026-11-21 12:30:00 UTC']);
    // reports that shape() cannot read: left out, and they stop nothing
    const BAD = [
      { id: 'fxbad1', received: at(24, '12:00:00'), report: { schema: 9, platform: 'openwrt', model: 'mt6000', firmware: '4.8.3', ioc: 2, findings: ['marker /etc/config/.gl'] } },
      { id: 'fxbad2', received: at(24, '12:01:00'), report: null },
      { id: 'fxbad3', received: at(24, '12:02:00'), report: { ...base, platform: 7, ioc: 3, findings: MK } },
    ];
    const newest = Date.parse(at(27, '08:00:00'));
    const HAND = {
      as_of: '2026-11-27T08:00Z', devices: 67, routers: 58, kvm: 9,
      updated: { routers: [5, 8], kvm: [1, 3] }, open: { routers: [40, 50], kvm: [3, 6] },
      cleaned: { routers: 5, kvm: 1, still: 1 }, shell: 6, goodcloud: { on: [1, 2], off: [1, 1] },
      pipe: { since22: 3, since24: 2, last: '2026-11-26T07:30Z' }, newest_command: '2026-11-21T18:58Z',
      backdoor: { devices: 3, mt2500: 2, after_update: 1 }, kvm_release: { rm10_release8: [1, 2, 1], rm10rc_release3: [1, 1, 0] },
      series: [{ name: '4.6 and older', hit: 1, of: 3 }, { name: '4.7', hit: 0, of: 3 }, { name: '4.8', hit: 37, of: 42 }, { name: '4.12', hit: 1, of: 1 }],
      sweep: [{ model: 'GL-X3000', at: '2026-11-20T22:00Z', n: 1, of: 5 }, { model: 'GL-BE3600', at: '2026-11-20T22:15Z', n: 2, of: 5 }, { model: 'GL-MT3000', at: '2026-11-20T22:15Z', n: 4, of: 6 }],
      hours: [['2026-11-19T00', 1], ['2026-11-20T21', 1], ['2026-11-20T22', 7], ['2026-11-20T23', 7], ['2026-11-21T07', 1], ['2026-11-21T08', 3], ['2026-11-21T09', 1], ['2026-11-21T12', 2], ['2026-11-21T18', 1]].map(([hour, n]) => ({ hour, n })),
      hours_routers: 24,
    };
    const ALL = [...FX, ...BAD], mine = figuresOf(foldFigures(null, ALL), newest), want = ref(FX);
    const part = (...keys) => same(keys.map((k) => mine[k]), keys.map((k) => HAND[k]));
    expect('figures: the fields of docs/figures.md, in its order', Object.keys(mine).join() === 'as_of,devices,routers,kvm,updated,open,cleaned,shell,goodcloud,pipe,newest_command,backdoor,kvm_release,series,sweep,hours,hours_routers' && Object.keys(mine.cleaned).join() === 'routers,kvm,still' && Object.keys(mine.pipe).join() === 'since22,since24,last' && Object.keys(mine.sweep[0]).join() === 'model,at,n,of');
    expect('figures: the pool takes per device the report with the most traces, then the newest, drops a device whose chosen report is a test, and counts each report without an ID', part('devices', 'routers', 'kvm', 'open') && same(mine.series[1], HAND.series[1]) && !mine.series.some((s) => s.name === '4.9'));
    expect('figures: security firmware by build date for routers, V1.10.3 release1 for KVMs, 1.8.7 only on a GL-RMQ1', part('updated', 'open'));
    expect('figures: cleaned counts traces before security firmware, not after it, by the last later report, and those still with traces', part('cleaned'));
    expect('figures: the shell, GoodCloud on open routers, the pipe from 22 and from 24 November by device and to the minute', part('shell', 'goodcloud', 'pipe'));
    expect('figures: the newest command is what shape() takes for one, outside security firmware', part('newest_command'));
    expect('figures: the older backdoor by device, by the model of its first report, and after an update', part('backdoor'));
    expect('figures: the KVM releases, with traces, all, with the malware files', part('kvm_release'));
    expect('figures: the series group 4.6 and older, leave out an unknown version and put 4.12 after 4.8', part('series'));
    expect('figures: the sweep keeps the window to the minute, needs five routers, takes the earliest of equal minutes and counts all times near it', part('sweep'));
    expect('figures: the hours keep their window, sorted', part('hours', 'hours_routers', 'as_of'));
    expect('figures: all of it, as worked out by hand', same(mine, HAND));
    expect('figures: the same as the plain count of the reference over all reports at once', same(mine, want) && same(want, HAND));
    expect('figures: a report shape() cannot read is left out', same(figuresOf(foldFigures(null, FX), newest), mine));
    // the same reports in any chunks, in any order, some twice, through KV in between: the same state, to the byte
    let seed = 20261128;
    const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
    const once = JSON.stringify(foldFigures(null, ALL));
    let alike = 0;
    for (let t = 0; t < 40; t++) {
      const rows = [...ALL, ...ALL.filter(() => rnd() < 0.3)];
      for (let i = rows.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [rows[i], rows[j]] = [rows[j], rows[i]]; }
      let state = null;
      for (let i = 0; i < rows.length;) { const k = 1 + Math.floor(rnd() * 25); state = foldFigures(JSON.parse(JSON.stringify(state)), rows.slice(i, i + k)); i += k; }
      if (JSON.stringify(state) === once) alike++;
    }
    expect('figures: the fold in random chunks, shuffled, with repeated reports, gives the state of one pass, 40 times', alike === 40);
    const half = foldFigures(null, FX.slice(0, 50)), kept = JSON.stringify(half), more = foldFigures(half, FX.slice(50));
    expect('figures: the fold leaves the state it was given as it was', JSON.stringify(half) === kept && JSON.stringify(more) === JSON.stringify(foldFigures(null, FX)));
    const st = foldFigures(null, FX), stText = JSON.stringify(st), figText = JSON.stringify(mine);
    expect('figures: the state is plain JSON, one short array per device, and the figures hold no device ID and no report', isFigureState(JSON.parse(stText)) && st.dev.every((e) => e.length <= 13) && st.dev.some((e) => e.length === 4) && !FX.some((x) => (x.report.device_id && figText.includes(x.report.device_id)) || figText.includes(x.id)) && !/AX1800|MT6000|AXT1800/.test(figText));
    let threw = false; try { foldFigures({ v: 1, dev: 'x' }, FX); } catch { threw = true; }
    expect('figures: a state of another shape is not taken for one', threw && !isFigureState({ v: 1, dev: [], one: [{}], cmd: null }) && !isFigureState(null) && isFigureState(foldFigures(null, [])));
    const empty = figuresOf(foldFigures(null, []), newest);
    expect('figures: without reports every count is 0 and every time null', empty.devices === 0 && empty.pipe.last === null && empty.newest_command === null && empty.series.length === 0 && empty.sweep.length === 0 && empty.hours_routers === 0);
    // the tool, on the made-up reports as an export (which holds no ids)
    const { exportFigures } = await import('../tools/figures.mjs');
    const exported = byTime(FX).map((x) => JSON.stringify({ received: x.received, report: x.report })).join('\n') + '\n';
    const tool = exportFigures(exported, { chunk: 20, overlap: 5 });
    expect('tools/figures.mjs folds an export in overlapping chunks to the figures of the reference', tool.chunks > 5 && same(tool.figures, oracle(exported.trim().split('\n').map((l) => JSON.parse(l)))) && same(tool.figures, HAND));

    // ---- through the worker: live.json with a D1 of the made-up reports
    const { FIGURES_SQL, figuresRun } = await import('../src/index.js');
    const fdb = d1(), fenv = { ...env, DB: fdb };
    const fput = fdb.raw.prepare('INSERT INTO reports (id, received, report) VALUES (?, ?, ?)');
    const insert = (rows) => { for (const x of rows) fput.run(x.id, x.received, x.report === null ? '{not json' : JSON.stringify(x.report)); };
    insert(ALL);
    // every read of the figures: its bounds and how many rows it gave
    const reads = [], prep = fdb.prepare;
    fdb.prepare = (sql) => { const s = prep(sql); return sql !== FIGURES_SQL ? s : { ...s, bind: (...a) => { const b = s.bind(...a); return { ...b, all: async () => { const r = await b.all(); reads.push({ from: a[0], upto: a[1], after: a[2], rows: r.results.length }); return r; } }; } }; };
    const FKEY = 'figures/csa-2026-01', DKEY = 'figures/csa-2026-01-devices';
    store.delete(FKEY); store.delete(DKEY); figuresRun.next = 0;
    const ask = async (e = fenv, path = '/2026-01/live.json', init) => {
      const later = [], r = await worker.fetch(new Request('https://csa.example.org' + path, init), e, { waitUntil: (p) => later.push(p) });
      const storedAtAnswer = store.has(FKEY), raw = await r.text();
      await Promise.all(later);
      return { r, raw, j: raw ? JSON.parse(raw) : null, storedAtAnswer };
    };
    const devices = () => JSON.parse(store.get(DKEY)), stale = () => { store.set(FKEY, JSON.stringify({ ...JSON.parse(store.get(FKEY)), checked: 0 })); figuresRun.next = 0; };
    const expectAs = (got, rows) => same({ ...got, as_of: ref(rows).as_of }, ref(rows));
    const asOfNow = (f) => /^\d{4}-\d\d-\d\dT\d\d:\d\dZ$/.test(f.as_of) && Math.abs(Date.parse(f.as_of) - Date.now()) < 120_000;
    const first = await ask();
    expect('live.json: while nothing is kept, figures is null and the run starts behind the answer, not in it', first.r.status === 200 && first.j.figures === null && !first.storedAtAnswer && store.has(FKEY) && reads.length > 0 && reads[0].from === '');
    const second = await ask();
    expect('live.json: after the run it has script, reported and figures, the figures as the reference counts them, as of the run', Object.keys(second.j).join() === 'script,reported,figures' && expectAs(second.j.figures, FX) && asOfNow(second.j.figures));
    expect('live.json: the figures are kept as checked and body, the devices as rules, upto, full and state', Object.keys(JSON.parse(store.get(FKEY))).join() === 'checked,body' && Object.keys(devices()).join() === 'rules,upto,full,state' && /^[0-9a-f]{64}$/.test(devices().rules) && devices().upto === at(27, '08:00:00') && devices().full === new Date(Date.now() - 4 * 3600_000).toISOString().slice(0, 10) && isFigureState(devices().state));
    const served = /^VERSION=(.*)$/m.exec(JSON.parse(store.get('script/csa-2026-01-fix')).body)[1];
    expect('live.json: script and reported are as before: the version served and the reported table', second.j.script.version === served && same(second.j.reported, await (await worker.fetch(new Request('https://csa.example.org/2026-01/reported.json'), fenv, { waitUntil() {} })).json()));
    const n0 = reads.length, odd = await ask(fenv, '/2026-01/live.json?figures=0&as_of=2030-01-01T00:00Z&devices=1', { headers: { cookie: 'figures=<b>', 'x-forwarded-for': '<b>', 'if-none-match': '*' } });
    expect('live.json: the figures take nothing from the request either, and a kept body starts no run', odd.raw === second.raw && reads.length === n0);
    const head = await ask(fenv, '/2026-01/live.json', { method: 'HEAD' });
    expect('live.json: HEAD answers without a body', head.r.status === 200 && head.raw === '' && head.r.headers.get('cache-control') === 'public, max-age=60');
    // a later run reads from the last upto minus two minutes: a late report is caught, an older one waits for a full read
    const NEW1 = { id: 'fxnew1', received: at(28, '09:00:00'), report: { ...base, device_id: D('n1'), ioc: 1, findings: MK } };
    const LATE = { id: 'fxlate', received: at(27, '07:59:00'), report: { ...base, device_id: D('n2') } };
    const OLD = { id: 'fxold', received: at(20, '12:00:00'), report: { ...base, device_id: D('n3'), model: 'mt3000' } };
    insert([NEW1, LATE, OLD]);
    const n1 = reads.length; stale(); const third = await ask();
    expect('live.json: a later run reads only the reports received since the last upto, less two minutes', reads.length === n1 + 1 && reads[n1].from === new Date(Date.parse(at(27, '08:00:00')) - 120_000).toISOString() && reads[n1].upto === at(28, '09:00:00') && reads[n1].after === '' && reads[n1].rows === 3);
    const fourth = await ask();
    expect('live.json: so the new and the late report count, the one received long before does not yet', same(third.j.figures, second.j.figures) && expectAs(fourth.j.figures, [...FX, NEW1, LATE]) && !expectAs(fourth.j.figures, [...FX, NEW1, LATE, OLD]) && devices().upto === at(28, '09:00:00'));
    store.set(DKEY, JSON.stringify({ ...devices(), rules: 'older rules' }));
    const n2 = reads.length; stale(); await ask();
    expect('live.json: when the rules change, all reports are read again', reads[n2].from === '' && expectAs((await ask()).j.figures, [...FX, NEW1, LATE, OLD]) && devices().rules !== 'older rules');
    store.set(DKEY, JSON.stringify({ ...devices(), full: '2026-11-01' }));
    const n3 = reads.length; stale(); await ask();
    const n4 = reads.length; stale(); await ask();
    expect('live.json: once a day, at the first run from 04:00 UTC, all reports are read again, then not until the next day', reads[n3].from === '' && devices().full === new Date(Date.now() - 4 * 3600_000).toISOString().slice(0, 10) && reads[n4].from !== '');
    for (const [what, broken] of [['not JSON', () => '{'], ['a state of another shape', () => JSON.stringify({ ...devices(), state: { v: 1, cmd: null, dev: 'x', one: [] } })], ['no time read up to', () => JSON.stringify({ ...devices(), upto: 'later' })]]) {
      store.set(DKEY, broken()); const n = reads.length; stale(); await ask();
      expect(`live.json: kept devices with ${what} mean a full read`, reads[n].from === '' && isFigureState(devices().state));
    }
    // more than a page: by (received, id), every report once, also with equal times
    const many = Array.from({ length: 2345 }, (_, i) => ({ id: 'fxpg' + String(i).padStart(5, '0'), received: '2026-11-28T10:00:00.' + String(i % 400).padStart(3, '0') + 'Z', report: { ...base, firmware: '4.7.5' } }));
    insert(many);
    const total = fdb.raw.prepare('SELECT count(*) AS n FROM reports').get().n;
    store.set(DKEY, JSON.stringify({ ...devices(), rules: 'older rules' }));
    const n5 = reads.length; stale(); await ask();
    const pages = reads.slice(n5);
    expect('live.json: a full read goes in pages of 1,000 by time and id, and reads every report once', pages.length === Math.floor(total / 1000) + 1 && pages.every((p, i) => p.rows === (i < pages.length - 1 ? 1000 : total % 1000)) && pages.slice(1).every((p) => p.after !== '') && pages.reduce((s, p) => s + p.rows, 0) === total);
    expect('live.json: and its figures are those of the reference over all of them', expectAs((await ask()).j.figures, [...FX, NEW1, LATE, OLD, ...many]));
    const plan = fdb.raw.prepare('EXPLAIN QUERY PLAN ' + FIGURES_SQL).all('a', 'b', 'c').map((r) => r.detail).join();
    expect('live.json: the figures read the reports through the index on the time of receipt and id', /^SEARCH reports USING INDEX reports_received \(\(received,id\)>\(\?,\?\) AND received<\?\)$/.test(plan));
    // when D1 fails: the last figures stay, the next try is in about three minutes
    const kept1 = (await ask()).j, prepOk = fdb.prepare;
    let tries = 0;
    fdb.prepare = (sql) => { if (sql === FIGURES_SQL) { tries++; throw new Error('D1_ERROR: too many requests'); } return prepOk(sql); };
    stale(); const t0 = Date.now(); const failed1 = await ask(), after1 = JSON.parse(store.get(FKEY));
    expect('live.json: when D1 fails, the figures stay as they were and the next try is in about three minutes', tries === 1 && same(failed1.j, kept1) && same(after1.body, kept1.figures) && Math.abs(after1.checked - (t0 - 900_000 + 180_000)) < 5000 && figuresRun.next >= t0 + 170_000);
    store.set(FKEY, JSON.stringify({ ...after1, checked: 0 })); await ask();
    expect('live.json: and this copy of the worker does not try again before, even when KV could not keep the failure', tries === 1 && figuresRun.next > Date.now());
    store.delete(FKEY); store.delete(DKEY); figuresRun.next = 0;
    const none1 = await ask(), none2 = await ask();
    expect('live.json: when D1 fails with nothing kept, figures is null, script and reported are as they were', tries === 2 && none1.j.figures === null && none2.j.figures === null && same(none2.j.script, kept1.script) && same(none2.j.reported, kept1.reported) && JSON.parse(store.get(FKEY)).body === null);
    fdb.prepare = prepOk;
    // when KV fails
    figuresRun.next = 0; stale(); await ask(); const good1 = (await ask()).j;
    const kvGetOk = env.REPORTS.get;
    env.REPORTS.get = async (k) => { if (k.startsWith('figures/')) throw new Error('KV GET failed: 429 Too Many Requests'); return kvGetOk(k); };
    kvMemo.clear(); const n7 = reads.length, kvBroken = await ask();
    expect('live.json: when KV fails for the figures, figures is null, script and reported are as they were, and nothing is read', good1.figures !== null && kvBroken.j.figures === null && same(kvBroken.j.script, good1.script) && same(kvBroken.j.reported, good1.reported) && reads.length === n7);
    env.REPORTS.get = async () => { throw new Error('KV GET failed: 429 Too Many Requests'); };
    kvMemo.clear(); const allBroken = await ask();
    expect('live.json: when KV fails altogether, it still answers, every part null as before', allBroken.r.status === 200 && allBroken.raw === '{"script":null,"reported":null,"figures":null}\n' && reads.length === n7);
    env.REPORTS.get = kvGetOk; kvMemo.clear();
    // a run that fails in the middle of a full read keeps the figures too
    stale(); store.set(DKEY, JSON.stringify({ ...devices(), rules: 'older rules' }));
    let calls = 0; fdb.prepare = (sql) => (sql === FIGURES_SQL && ++calls === 2 ? (() => { throw new Error('D1_ERROR: reset'); })() : prepOk(sql));
    await ask();
    expect('live.json: a full read that fails on its second page changes nothing it kept', calls === 2 && same(JSON.parse(store.get(FKEY)).body, good1.figures) && devices().rules === 'older rules');
    fdb.prepare = prepOk; figuresRun.next = 0;
    const noDb = await ask({ ...env, DB: undefined });
    expect('live.json: without the database, figures is null', noDb.j.figures === null && Object.keys(noDb.j).join() === 'script,reported,figures');
    store.delete(FKEY); store.delete(DKEY); figuresRun.next = 0;
  }
  globalThis.fetch = realFetch;
  console.log(failed ? `${failed} failed` : 'all passed');
  process.exit(failed ? 1 : 0);
}
