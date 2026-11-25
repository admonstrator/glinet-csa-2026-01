// node worker/test/run.mjs          run the tests
// node worker/test/run.mjs serve    serve the worker on 127.0.0.1:8787 with a KV in memory
import worker, { validate, reportedTable, firstTraces, TRACE_SQL, REPORT_FIELDS, UPDATE_KEYS } from '../src/index.js';
import { suggestionsSql } from '../tools/suggestions-sql.mjs';
import nodeCrypto from 'node:crypto';
import http from 'node:http';

import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
const store = new Map(), meta = new Map();
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
  http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const r = await call(req.method, req.method === 'POST' ? Buffer.concat(chunks) : undefined, req.headers, req.url);
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(await r.text());
    if (req.method === 'POST') console.log(r.status, [...store.entries()].filter(([k]) => k.startsWith('csa-2026-01/')).at(-1)?.[1] ?? '');
  }).listen(8787, '127.0.0.1');
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
    expect('cards stay grouped by page in page order', kept.items.map((i) => PAGES.findIndex((p) => p[0] === i.p)).every((x, i, a) => !i || a[i - 1] <= x) && kept.items.filter((i) => i.p === 'overview').at(-1).k === 'healed' && kept.items[0].k === 'reports');
    const plain = normalize({ tpl: 'large', custom: false, items: [{ k: 'when', p: 'overview', w: 3, h: 3 }], hidden: ['ports'] });
    expect('a saved layout nobody changed: its template as it is now, hidden cards kept', plain.tpl === 'large' && !plain.custom && JSON.stringify(plain.items) === JSON.stringify(tplItems('large')) && JSON.stringify(plain.hidden) === '["ports"]');
    const old = migrate({ order: ['Reports', 'Is it still going on', 'Ports of the remote shells', 'Malware files', 'When it started', 'What each kind of evidence means'], hidden: ['Ports of the remote shells', 'What each kind of evidence means'], sizes: { 'When it started': 'half', 'Models and firmware': 'full', 'Devices': 'odd' } });
    const ov = old.items.filter((i) => i.p === 'overview').map((i) => i.k).join(' '), atk = old.items.filter((i) => i.p === 'attack').map((i) => i.k).join(' ');
    expect('the layout of before: its order on each page, its hidden cards and widths', ov === 'hit shell back restart gc going when course healed' && atk === 'evidence ports files left' && JSON.stringify(old.hidden) === '["ports"]' && at(old, 'when').w === 6 && at(old, 'matrix').w === 12 && at(old, 'devices').w === 4 && old.custom && old.items.length === n);
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
  globalThis.fetch = realFetch;
  console.log(failed ? `${failed} failed` : 'all passed');
  process.exit(failed ? 1 : 0);
}
