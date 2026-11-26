// Collects the short, anonymous reports that gl-helper-triage.sh sends when its user
// agrees. One report is a few facts about a device (model, firmware, which indicators
// were found, when). The worker stores exactly the fields listed below and nothing
// about the sender: no IP address, no country, no headers.

import { DASHBOARD } from './dashboard.js';
import { RESULT } from './result.js';
import { KNOWN_RELEASE_HASHES } from './known.js';

const MAX_BYTES = 49152;
const SAFE = /^[A-Za-z0-9 ._:\/+@=,()-]*$/;
const TIME = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)?$/;

const str = (max) => (v) => typeof v === 'string' && v.length <= max && SAFE.test(v);
const int = (v) => Number.isInteger(v) && v >= 0 && v <= 1e9;
const time = (v) => typeof v === 'string' && TIME.test(v);
const list = (max, item) => (v) => Array.isArray(v) && v.length <= max && v.every(item);

// Every field is required; anything else in a report is refused.
const FIELDS = {
  schema: (v) => Number.isInteger(v) && v >= 1 && v <= 10,
  tool: str(16),
  platform: str(48),
  model: str(64),
  firmware: str(48),
  checked_at: time,
  uptime_s: int,
  ioc: int,
  persist: int,
  review: int,
  findings: list(40, str(120)),
  quick_check: (v) => typeof v === 'boolean',
  shell_started: time,
  shell_ports: list(10, (v) => Number.isInteger(v) && v > 0 && v < 65536),
  pipe_time: time,
};

// Since script 2.2 (schema 2): fingerprints of the implant's files and the time of the
// cloud handler's state file.
const FILE = { path: str(120), sha256: (v) => typeof v === 'string' && /^([0-9a-f]{64})?$/.test(v), size: int, mtime: time };
const isFileOf = (shape) => (v) =>
  v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === Object.keys(shape).length && Object.entries(shape).every(([k, ok]) => ok(v[k]));
const isFile = isFileOf(FILE);
const FIELDS_V2 = { ...FIELDS, state_file_time: time, files: list(12, isFile) };

// Since script 2.3 (schema 3): what the attacker left, as free text: changed lines of
// autostart files, the rules of the firewall chain the attack used, command lines of its
// processes. Printable ASCII only; the dashboard shows it as text, never as HTML.
const txt = (max) => (v) => typeof v === 'string' && v.length <= max && /^[\x20-\x7e]*$/.test(v);
const isPersist = (v) =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 2 &&
  str(120)(v.path) && list(60, txt(300))(v.lines);
const FIELDS_V3 = { ...FIELDS_V2, persistence: list(6, isPersist), fw_rules: list(10, txt(300)), commands: list(5, txt(400)) };

// Since script 2.9 (schema 4): a device id, so that repeated reports from one device can
// be told apart from reports of many devices. The script sends a hash of a hardware
// address. A plain hash of a MAC address can be reversed by trying all addresses, so the
// worker never stores what it receives: it stores an HMAC of it with the secret
// DEVICE_SALT, shortened. Without that secret the id is dropped.
const FIELDS_V4 = { ...FIELDS_V3, device_id: (v) => typeof v === 'string' && /^([0-9a-f]{16})?$/.test(v) };

// Since script 2.13 (schema 5): each file also carries its ctime, the time the kernel last
// changed the file's entry. touch and tar can set the written time back, not this one.
const FIELDS_V5 = { ...FIELDS_V4, files: list(12, isFileOf({ ...FILE, ctime: time })) };

// Since script 2.23 (schema 6): what the script listed for review, as kind and path with
// a fingerprint for files, so that a pattern across devices shows up; whether GoodCloud
// and AstroWarp are switched on; and the size of the cloud handler's state file (-1: no
// such file). An empty state file is what the attack leaves.
const onoff = (v) => v === 'on' || v === 'off' || v === 'unknown';
const isReview = isFileOf({ kind: str(24), path: str(160), sha256: FILE.sha256 });
const FIELDS_V6 = {
  ...FIELDS_V5, goodcloud: onoff, cloud_client: str(32), astrowarp: onoff,
  state_file_size: (v) => Number.isInteger(v) && v >= -1 && v <= 1e9, review_items: list(40, isReview),
};

// Since script 2.24 (schema 7): each review item also carries its two times, as the files
// of the malware do: when it was written and when the kernel last changed its entry.
const FIELDS_V7 = { ...FIELDS_V6, review_items: list(40, isFileOf({ kind: str(24), path: str(160), sha256: FILE.sha256, mtime: time, ctime: time })) };

// Since script 2.28 (schema 8): whether the device is bound to a GoodCloud account and
// whether remote SSH and the remote web interface through the cloud are on. Yes, no or
// unknown each; the account itself is never sent.
const FIELDS_V8 = { ...FIELDS_V7, cloud_bound: onoff, rtty_ssh: onoff, rtty_web: onoff };

// Since script 2.35 (schema 9): a note of the sender's own, given with --note, for people
// who report many devices: where a report comes from, before or after a clean-up, a
// repeat. Empty without one. Plain text; the dashboard shows it as text.
// Also the time the cloud handler's state file was created, its first call: the file's
// access time, sent only where the filesystem does not update it (noatime), else empty.
const FIELDS_V9 = { ...FIELDS_V8, note: txt(120), state_file_first: time };

// Since script 2.46 (schema 10): whether the firmware brings GL.iNet's own cleanup (package
// gl-sdk4-system-check, router firmware 4.9.3 on). It deletes the malware's known traces
// at the first start, so a clean report from such a device says nothing about the time
// before the update.
const FIELDS_V10 = { ...FIELDS_V9, vendor_cleanup: onoff };
// for the test that openapi.json, the schema Cloudflare checks reports against, knows every field
export const REPORT_FIELDS = Object.keys(FIELDS_V10);

async function sealDeviceId(env, id) {
  if (!env.DEVICE_SALT || !id) return '';
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.DEVICE_SALT), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(id)));
  return [...mac.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const text = (body, status = 200) =>
  new Response(body + '\n', { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });

// The body of a request as bytes, at most max of them. A content-length above that is
// refused before anything is read; otherwise the body is read as a stream and given up as
// soon as more than max bytes arrived, so a missing or false content-length cannot bring a
// large body into memory. null: too large.
async function readCapped(request, max) {
  const declared = request.headers.get('content-length');
  if (declared !== null && /^\d+$/.test(declared.trim()) && Number(declared.trim()) > max) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader(), parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      try { await reader.cancel(); } catch { /* the answer is the same */ }
      return null;
    }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.byteLength; }
  return out;
}

export function validate(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) return 'not an object';
  const fields = report.schema === 10 ? FIELDS_V10 : report.schema === 9 ? FIELDS_V9 : report.schema === 8 ? FIELDS_V8 : report.schema === 7 ? FIELDS_V7 : report.schema === 6 ? FIELDS_V6 : report.schema === 5 ? FIELDS_V5 : report.schema === 4 ? FIELDS_V4 : report.schema === 3 ? FIELDS_V3 : report.schema === 2 ? FIELDS_V2 : FIELDS;
  for (const key of Object.keys(report)) if (!(key in fields)) return `unknown field ${key.slice(0, 32)}`;
  for (const [key, ok] of Object.entries(fields)) if (!ok(report[key])) return `bad or missing field ${key}`;
  return null;
}

// ---------------------------------------------------------------- storage
// Reports live in D1 (a table, one row per report) when the binding DB exists, and in KV
// as before when it does not, so the worker can be deployed before the database is set
// up. D1 fits the job better: one write per report, the whole dashboard in a few
// queries, and no daily limit of 1,000 writes and listings.
const LATEST_KEY = 'meta/csa-2026-01-latest';
// On the free Workers plan one request may make 50 subrequests, and every KV read is one.
// From KV, reports are therefore handed out 40 at a time. A D1 query is one subrequest.
const PAGE = 40;
const DB_PAGE = 500;

// The values the public addresses need (script, firmware list, reported table) are read
// from KV through the memory of this copy of the worker: each key at most once a minute,
// not on every call. The free plan allows 100,000 KV reads a day, and every visitor of the
// advisory and of the result page used to cost one or two. KV itself keeps a value up to
// a minute at each location, so nothing gets older than it already could. When KV refuses
// a read, the last value known here is used; with none, the read fails and the caller
// decides what to do without it.
export const kvMemo = new Map();
const KV_MEMO_MS = 60_000;
async function kvGet(env, key, fresh = false) {
  const m = kvMemo.get(key);
  if (m && !fresh && Date.now() - m.at < KV_MEMO_MS) return m.value;
  try {
    const value = await env.REPORTS.get(key);
    kvMemo.set(key, { at: Date.now(), value });
    return value;
  } catch (e) {
    if (!m) throw e;
    m.at = Date.now(); // ask KV again in a minute
    return m.value;
  }
}
async function kvPut(env, key, value) {
  await env.REPORTS.put(key, value);
  kvMemo.set(key, { at: Date.now(), value });
}
const row = (r) => ({ id: r.id, received: r.received, report: JSON.parse(r.report) });
const kvLoad = async (env, names) =>
  (await Promise.all(names.map(async (name) => [name, await env.REPORTS.get(name)]))).filter((x) => x[1]).map(([id, v]) => ({ id, ...JSON.parse(v) }));

// What the team says about a finding that the scripts listed for review, with a note:
// "probably safe" (verdict safe: the dashboard then hides it unless asked), "probably not
// safe" (unsafe) or "known malware" (malware). Everyone who may open the dashboard may set
// and remove a label, and each label records who set it (the address Cloudflare Access
// signed in). One label per kind and path; it remembers the fingerprints it was given for,
// so a new file at a path that was called harmless shows up again, unless the label holds
// for every file at its path (every). Kept in D1 (the table is created on first use, the
// column every added to an older one) or, without D1, in one KV entry.
const LABELS_KEY = 'meta/csa-2026-01-labels';
export const LABELS_TABLE = 'CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, verdict TEXT NOT NULL, note TEXT NOT NULL, hashes TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL, every INTEGER NOT NULL DEFAULT 0)';
let labelsTable = false;
const labels = {
  async ready(env) {
    if (labelsTable) return;
    await env.DB.prepare(LABELS_TABLE).run();
    // the column every for a table from before it: added once, and any other error of the
    // ALTER counts, so that the next request tries again (review of 2.61)
    const has = async () => (await env.DB.prepare('PRAGMA table_info(labels)').all()).results.some((c) => c.name === 'every');
    if (!(await has())) {
      try {
        await env.DB.prepare('ALTER TABLE labels ADD COLUMN every INTEGER NOT NULL DEFAULT 0').run();
      } catch (e) {
        if (!(await has())) throw e; // else another isolate added it at the same moment
      }
    }
    labelsTable = true;
  },
  async all(env) {
    if (env.DB) {
      await labels.ready(env);
      const { results } = await env.DB.prepare('SELECT key, verdict, note, hashes, every, by, at FROM labels').all();
      return Object.fromEntries(results.map((r) => [r.key, { verdict: r.verdict, note: r.note, hashes: JSON.parse(r.hashes), every: Number(r.every) === 1, by: r.by, at: r.at }]));
    }
    return JSON.parse((await env.REPORTS.get(LABELS_KEY)) || '{}');
  },
  async set(env, key, label) {
    if (env.DB) {
      await labels.ready(env);
      if (!label) await env.DB.prepare('DELETE FROM labels WHERE key = ?1').bind(key).run();
      else await env.DB.prepare('INSERT OR REPLACE INTO labels (key, verdict, note, hashes, every, by, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)').bind(key, label.verdict, label.note, JSON.stringify(label.hashes), label.every ? 1 : 0, label.by, label.at).run();
    } else {
      const all = JSON.parse((await env.REPORTS.get(LABELS_KEY)) || '{}');
      if (label) all[key] = label; else delete all[key];
      await env.REPORTS.put(LABELS_KEY, JSON.stringify(all));
    }
    // after the write: a check that read the marks before it keeps nothing (checkMarks)
    markCache.gen++;
    markCache.map = null;
  },
};

// Suggestions: findings that an analysis of the reports takes for probably safe, each with
// its reason and the fingerprints it covers. A suggestion hides nothing. It waits until
// someone on the team confirms it, which sets a label in that person's name and removes
// the suggestion, or declines it, which keeps it with who said no, so that loading the same
// suggestions again does not bring it back. They come in as SQL (tools/suggestions-sql.mjs),
// so only with D1; the dashboard cannot add one.
export const SUGGESTIONS_TABLE = 'CREATE TABLE IF NOT EXISTS suggestions (key TEXT PRIMARY KEY, note TEXT NOT NULL, hashes TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL, declined_by TEXT NOT NULL DEFAULT \'\', declined_at TEXT NOT NULL DEFAULT \'\')';
let suggestionsTable = false;
const suggestions = {
  async ready(env) {
    if (suggestionsTable) return;
    await env.DB.prepare(SUGGESTIONS_TABLE).run();
    suggestionsTable = true;
  },
  async all(env) {
    if (!env.DB) return {};
    await suggestions.ready(env);
    const { results } = await env.DB.prepare('SELECT key, note, hashes, by, at, declined_by, declined_at FROM suggestions').all();
    return Object.fromEntries(results.map((r) => [r.key, { note: r.note, hashes: JSON.parse(r.hashes), by: r.by, at: r.at, declined_by: r.declined_by, declined_at: r.declined_at }]));
  },
  // answered with a yes: the label carries it from now on
  async drop(env, key) {
    if (!env.DB) return;
    await suggestions.ready(env);
    await env.DB.prepare('DELETE FROM suggestions WHERE key = ?1').bind(key).run();
  },
  async decline(env, key, user) {
    await suggestions.ready(env);
    await env.DB.prepare("UPDATE suggestions SET declined_by = ?2, declined_at = ?3 WHERE key = ?1 AND declined_by = ''").bind(key, user, new Date().toISOString()).run();
  },
};

// A label as the dashboard sends it. The key is a kind and a path as the reports carry
// them; the note is plain text and shown as text. "decline" answers a suggestion with no.
export function validLabel(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'not an object';
  if (!(typeof body.key === 'string' && body.key.length >= 3 && body.key.length <= 200 && SAFE.test(body.key))) return 'bad key';
  if (!['safe', 'unsafe', 'malware', '', 'decline'].includes(body.verdict)) return 'bad verdict';
  if (!(typeof body.note === 'string' && body.note.length <= 200 && /^[\x20-\x7e]*$/.test(body.note))) return 'bad note';
  if (!(Array.isArray(body.hashes) && body.hashes.length <= 60 && body.hashes.every((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)))) return 'bad hashes';
  if (body.every !== undefined && typeof body.every !== 'boolean') return 'bad every';
  return null;
}

// A file the dashboard puts on the community list as malware, at any path, or takes off it.
export function validBadHash(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'not an object';
  if (!(typeof body.sha256 === 'string' && /^[0-9a-f]{64}$/.test(body.sha256))) return 'bad sha256';
  if (!['malware', ''].includes(body.verdict)) return 'bad verdict';
  if (!(typeof body.note === 'string' && body.note.length <= 200 && /^[\x20-\x7e]*$/.test(body.note))) return 'bad note';
  return null;
}

const reports = {
  async add(env, received, report) {
    if (env.DB) {
      await env.DB.prepare('INSERT INTO reports (id, received, report) VALUES (?1, ?2, ?3)').bind(crypto.randomUUID(), received, JSON.stringify(report)).run();
      return;
    }
    // The time of receipt also goes into the key's metadata, so the live view can find
    // new reports from a key listing, and into one marker key that dashboards poll.
    await env.REPORTS.put(`csa-2026-01/${received.slice(0, 10)}/${crypto.randomUUID()}`, JSON.stringify({ received, report }), { metadata: { received } });
    try {
      await env.REPORTS.put(LATEST_KEY, received);
    } catch {
      // the report is stored; the live view just notices it later
    }
  },
  // all reports, oldest first, a page at a time
  async page(env, cursor) {
    if (env.DB) {
      const [received = '', id = ''] = (cursor || '').split(' ');
      const { results } = await env.DB.prepare('SELECT id, received, report FROM reports WHERE (received, id) > (?1, ?2) ORDER BY received, id LIMIT ?3').bind(received, id, DB_PAGE).all();
      const last = results[results.length - 1];
      return { items: results.map(row), cursor: results.length === DB_PAGE ? `${last.received} ${last.id}` : '' };
    }
    const page = await env.REPORTS.list({ prefix: 'csa-2026-01/', limit: PAGE, cursor: cursor || undefined });
    return { items: await kvLoad(env, page.keys.map((k) => k.name)), cursor: page.list_complete ? '' : page.cursor };
  },
  // reports received after "since", oldest first, one page
  async since(env, since) {
    if (env.DB) {
      const { results } = await env.DB.prepare('SELECT id, received, report FROM reports WHERE received > ?1 ORDER BY received, id LIMIT ?2').bind(since, DB_PAGE).all();
      return results.map(row);
    }
    // KV keys are grouped by day, so only the days from then until now are listed (three at most)
    const names = [];
    for (let day = Date.parse(since.slice(0, 10)), n = 0; day <= Date.now() && n < 3; day += 86_400_000, n++) {
      let cursor;
      do {
        const page = await env.REPORTS.list({ prefix: `csa-2026-01/${new Date(day).toISOString().slice(0, 10)}/`, cursor });
        for (const k of page.keys) if (k.metadata && k.metadata.received > since) names.push({ name: k.name, received: k.metadata.received });
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    }
    names.sort((a, b) => (a.received < b.received ? -1 : 1));
    return kvLoad(env, names.slice(0, PAGE).map((n) => n.name));
  },
  async latest(env) {
    if (env.DB) return (await env.DB.prepare('SELECT max(received) AS latest FROM reports').first('latest')) || '';
    return (await env.REPORTS.get(LATEST_KEY)) || '';
  },
};

async function submit(request, env) {
  const body = await readCapped(request, MAX_BYTES);
  if (!body) return text('too large', 413);
  const raw = new TextDecoder().decode(body);
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    return text('not JSON', 400);
  }
  const problem = validate(report);
  if (problem) return text(problem, 400);
  if ('device_id' in report) report.device_id = await sealDeviceId(env, report.device_id);
  await reports.add(env, new Date().toISOString(), report);
  return text('stored, thank you');
}

const maintainer = (request, env) => Boolean(env.EXPORT_TOKEN) && request.headers.get('authorization') === `Bearer ${env.EXPORT_TOKEN}`;

// For the maintainers: all reports as JSON lines, a page per call. Only with the secret
// EXPORT_TOKEN; without that secret the address does not exist.
async function exportReports(request, env) {
  if (!maintainer(request, env)) return text('not found', 404);
  const params = new URL(request.url).searchParams;
  let page = await reports.page(env, params.get('cursor'));
  const items = page.items;
  // ?all=1: every report in one answer instead of a page at a time. From D1 that is one
  // query per 500 reports; 40 pages stay within what one request may do.
  if (params.get('all') === '1' && env.DB) for (let n = 1; page.cursor && n < 40; n++) { page = await reports.page(env, page.cursor); items.push(...page.items); }
  return new Response(items.map((x) => JSON.stringify({ received: x.received, report: x.report })).join('\n') + '\n', {
    headers: { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-next-cursor': page.cursor },
  });
}

// One-off move from KV to D1, 40 reports per call, for the maintainers. It copies and
// leaves KV as it is; a report that is already in the table is skipped, so the call can
// be repeated. The answer says how to continue.
async function migrate(request, env) {
  if (!maintainer(request, env)) return text('not found', 404);
  if (!env.DB) return text('no D1 database bound as DB', 400);
  const page = await env.REPORTS.list({ prefix: 'csa-2026-01/', limit: PAGE, cursor: new URL(request.url).searchParams.get('cursor') || undefined });
  const items = await kvLoad(env, page.keys.map((k) => k.name));
  const insert = env.DB.prepare('INSERT OR IGNORE INTO reports (id, received, report) VALUES (?1, ?2, ?3)');
  if (items.length) await env.DB.batch(items.map((x) => insert.bind(x.id, x.received, JSON.stringify(x.report))));
  // older reports came in: the reported table reads them all again
  if (items.length) await env.REPORTS.put(REPORTED_DEVICES_KEY, 'null');
  const total = await env.DB.prepare('SELECT count(*) AS n FROM reports').first('n');
  return new Response(JSON.stringify({ copied: items.length, in_database: total, cursor: page.list_complete ? '' : page.cursor }) + '\n', {
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

// The dashboard is for the team only. Cloudflare Access sits in front of it and signs
// every request it lets through; the worker checks that signature itself, so the page
// stays closed when Access is missing or covers the wrong path. Without ACCESS_TEAM_DOMAIN
// and ACCESS_AUD the dashboard does not exist.
let accessKeys = { at: 0, keys: [] };
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

export async function accessUser(request, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const [head, body, sig] = (request.headers.get('cf-access-jwt-assertion') || '').split('.');
  if (!sig) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64(head)));
    const claims = JSON.parse(new TextDecoder().decode(b64(body)));
    const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
    if (header.alg !== 'RS256' || claims.iss !== issuer || !(claims.exp > Date.now() / 1000)) return null;
    if (![].concat(claims.aud).includes(env.ACCESS_AUD)) return null;
    if (Date.now() - accessKeys.at > 600_000 || !accessKeys.keys.some((k) => k.kid === header.kid)) {
      const res = await fetch(`${issuer}/cdn-cgi/access/certs`);
      accessKeys = { at: Date.now(), keys: (await res.json()).keys || [] };
    }
    const jwk = accessKeys.keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64(sig), new TextEncoder().encode(`${head}.${body}`));
    return ok ? claims.email || 'signed in' : null;
  } catch {
    return null;
  }
}

async function dashboard(request, env, data) {
  const user = await accessUser(request, env);
  if (!user) return text('not found', 404);
  if (data === 'labels' || data === 'bad-hashes') {
    const out = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
    const both = async () => out({ labels: await labels.all(env), suggestions: await suggestions.all(env), bad: env.DB ? await badHashes.all(env) : null, you: user });
    if (request.method === 'GET') return both();
    // a change: only from the dashboard itself. A form on another site cannot send JSON,
    // and the browser names the page a request comes from.
    if (!(request.headers.get('content-type') || '').startsWith('application/json') || request.headers.get('origin') !== new URL(request.url).origin) return text('not from the dashboard', 403);
    let body;
    try { body = JSON.parse((await request.text()).slice(0, 8192)); } catch { return text('not JSON', 400); }
    if (data === 'bad-hashes') {
      const wrong = validBadHash(body);
      if (wrong) return text(wrong, 400);
      if (!env.DB) return text('the list needs the database', 400);
      await badHashes.set(env, body.sha256, body.verdict ? { note: body.note || 'marked on the dashboard', by: user, at: new Date().toISOString() } : null);
      return both();
    }
    const bad = validLabel(body);
    if (bad) return text(bad, 400);
    if (body.verdict === 'decline') {
      if (!env.DB) return text('suggestions need the database', 400);
      await suggestions.decline(env, body.key, user);
      return both();
    }
    await labels.set(env, body.key, body.verdict ? { verdict: body.verdict, note: body.note, hashes: body.hashes, every: body.every === true, by: user, at: new Date().toISOString() } : null);
    if (body.verdict) await suggestions.drop(env, body.key);
    return both();
  }
  if (!data) {
    return new Response(DASHBOARD, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
      },
    });
  }
  const json = (body) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  const params = new URL(request.url).searchParams;
  if (data === 'latest') return json({ latest: await reports.latest(env) });
  const since = params.get('since');
  if (since) {
    // live view: only reports received after "since"
    if (!/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(since)) return text('bad since', 400);
    return json({ items: await reports.since(env, since), cursor: '' });
  }
  return json(await reports.page(env, params.get('cursor')));
}

// The script itself, served from here instead of raw.githubusercontent.com, which keeps
// a file for five minutes after a push. The worker only ever takes the script from the
// main branch of the official repository: it asks GitHub which commit main points to and
// fetches the file by that commit, an address GitHub does not cache. The commit comes from
// the address git itself uses (info/refs); GitHub's API limits anonymous calls per IP
// address, and workers share theirs with many others. Anyone may call
// /refresh; it can only bring the copy here in line with main, at most twice a minute.
const REPO = 'admonstrator/glinet-csa-2026-01';
const SCRIPT = 'gl-helper-triage.sh';
const SCRIPT_KEY = 'script/csa-2026-01-fix';
const RAW_MAIN = `https://raw.githubusercontent.com/${REPO}/main/${SCRIPT}`;

// Which commit main points to. First the way git asks; where that fails, GitHub's API.
// Both addresses change with every call, so that no cache in between can answer.
async function newestCommit(errors) {
  try {
    const refs = await fetch(`https://github.com/${REPO}.git/info/refs?service=git-upload-pack&t=${Date.now()}`, { headers: { 'user-agent': 'git/2.43.0', 'cache-control': 'no-cache' } });
    const commit = ((await refs.text()).match(/([0-9a-f]{40}) refs\/heads\/main\n/) || [])[1];
    if (refs.ok && commit) return commit;
    errors.push(`refs: ${refs.status}${commit ? '' : ', no main in the answer'}`);
  } catch (e) { errors.push('refs: ' + String((e && e.message) || e)); }
  try {
    const api = await fetch(`https://api.github.com/repos/${REPO}/commits/main?t=${Date.now()}`, { headers: { 'user-agent': 'csa-2026-01-worker', accept: 'application/vnd.github.sha' } });
    const commit = (await api.text()).trim();
    if (api.ok && /^[0-9a-f]{40}$/.test(commit)) return commit;
    errors.push(`api: ${api.status}`);
  } catch (e) { errors.push('api: ' + String((e && e.message) || e)); }
  return '';
}
// When a refresh was last tried without success. Kept apart from the script: writing the
// copy back to note the time could put an older script over a newer one stored meanwhile.
const TRIED_KEY = 'script/csa-2026-01-fix.tried';
async function refreshScript(env, force) {
  const have = JSON.parse((await kvGet(env, SCRIPT_KEY, true)) || 'null');
  const last = Math.max(have ? have.checked : 0, Number((await kvGet(env, TRIED_KEY, true)) || 0));
  if (have && !force && Date.now() - last < 600_000) return have;
  if (have && Date.now() - last < 30_000) return have;
  const errors = [];
  try {
    const commit = await newestCommit(errors);
    if (!commit) throw new Error('no commit');
    let body = have && have.commit === commit ? have.body : null;
    if (body === null) {
      const raw = await fetch(`https://raw.githubusercontent.com/${REPO}/${commit}/${SCRIPT}`);
      body = await raw.text();
      if (!raw.ok) throw new Error(`file: ${raw.status}`);
      if (!body.startsWith('#!/bin/sh') || body.length < 1000 || body.length > 500_000) throw new Error(`file: not the script (${body.length} characters)`);
    }
    const next = { commit, body, checked: Date.now() };
    await kvPut(env, SCRIPT_KEY, JSON.stringify(next));
    return next;
  } catch (e) {
    // GitHub not reachable or rate limited: keep what there is, try again in half a minute,
    // and say why to whoever asked for the refresh
    errors.push(String((e && e.message) || e));
    try { await kvPut(env, TRIED_KEY, String(Date.now() - 570_000)); } catch { /* the next call tries again */ }
    return have ? { ...have, error: errors.join('; ').replace(/[^\x20-\x7e]/g, '?').slice(0, 300) } : null;
  }
}

async function script(request, env, ctx, pathname) {
  if (pathname.endsWith('/refresh')) {
    if (request.method !== 'POST') return text('method not allowed', 405);
    const now = await refreshScript(env, true);
    if (!now) return text('could not reach GitHub', 502);
    // the commit served now; when the refresh failed, the header says why
    return new Response(now.commit + '\n', { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...(now.error ? { 'x-refresh-error': now.error } : {}) } });
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  let have;
  // KV refuses and nothing is known here: GitHub serves the script, a few minutes behind at most
  try { have = JSON.parse((await kvGet(env, SCRIPT_KEY)) || 'null'); } catch { return Response.redirect(RAW_MAIN, 302); }
  if (!have) have = await refreshScript(env, true);
  else if (Date.now() - have.checked > 600_000) ctx.waitUntil(refreshScript(env, false));
  // nothing stored and GitHub not reachable from here: send the client to GitHub itself
  if (!have) return Response.redirect(RAW_MAIN, 302);
  return new Response(request.method === 'HEAD' ? null : have.body, {
    // any page may read the script: the guide on the website shows its current version
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-script-commit': have.commit, 'access-control-allow-origin': '*' },
  });
}

// ---------------------------------------------------------------- the script's signature
// "--update" of the script takes a new version only when its signature fits a key that is
// built into the script. The signature is made where the script is published (a workflow
// in the repository, with the key kept there as a secret) and handed in here. Anyone may
// hand one in: it is taken only when it fits the script served now and one of the public
// keys, and such a signature cannot be made without the key. It is kept with the
// fingerprint of the script it is for and handed out only while that script is served.
// The format is that of signify and usign: a comment line, then base64 of "Ed", eight
// bytes that name the key, and the signature (in a public key file: the key).
const SIG_KEY = 'script/csa-2026-01-fix.sig';
// the base64 lines of the public keys, the same as UPDATE_KEYS in the script
export const UPDATE_KEYS = ['RWT3i36dVR3XndIzvtu600f1No34ytWkFYphv+5p49dLKtEUUy3IfIDx', 'RWTjqtEa0VPVvTR3x0I/d2cCw3rN4ly+mVAnwgaEzL3j36CPwUTGhqn1'];
const unbase64 = (s) => { try { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); } catch { return null; } };
const sha256hex = async (t) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)))].map((b) => b.toString(16).padStart(2, '0')).join('');
async function signatureFits(env, sigText, body) {
  const line = String(sigText).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('untrusted comment:'))[0] || '';
  const sig = unbase64(line);
  if (!sig || sig.length !== 74 || sig[0] !== 0x45 || sig[1] !== 0x64) return false;
  const keys = (env.UPDATE_PUBLIC_KEYS ? String(env.UPDATE_PUBLIC_KEYS).split(/\s+/) : UPDATE_KEYS).filter(Boolean);
  for (const k of keys) {
    const pub = unbase64(k);
    if (!pub || pub.length !== 42 || pub[0] !== 0x45 || pub[1] !== 0x64) continue;
    if (!pub.slice(2, 10).every((x, i) => x === sig[2 + i])) continue; // made with another key
    try {
      const key = await crypto.subtle.importKey('raw', pub.slice(10), { name: 'Ed25519' }, false, ['verify']);
      if (await crypto.subtle.verify({ name: 'Ed25519' }, key, sig.slice(10), new TextEncoder().encode(body))) return true;
    } catch { /* not a key this runtime takes */ }
  }
  return false;
}
async function signature(request, env) {
  let have = JSON.parse((await kvGet(env, SCRIPT_KEY, true)) || 'null');
  if (request.method === 'POST') {
    const sigText = (await request.text()).slice(0, 1024);
    // the signature may be for a version this worker has not fetched yet
    if (!have || !(await signatureFits(env, sigText, have.body))) have = await refreshScript(env, true);
    if (!have) return text('could not reach GitHub', 502);
    if (!(await signatureFits(env, sigText, have.body))) return text('this signature does not fit the script served now', 400);
    await kvPut(env, SIG_KEY, JSON.stringify({ sha: await sha256hex(have.body), sig: sigText }));
    return text(have.commit);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  const kept = JSON.parse((await kvGet(env, SIG_KEY, true)) || 'null');
  if (!have || !kept || kept.sha !== (await sha256hex(have.body))) return text('no signature for the script served now', 404);
  return new Response(request.method === 'HEAD' ? null : kept.sig, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': '*' } });
}

// The page that explains a result of the script in plain words, in English, German and
// Chinese: csa.gl-i.net/#AA006011D (scripts 2.39 and 2.40 printed a longer form,
// csa.gl-i.net/2026-01/#v=2.39&p=r&..., which still works). The result is in the part
// of the address after "#", which a browser does not send. So this answer is the same for
// everyone, and the worker learns nothing about a device from it. Open to all, no login.
// The one thing put in is the version of the script served now, so that the page can say
// when a result comes from an older one.
// The newest firmware per model, from the firmware archive at firmware.gl-i.net (its
// api/all.json, built every few hours). Kept in KV and fetched again at most once an
// hour; when the archive cannot be reached, the copy here keeps being used. Only the
// release and the beta of each model are taken, and only values of the expected shape:
// the list is put into a page.
const FIRMWARE_URL = 'https://firmware.gl-i.net/api/all.json';
const FIRMWARE_KEY = 'firmware/list';
async function refreshFirmware(env, have) {
  try {
    const res = await fetch(FIRMWARE_URL, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error('no list');
    const all = await res.json(), models = {}, pair = (x) => (x && /^\d{1,2}(\.\d{1,3}){1,2}$/.test(String(x.version)) && /^\d{4}-\d\d-\d\d/.test(String(x.release_time)) ? [String(x.version), String(x.release_time).slice(0, 10)] : null);
    for (const [name, ch] of Object.entries(all)) {
      if (!/^[a-z0-9-]{2,16}$/.test(name) || !ch || typeof ch !== 'object') continue;
      const r = pair(ch.release), b = pair(ch.beta);
      if (r) models[name] = b ? { r, b } : { r };
    }
    if (Object.keys(models).length < 5) throw new Error('too few models');
    const stamp = new Date(res.headers.get('last-modified') || Date.now()), asof = isNaN(stamp) ? '' : stamp.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    const next = { checked: Date.now(), asof, models };
    await kvPut(env, FIRMWARE_KEY, JSON.stringify(next));
    return next;
  } catch {
    if (have) await kvPut(env, FIRMWARE_KEY, JSON.stringify({ ...have, checked: Date.now() - 3000_000 }));
    return have;
  }
}
// When KV refuses and nothing is known here, this fails: no list, rather than the archive
// asked and the list written on every call.
async function firmwareList(env, ctx) {
  const raw = await kvGet(env, FIRMWARE_KEY);
  let have = null;
  try { have = JSON.parse(raw || 'null'); } catch { have = null; }
  if (!have) return refreshFirmware(env, null);
  if (Date.now() - have.checked > 3600_000) ctx.waitUntil(refreshFirmware(env, have));
  return have;
}

// The version of a stored script and its release time ("2026-11-24T14:41:00Z", or ''), from
// its VERSION= and RELEASED= lines; null when there is none.
function servedVersion(have) {
  const v = have && /^VERSION=(\d{1,2}\.\d{1,3})$/m.exec(have.body);
  if (!v) return null;
  const d = /^RELEASED='(\d{4}-\d\d-\d\d) (\d\d:\d\d) UTC'$/m.exec(have.body);
  return { version: v[1], released: d ? `${d[1]}T${d[2]}:00Z` : '' };
}

async function resultPage(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  let current = '';
  try {
    current = (servedVersion(JSON.parse((await kvGet(env, SCRIPT_KEY)) || 'null')) || {}).version || '';
  } catch { /* not known: the page then says nothing about versions */ }
  let fw = null;
  try { fw = await firmwareList(env, ctx); } catch { fw = null; }
  // as text inside a script: "<" must not be able to end it
  const list = fw ? JSON.stringify({ asof: fw.asof, models: fw.models }).replace(/</g, '\\u003c') : 'null';
  return new Response(request.method === 'HEAD' ? null : RESULT.replace('__CURRENT_VERSION__', current || '__CURRENT_VERSION__').replace('/*FIRMWARE*/null', () => list), {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

// ---------------------------------------------------------------- the reported table
// For the advisory on gl-i.net: on which models and firmware versions the attack of
// 20 November left traces, by the reports. Open to all, so it says no more than the table
// on that page does: model and firmware version, nothing per device and nothing per report.
// Anyone can send a report, and nobody reads this list before it is shown. So a model and
// version get in only when
//   - at least five different devices reported traces on them. Only reports with a device
//     id count: without one, two reports of one device cannot be told apart;
//   - the firmware archive knows the model, and the version has the usual shape;
//   - the firmware is older than the attack. A trace on a build from 20 November on was
//     either brought along by an upgrade or is something new, and both need a person.
// A device counts for the firmware of its first report with traces: who checks, upgrades
// and checks again must not move the trace to the new firmware.
// "Traces" as the dashboard counts them: the older backdoor apart, two known false alarms
// of early scripts out, and the cloud handler's state file as a trace also where the
// script that sent the report did not know it yet.
// Worked out at most every 15 minutes and kept in KV in between.
const REPORTED_KEY = 'reported/csa-2026-01';
// Which device had its first report with traces on which firmware, and up to which time of
// receipt the reports have been read, kept in KV apart from the table. Each run then reads
// only the reports received since, through the index on "received", not all of them. Two
// minutes of overlap catch a report stored a moment after a later one. When the rules
// below change, or the copy is missing, all reports are read once more.
const REPORTED_DEVICES_KEY = 'reported/csa-2026-01-devices';
const REPORTED_OVERLAP = 120_000;
const REPORTED_MIN = 5;
const REPORTED_EVERY = 900_000;
const ATTACK_DAY = '2026-11-20';
const NOT_TRACE = /^(applet-hijack \/usr\/sbin\/tailscaled?|(backdoor-host|backdoor-init|persist-ref) \/\S*gl-helper-triage\.sh)$/;
const verKey = (v) => v.replace(/\d+/g, (n) => n.padStart(5, '0'));

function attackTrace(r) {
  const f = Array.isArray(r.findings) ? r.findings.filter((x) => typeof x === 'string') : [];
  const not = f.filter((x) => NOT_TRACE.test(x) || x.startsWith('backdoor-')).length;
  if ((Number(r.ioc) || 0) - not > 0) return true;
  const at = Date.parse(String(r.state_file_time || '').replace(' UTC', 'Z').replace(' ', 'T'));
  return r.platform === 'openwrt' && r.astrowarp !== 'on' && (r.state_file_size == null || r.state_file_size === 0) && at >= Date.parse(ATTACK_DAY);
}

// rows: one per report, oldest first. Adds each device's first report with traces to "first".
export function firstTraces(rows, first = new Map()) {
  for (const r of rows) {
    if (typeof r.dev !== 'string' || !r.dev || first.has(r.dev) || !attackTrace(r)) continue;
    first.set(r.dev, { platform: r.platform, model: r.model, firmware: r.firmware });
  }
  return first;
}

// first: as firstTraces gives it. fw: the models of the firmware list.
export function reportedTable(first, fw, min = REPORTED_MIN) {
  const cells = new Map();
  for (const [dev, r] of first) {
    const kind = r.platform === 'openwrt' ? 'Router' : String(r.platform).startsWith('glkvm') ? 'KVM' : '';
    const model = String(r.model || '').toLowerCase().replace(/^gl\.?inet\s+/, '').replace(/^gl-/, '').replace(/\s*\(.*\)$/, '');
    const parts = String(r.firmware || '').trim().split(/\s+/);
    const version = (/^v?(\d{1,2}\.\d{1,3}(?:\.\d{1,3})?(?:-op\d{2})?)$/i.exec(parts[0]) || [])[1];
    if (!kind || !version || !Object.hasOwn(fw, model)) continue;
    // the day the firmware was built, as newer scripts send it; else the day the archive
    // gives for that version
    const built = (/^\d{4}-\d\d-\d\d$/.exec(parts[parts.length - 1]) || [])[0] || ([fw[model].r, fw[model].b].find((x) => x && x[0] === version) || [])[1] || '';
    if (built >= ATTACK_DAY) continue;
    const key = model + ' ' + version, c = cells.get(key) || { model, kind, version, devs: new Set() };
    c.devs.add(dev); cells.set(key, c);
  }
  const models = new Map();
  for (const c of cells.values()) {
    if (c.devs.size < min) continue;
    const m = models.get(c.model) || { model: c.model, sku: 'GL-' + c.model.toUpperCase(), kind: c.kind, firmware: [] };
    m.firmware.push(c.version); models.set(c.model, m);
  }
  return [...models.values()].sort((a, b) => (a.model < b.model ? -1 : 1)).map((m) => ({ ...m, firmware: m.firmware.sort((a, b) => (verKey(a) < verKey(b) ? -1 : 1)) }));
}

// only what the table needs, and only reports that can count, received in (?1, ?2]
const xj = (f) => `json_extract(report, '$.${f}')`;
export const TRACE_SQL =
  `SELECT ${xj('device_id')} AS dev, ${xj('model')} AS model, ${xj('firmware')} AS firmware, ${xj('platform')} AS platform, ${xj('ioc')} AS ioc, ${xj('findings')} AS findings, ` +
  `${xj('astrowarp')} AS astrowarp, ${xj('state_file_size')} AS state_file_size, ${xj('state_file_time')} AS state_file_time FROM reports ` +
  `WHERE received > ?1 AND received <= ?2 AND ${xj('device_id')} != '' AND (${xj('ioc')} > 0 OR ${xj('state_file_time')} != '') ORDER BY received, id`;

async function refreshReported(env, ctx, have) {
  try {
    const fw = await firmwareList(env, ctx);
    if (!fw || !fw.models) throw new Error('no firmware list');
    const rules = await sha256hex([attackTrace, firstTraces, NOT_TRACE, ATTACK_DAY, TRACE_SQL].join('\n'));
    // when KV refuses, this throws: better to wait than to read all reports on every call
    const keptRaw = await env.REPORTS.get(REPORTED_DEVICES_KEY);
    let kept = null;
    try { kept = JSON.parse(keptRaw || 'null'); } catch { kept = null; }
    const again = !kept || kept.rules !== rules || !(Date.parse(kept.upto) > 0) || !Array.isArray(kept.devices);
    const first = new Map(again ? [] : kept.devices.map(([dev, platform, model, firmware]) => [dev, { platform, model, firmware }]));
    // the newest report now, read from the index: one row
    const upto = (await env.DB.prepare('SELECT max(received) AS latest FROM reports').first('latest')) || '';
    const from = again ? '' : new Date(Date.parse(kept.upto) - REPORTED_OVERLAP).toISOString();
    const { results } = await env.DB.prepare(TRACE_SQL).bind(from, upto).all();
    for (const r of results) { try { r.findings = JSON.parse(r.findings || '[]'); } catch { r.findings = []; } }
    firstTraces(results, first);
    if (again || upto !== kept.upto) await env.REPORTS.put(REPORTED_DEVICES_KEY, JSON.stringify({ rules, upto, devices: [...first].map(([dev, d]) => [dev, d.platform, d.model, d.firmware]) }));
    const next = { checked: Date.now(), body: { advisory: 'CSA-2026-01', as_of: new Date().toISOString().slice(0, 16) + 'Z', min_devices: REPORTED_MIN, models: reportedTable(first, fw.models) } };
    await kvPut(env, REPORTED_KEY, JSON.stringify(next));
    return next;
  } catch {
    // keep what there is, and try again in a few minutes rather than on every call
    if (have) await kvPut(env, REPORTED_KEY, JSON.stringify({ ...have, checked: Date.now() - REPORTED_EVERY + 180_000 }));
    return have || null;
  }
}

// The table as kept, worked out again behind the answer once it is older than a quarter of
// an hour. null without the database, or when KV refuses and nothing is known here: then
// the advisory shows its own table.
async function reportedNow(env, ctx) {
  if (!env.DB) return null;
  let raw;
  try { raw = await kvGet(env, REPORTED_KEY); } catch { return null; }
  let have = null;
  try { have = JSON.parse(raw || 'null'); } catch { have = null; }
  if (!have) have = await refreshReported(env, ctx, null);
  else if (Date.now() - have.checked > REPORTED_EVERY) ctx.waitUntil(refreshReported(env, ctx, have));
  return have ? have.body : null;
}

const openJson = (request, body, maxAge) =>
  new Response(request.method === 'HEAD' ? null : JSON.stringify(body) + '\n', {
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': `public, max-age=${maxAge}`, 'access-control-allow-origin': '*', 'x-content-type-options': 'nosniff' },
  });

async function reported(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  const body = await reportedNow(env, ctx);
  return body ? openJson(request, body, 300) : text('not available', 503);
}

// For the advisory and the fix guide on gl-i.net: the version of the script served now
// and its release time, with the reported table, in one small answer. Before, a reader's
// browser fetched the whole script for its version and the table in a second call. Read
// from memory and KV like the rest; a part that is not known is null.
async function live(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  let script = null;
  try { script = servedVersion(JSON.parse((await kvGet(env, SCRIPT_KEY)) || 'null')); } catch { script = null; }
  return openJson(request, { script, reported: await reportedNow(env, ctx) }, 60);
}

// ---------------------------------------------------------------- the fingerprint check
// From 2.60 the script can ask, after its user agreed, whether the files it listed for
// review are known: known malware, probably safe, or not known. It sends the
// SHA-256 of "<kind> <path>" and the SHA-256 of the file per line; docs/lookup.md is the
// contract for request and answer. The answer can only make the script's verdict worse.
// Every request is taken for an attack: the size is capped while reading, the bytes are
// checked before anything is decoded, every line must fit a fixed pattern, and every
// refusal is a fixed text that holds nothing of the request. Nothing of a request is
// stored or logged; the one write is the counter of an entry in bad_hashes.
// Off unless the worker has LOOKUP = "on" among its vars: then every method gets 404.
const LOOKUP_MAX_BYTES = 8192;
const LOOKUP_MAX_ITEMS = 40;
const LOOKUP_HEAD = [/^csa-2026-01-lookup 1$/, /^version 2\.[0-9]{1,3}$/, /^nonce [0-9a-f]{32}$/];
const LOOKUP_ITEM = /^[0-9a-f]{64} [0-9a-f]{64}$/;
const plain = (body, status = 200) =>
  new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });

// A request as bytes: its nonce and its lines as [key hash, file hash], or null when a
// single byte or line does not fit. Only 0x0a and 0x20 to 0x7e may occur; nothing is
// trimmed, normalized or replaced.
export function lookupRequest(bytes) {
  for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0x0a && (bytes[i] < 0x20 || bytes[i] > 0x7e)) return null;
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) return null;
  // the bytes are ASCII now, so this cannot fail or change anything
  const lines = new TextDecoder().decode(bytes).slice(0, -1).split('\n');
  if (lines.length < LOOKUP_HEAD.length + 1 || lines.length > LOOKUP_HEAD.length + LOOKUP_MAX_ITEMS) return null;
  for (let i = 0; i < LOOKUP_HEAD.length; i++) if (!LOOKUP_HEAD[i].test(lines[i])) return null;
  const seen = new Set(), items = [];
  for (const line of lines.slice(LOOKUP_HEAD.length)) {
    if (!LOOKUP_ITEM.test(line) || seen.has(line)) return null;
    seen.add(line);
    items.push([line.slice(0, 64), line.slice(65)]);
  }
  return { nonce: lines[2].slice('nonce '.length), items };
}

// Files the maintainers know as malware, by SHA-256. They come in as SQL
// (tools/bad-hashes-sql.mjs), so only with D1. answer = 1: the check answers known_bad;
// answer = 0: the entry waits for a person, and the check answers as if it were not there.
// asked counts the requests that asked about the file, released or not (one each, however
// many of its lines name it), and asked_last is the day of the last one, so the maintainers
// see a file come up before they release it. Anyone can send requests: a hint, not a count
// of devices.
export const BAD_HASHES_TABLE = "CREATE TABLE IF NOT EXISTS bad_hashes (sha256 TEXT PRIMARY KEY, note TEXT NOT NULL, answer INTEGER NOT NULL DEFAULT 0, by TEXT NOT NULL, at TEXT NOT NULL, asked INTEGER NOT NULL DEFAULT 0, asked_last TEXT NOT NULL DEFAULT '')";
let badHashesTable = false;
export const badHashes = {
  async ready(env) {
    if (badHashesTable) return;
    await env.DB.prepare(BAD_HASHES_TABLE).run();
    badHashesTable = true;
  },
  // the entries among these fingerprints, as a Map from fingerprint to { answer, last }
  async find(env, files) {
    await badHashes.ready(env);
    const places = files.map((_, i) => '?' + (i + 1)).join(', ');
    const { results } = await env.DB.prepare(`SELECT sha256, answer, asked_last FROM bad_hashes WHERE sha256 IN (${places})`).bind(...files).all();
    return new Map(results.map((r) => [r.sha256, { answer: Number(r.answer), last: r.asked_last }]));
  },
  // one more day for each of these fingerprints; a second worker that saw the same old day
  // changes nothing
  async count(env, files, day) {
    const up = env.DB.prepare('UPDATE bad_hashes SET asked = asked + 1, asked_last = ?2 WHERE sha256 = ?1 AND asked_last <> ?2');
    await env.DB.batch(files.map((file) => up.bind(file, day)));
  },
  // every entry, for the dashboard: an object from fingerprint to the entry
  async all(env) {
    await badHashes.ready(env);
    const { results } = await env.DB.prepare('SELECT sha256, note, answer, by, at, asked, asked_last FROM bad_hashes').all();
    return Object.fromEntries(results.map((r) => [r.sha256, { note: r.note, answer: Number(r.answer), by: r.by, at: r.at, asked: Number(r.asked), asked_last: r.asked_last }]));
  },
  // from the dashboard: on the list with answer 1, keeping its counter, or off it
  async set(env, file, entry) {
    await badHashes.ready(env);
    if (!entry) await env.DB.prepare('DELETE FROM bad_hashes WHERE sha256 = ?1').bind(file).run();
    else await env.DB.prepare('INSERT INTO bad_hashes (sha256, note, answer, by, at) VALUES (?1, ?2, 1, ?3, ?4) ON CONFLICT (sha256) DO UPDATE SET note = excluded.note, answer = 1, by = excluded.by, at = excluded.at').bind(file, entry.note, entry.by, entry.at).run();
  },
};

// The marks "probably safe" and "known malware" of the dashboard as the check needs them: a
// Map from the SHA-256 of a mark's key to its verdict, the fingerprints it was set for and
// whether it holds for every file at its path. Kept per isolate for a minute, so that a
// check costs no query of its own and a mark set or removed on the dashboard counts a
// minute later at the latest; one set in this isolate counts at once. Marks "probably not
// safe" and suggestions never count. "now" can be replaced, for the tests.
export const markCache = { ttl: 60_000, now: () => Date.now(), at: 0, map: null, gen: 0 };
async function checkMarks(env) {
  const now = markCache.now(), gen = markCache.gen;
  if (markCache.map && now >= markCache.at && now - markCache.at < markCache.ttl) return markCache.map;
  const map = new Map();
  for (const [key, label] of Object.entries(await labels.all(env))) {
    if (!label || !['safe', 'malware'].includes(label.verdict) || !Array.isArray(label.hashes)) continue;
    map.set(await sha256hex(key), { verdict: label.verdict, every: label.every === true, hashes: new Set(label.hashes.filter((h) => typeof h === 'string')) });
  }
  // kept only when no mark was set while it was read: else it could be the old marks
  if (markCache.gen === gen) {
    markCache.at = now;
    markCache.map = map;
  }
  return map;
}

// One word per line, in the order asked: a file on the malware list, then a known release
// file, then the marks of the dashboard.
async function lookupWords(env, items, day, ctx) {
  const bad = env.DB ? await badHashes.find(env, [...new Set(items.map(([, file]) => file))]) : new Map();
  const marks = await checkMarks(env);
  const words = items.map(([key, file]) => {
    const mark = marks.get(key);
    if (bad.get(file)?.answer === 1) return 'known_bad';
    // a release file is never malware by a mark, even one for every file at its path: a
    // mark for one odd file at the path of a release would else hit every device with the
    // release (review of 2.61). Only the malware list can name such a file.
    if (KNOWN_RELEASE_HASHES.has(file)) return 'known_safe';
    // "known malware" for every file at its path, or for the files it was set for
    if (mark?.verdict === 'malware' && (mark.every || mark.hashes.has(file))) return 'known_bad';
    // "probably safe" only for the files it was set for, even when it hides every file at
    // its path on the dashboard: a file nobody has seen is not called safe
    if (mark?.verdict === 'safe' && mark.hashes.has(file)) return 'known_safe';
    return 'unknown';
  });
  // One more day for each file of this request that is in the table, released or not, and
  // not counted today yet: at most one write per entry and day, however many requests come
  // (made-up requests could otherwise run up D1 writes, which the spending limit does not
  // cover). Started when every read is done and not waited for: an answer that waited for
  // the write, or read the marks behind it, would take longer for a file in the table, and
  // so tell an entry that waits from a file nobody listed (review of 2.60).
  const due = [...bad].filter(([, e]) => e.last !== day).map(([file]) => file);
  if (due.length) {
    const counted = badHashes.count(env, due, day).catch(() => { /* the answer does not depend on the counter */ });
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(counted);
    else await counted;
  }
  return words;
}

async function lookup(request, env, ctx) {
  if (env.LOOKUP !== 'on') return plain('not found\n', 404);
  if (request.method !== 'POST') return plain('method not allowed\n', 405);
  const body = await readCapped(request, LOOKUP_MAX_BYTES);
  if (!body) return plain('too large\n', 413);
  const ask = lookupRequest(body);
  if (!ask) return plain('bad request\n', 400);
  const now = new Date().toISOString();
  let words;
  try {
    words = await lookupWords(env, ask.items, now.slice(0, 10), ctx);
  } catch {
    // the database or KV failed: no answer rather than one that misses an entry
    return plain('not available\n', 503);
  }
  const lines = ['csa-2026-01-lookup-answer 1', 'nonce ' + ask.nonce, `at ${now.slice(0, 10)} ${now.slice(11, 16)} UTC`];
  ask.items.forEach(([key, file], i) => lines.push(`${key} ${file} ${words[i]}`));
  return plain(lines.join('\n') + '\n');
}

export default {
  async fetch(request, env, ctx) {
    const { pathname, hostname } = new URL(request.url);
    // the result page; the long form of the address leads to the short one (a browser
    // keeps the part after "#" across the redirect)
    if (pathname === '/2026-01/') return resultPage(request, env, ctx);
    // the table for the advisory: models and firmware versions with traces, by the reports
    if (pathname === '/2026-01/reported.json') return reported(request, env, ctx);
    // the version of the script and the table, for the pages on gl-i.net
    if (pathname === '/2026-01/live.json') return live(request, env, ctx);
    if (/^\/(csa-)?2026-01\/?$/.test(pathname)) return Response.redirect(new URL('/2026-01/', request.url).href, 302);
    // On csa.gl-i.net the page is also the front door: csa.gl-i.net/#AA006011D is what the
    // script prints. A code typed without the "#" arrives as the path; the page then moves
    // it behind the "#" itself.
    if (hostname.startsWith('csa.') && (pathname === '/' || /^\/[0-9A-Za-z-]{9,16}$/.test(pathname))) return resultPage(request, env, ctx);
    if (/\/csa-2026-01-fix\.sig$/.test(pathname)) return signature(request, env);
    if (/\/csa-2026-01-fix(\/|$)/.test(pathname)) return script(request, env, ctx, pathname);
    // the fingerprint check (docs/lookup.md), for every method: a POST there is never a
    // report. Only at this one address, like the reports, so that a rate limit on its path
    // covers every way in.
    if (pathname === '/csa-2026-01-report/lookup') return lookup(request, env, ctx);
    if (pathname.endsWith('/migrate')) {
      // a browser, or curl without -X POST, sends GET and would only see the text below
      if (request.method !== 'POST') return text('This address needs POST: curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" <this address>', 405);
      return migrate(request, env);
    }
    if (pathname.endsWith('/dashboard/labels') && (request.method === 'GET' || request.method === 'POST')) return dashboard(request, env, 'labels');
    if (pathname.endsWith('/dashboard/bad-hashes') && request.method === 'POST') return dashboard(request, env, 'bad-hashes');
    // Reports are taken only at the address the script sends to. A POST anywhere else stores
    // nothing, so a rate limit on this one path (a Cloudflare rule, ahead of the worker)
    // covers every way in.
    if (request.method === 'POST' && /^\/csa-2026-01-report\/?$/.test(pathname)) return submit(request, env);
    if (request.method === 'GET' && pathname.endsWith('/export')) return exportReports(request, env);
    if (request.method === 'GET' && /\/dashboard\/?$/.test(pathname)) return dashboard(request, env, false);
    if (request.method === 'GET' && pathname.endsWith('/dashboard/data')) return dashboard(request, env, true);
    if (request.method === 'GET' && pathname.endsWith('/dashboard/latest')) return dashboard(request, env, 'latest');
    if (request.method === 'GET') {
      return text(
        'This address receives the short, anonymous reports of the community script for CSA-2026-01.\n' +
          'The script sends one only when its user agrees. Details: https://gl-i.net/security/csa-2026-01/fix/',
      );
    }
    return text('method not allowed', 405);
  },
};
