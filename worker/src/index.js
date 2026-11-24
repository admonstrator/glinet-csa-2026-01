// Collects the short, anonymous reports that gl-helper-triage.sh sends when its user
// agrees. One report is a few facts about a device (model, firmware, which indicators
// were found, when). The worker stores exactly the fields listed below and nothing
// about the sender: no IP address, no country, no headers.

import { DASHBOARD } from './dashboard.js';
import { RESULT } from './result.js';

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
const row = (r) => ({ id: r.id, received: r.received, report: JSON.parse(r.report) });
const kvLoad = async (env, names) =>
  (await Promise.all(names.map(async (name) => [name, await env.REPORTS.get(name)]))).filter((x) => x[1]).map(([id, v]) => ({ id, ...JSON.parse(v) }));

// What the team says about a finding that the scripts listed for review: "probably safe",
// with a note. The dashboard then hides it unless asked. Everyone who may open the
// dashboard may set and remove a label, and each label records who set it (the address
// Cloudflare Access signed in). One label per kind and path; it remembers the fingerprints it
// was given for, so a new file at a path that was called harmless shows up again.
// Kept in D1 (the table is created on first use) or, without D1, in one KV entry.
const LABELS_KEY = 'meta/csa-2026-01-labels';
let labelsTable = false;
const labels = {
  async ready(env) {
    if (labelsTable) return;
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, verdict TEXT NOT NULL, note TEXT NOT NULL, hashes TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL)').run();
    labelsTable = true;
  },
  async all(env) {
    if (env.DB) {
      await labels.ready(env);
      const { results } = await env.DB.prepare('SELECT key, verdict, note, hashes, by, at FROM labels').all();
      return Object.fromEntries(results.map((r) => [r.key, { verdict: r.verdict, note: r.note, hashes: JSON.parse(r.hashes), by: r.by, at: r.at }]));
    }
    return JSON.parse((await env.REPORTS.get(LABELS_KEY)) || '{}');
  },
  async set(env, key, label) {
    if (env.DB) {
      await labels.ready(env);
      if (!label) await env.DB.prepare('DELETE FROM labels WHERE key = ?1').bind(key).run();
      else await env.DB.prepare('INSERT OR REPLACE INTO labels (key, verdict, note, hashes, by, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)').bind(key, label.verdict, label.note, JSON.stringify(label.hashes), label.by, label.at).run();
      return;
    }
    const all = JSON.parse((await env.REPORTS.get(LABELS_KEY)) || '{}');
    if (label) all[key] = label; else delete all[key];
    await env.REPORTS.put(LABELS_KEY, JSON.stringify(all));
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
  if (!['safe', '', 'decline'].includes(body.verdict)) return 'bad verdict';
  if (!(typeof body.note === 'string' && body.note.length <= 200 && /^[\x20-\x7e]*$/.test(body.note))) return 'bad note';
  if (!(Array.isArray(body.hashes) && body.hashes.length <= 60 && body.hashes.every((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)))) return 'bad hashes';
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
  const raw = await request.text();
  if (raw.length > MAX_BYTES) return text('too large', 413);
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
  if (data === 'labels') {
    const out = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
    const both = async () => out({ labels: await labels.all(env), suggestions: await suggestions.all(env), you: user });
    if (request.method === 'GET') return both();
    // a change: only from the dashboard itself. A form on another site cannot send JSON,
    // and the browser names the page a request comes from.
    if (!(request.headers.get('content-type') || '').startsWith('application/json') || request.headers.get('origin') !== new URL(request.url).origin) return text('not from the dashboard', 403);
    let body;
    try { body = JSON.parse((await request.text()).slice(0, 8192)); } catch { return text('not JSON', 400); }
    const bad = validLabel(body);
    if (bad) return text(bad, 400);
    if (body.verdict === 'decline') {
      if (!env.DB) return text('suggestions need the database', 400);
      await suggestions.decline(env, body.key, user);
      return both();
    }
    await labels.set(env, body.key, body.verdict ? { verdict: body.verdict, note: body.note, hashes: body.hashes, by: user, at: new Date().toISOString() } : null);
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
  const have = JSON.parse((await env.REPORTS.get(SCRIPT_KEY)) || 'null');
  const last = Math.max(have ? have.checked : 0, Number((await env.REPORTS.get(TRIED_KEY)) || 0));
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
    await env.REPORTS.put(SCRIPT_KEY, JSON.stringify(next));
    return next;
  } catch (e) {
    // GitHub not reachable or rate limited: keep what there is, try again in half a minute,
    // and say why to whoever asked for the refresh
    errors.push(String((e && e.message) || e));
    try { await env.REPORTS.put(TRIED_KEY, String(Date.now() - 570_000)); } catch { /* the next call tries again */ }
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
  let have = JSON.parse((await env.REPORTS.get(SCRIPT_KEY)) || 'null');
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
  let have = JSON.parse((await env.REPORTS.get(SCRIPT_KEY)) || 'null');
  if (request.method === 'POST') {
    const sigText = (await request.text()).slice(0, 1024);
    // the signature may be for a version this worker has not fetched yet
    if (!have || !(await signatureFits(env, sigText, have.body))) have = await refreshScript(env, true);
    if (!have) return text('could not reach GitHub', 502);
    if (!(await signatureFits(env, sigText, have.body))) return text('this signature does not fit the script served now', 400);
    await env.REPORTS.put(SIG_KEY, JSON.stringify({ sha: await sha256hex(have.body), sig: sigText }));
    return text(have.commit);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  const kept = JSON.parse((await env.REPORTS.get(SIG_KEY)) || 'null');
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
    await env.REPORTS.put(FIRMWARE_KEY, JSON.stringify(next));
    return next;
  } catch {
    if (have) await env.REPORTS.put(FIRMWARE_KEY, JSON.stringify({ ...have, checked: Date.now() - 3000_000 }));
    return have;
  }
}
async function firmwareList(env, ctx) {
  let have = null;
  try { have = JSON.parse((await env.REPORTS.get(FIRMWARE_KEY)) || 'null'); } catch { have = null; }
  if (!have) return refreshFirmware(env, null);
  if (Date.now() - have.checked > 3600_000) ctx.waitUntil(refreshFirmware(env, have));
  return have;
}

async function resultPage(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  let current = '';
  try {
    const have = JSON.parse((await env.REPORTS.get(SCRIPT_KEY)) || 'null');
    current = ((have && /^VERSION=(\d{1,2}\.\d{1,3})$/m.exec(have.body)) || [])[1] || '';
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

// rows: one per report, oldest first. fw: the models of the firmware list.
export function reportedTable(rows, fw, min = REPORTED_MIN) {
  const first = new Map();
  for (const r of rows) {
    if (typeof r.dev !== 'string' || !r.dev || first.has(r.dev) || !attackTrace(r)) continue;
    first.set(r.dev, r);
  }
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

async function refreshReported(env, ctx, have) {
  try {
    const fw = await firmwareList(env, ctx);
    if (!fw || !fw.models) throw new Error('no firmware list');
    const x = (f) => `json_extract(report, '$.${f}')`;
    // only what the table needs, and only reports that can count
    const { results } = await env.DB.prepare(
      `SELECT ${x('device_id')} AS dev, ${x('model')} AS model, ${x('firmware')} AS firmware, ${x('platform')} AS platform, ${x('ioc')} AS ioc, ${x('findings')} AS findings, ` +
        `${x('astrowarp')} AS astrowarp, ${x('state_file_size')} AS state_file_size, ${x('state_file_time')} AS state_file_time FROM reports ` +
        `WHERE ${x('device_id')} != '' AND (${x('ioc')} > 0 OR ${x('state_file_time')} != '') ORDER BY received, id`,
    ).all();
    for (const r of results) { try { r.findings = JSON.parse(r.findings || '[]'); } catch { r.findings = []; } }
    const next = { checked: Date.now(), body: { advisory: 'CSA-2026-01', as_of: new Date().toISOString().slice(0, 16) + 'Z', min_devices: REPORTED_MIN, models: reportedTable(results, fw.models) } };
    await env.REPORTS.put(REPORTED_KEY, JSON.stringify(next));
    return next;
  } catch {
    // keep what there is, and try again in a few minutes rather than on every call
    if (have) await env.REPORTS.put(REPORTED_KEY, JSON.stringify({ ...have, checked: Date.now() - REPORTED_EVERY + 180_000 }));
    return have || null;
  }
}

async function reported(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  if (!env.DB) return text('not available', 503);
  let have = null;
  try { have = JSON.parse((await env.REPORTS.get(REPORTED_KEY)) || 'null'); } catch { have = null; }
  if (!have) have = await refreshReported(env, ctx, null);
  else if (Date.now() - have.checked > REPORTED_EVERY) ctx.waitUntil(refreshReported(env, ctx, have));
  if (!have) return text('not available', 503);
  return new Response(request.method === 'HEAD' ? null : JSON.stringify(have.body) + '\n', {
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*', 'x-content-type-options': 'nosniff' },
  });
}

export default {
  async fetch(request, env, ctx) {
    const { pathname, hostname } = new URL(request.url);
    // the result page; the long form of the address leads to the short one (a browser
    // keeps the part after "#" across the redirect)
    if (pathname === '/2026-01/') return resultPage(request, env, ctx);
    // the table for the advisory: models and firmware versions with traces, by the reports
    if (pathname === '/2026-01/reported.json') return reported(request, env, ctx);
    if (/^\/(csa-)?2026-01\/?$/.test(pathname)) return Response.redirect(new URL('/2026-01/', request.url).href, 302);
    // On csa.gl-i.net the page is also the front door: csa.gl-i.net/#AA006011D is what the
    // script prints. A code typed without the "#" arrives as the path; the page then moves
    // it behind the "#" itself.
    if (hostname.startsWith('csa.') && (pathname === '/' || /^\/[0-9A-Za-z-]{9,16}$/.test(pathname))) return resultPage(request, env, ctx);
    if (/\/csa-2026-01-fix\.sig$/.test(pathname)) return signature(request, env);
    if (/\/csa-2026-01-fix(\/|$)/.test(pathname)) return script(request, env, ctx, pathname);
    if (pathname.endsWith('/migrate')) {
      // a browser, or curl without -X POST, sends GET and would only see the text below
      if (request.method !== 'POST') return text('This address needs POST: curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" <this address>', 405);
      return migrate(request, env);
    }
    if (pathname.endsWith('/dashboard/labels') && (request.method === 'GET' || request.method === 'POST')) return dashboard(request, env, 'labels');
    if (request.method === 'POST') return submit(request, env);
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
