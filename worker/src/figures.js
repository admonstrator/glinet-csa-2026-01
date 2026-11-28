// The figures of the advisory on gl-i.net, as docs/figures.md defines them. The worker
// keeps a small state with what the figures need of every device and adds to it the
// reports received since its last run: foldFigures(state, rows) gives the new state,
// figuresOf(state, asOf) the figures. Both are pure, so that tools/figures.mjs and the
// tests run exactly what the worker runs. Every report goes through shape(), the
// dashboard's own function (shape.js, written from dashboard.html by build.mjs): the page
// and the dashboard must never count differently.
//
// The worker reads with an overlap, and a report stored a moment late arrives after later
// ones. So the same reports must give the same state however they come: in any chunks, in
// any order, some of them twice. Everything kept is therefore a maximum, a minimum, or the
// pick of the report with the most traces and of those the newest, by the time of receipt;
// never "the first report seen". That pick cannot tie: two reports of one device are not
// received in the same millisecond.
import { shape, ts } from './shape.js';

const MIN = 60_000;
// A time on the device later than the report's own arrival comes from a wrong clock there;
// such a time is left out, or one device could move a figure years ahead.
const LATE = 10 * MIN;
// A group of the firmware chart needs at least this many routers: fewer would say what
// single devices run, and a made-up firmware would make its own bar.
const SERIES_MIN = 5;
// The model as the reported table names it, from what a report may carry: "GL-MT6000",
// "GL.iNet GL-MT6000 (NAND)", "mt6000". Anything else names no model.
const modelOf = (m) => { const v = String(m || '').toLowerCase().replace(/^gl\.?inet\s+/, '').replace(/^gl-/, '').replace(/\s*\(.*\)$/, ''); return /^[a-z0-9-]{2,16}$/.test(v) ? v : null; };
const minute = (m) => new Date(m * MIN).toISOString().slice(0, 16) + 'Z';
// the windows of the figures, in minutes since 1970
const WINDOWS = {
  pipe: Date.parse('2026-11-22T00:00Z') / MIN, pipeLate: Date.parse('2026-11-24T00:00Z') / MIN,
  sweep: [Date.parse('2026-11-20T22:00Z') / MIN, Date.parse('2026-11-21T08:00Z') / MIN],
  hours: [Date.parse('2026-11-19T00:00Z') / MIN, Date.parse('2026-11-22T00:00Z') / MIN],
};

// Security firmware: a router built on 22 November or later, a KVM on V1.10.3 release1, a
// GL-RMQ1 on 1.8.7.
const built = (r) => (/(\d{4}-\d\d-\d\d)\s*$/.exec(r.firmware || '') || [])[1] || '';
const onFix = (r) => (r.kvm ? /V?1\.10\.3 release1\b/i.test(r.firmware) || (/^V?1\.8\.7/i.test(r.firmware) && /rmq1/i.test(r.model)) : r.type === 'Router' && built(r) >= '2026-11-22');

// One device as kept is an array, the device ID (or, for a report without one, the id of
// the report) first. The report that counts for the device gives received, traces, bits,
// and on open routers the firmware's major.minor, and with traces and a state file also
// the model and the minute of that file. The other places hold what all its reports say.
// Places at the end that hold nothing are left out of the stored state.
const P = {
  RECV: 1, IOC: 2, BITS: 3, SERIES: 4, MODEL: 5, AT: 6,
  TRACE: 7,     // the first report with traces on other than security firmware (ms)
  FIXED: 8,     // the newest report on security firmware (ms)
  FIXED_HIT: 9, // the newest report on security firmware with traces (ms)
  PIPE: 10,     // the latest time of the shell's pipe from 22 November on (minute)
  BD: 11,       // the first report with the older backdoor (ms)
  MORE: 12,     // the bits of M
};
const SIZE = 13;
// of the report that counts
const B = { TEST: 1, ROUTER: 2, KVM: 4, FIX: 8, HIT: 16, SHELL: 32, GC_ON: 64, GC_OFF: 128, REL8: 256, REL3: 512, MARKER: 1024 };
// of all reports of the device: the newest one on security firmware is a KVM; the first one
// with the older backdoor came from a GL-MT2500; one with the backdoor was on security firmware
const M = { FIX_KVM: 1, BD_MT2500: 2, BD_FIX: 4 };
const VERSION = 1;

// A report as a device of its own, and the minute of its command from the cloud; null for
// a report that cannot be read (one bad report must not stop the rest) or that counts for
// nothing (a test without a device ID).
function entryOf(x) {
  try {
    const r = shape(x);
    if (!Number.isFinite(r.recv) || !Number.isFinite(r.ioc)) return null;
    if (r.isTest && !r.dev) return null;
    const sane = (t) => (Number.isFinite(t) && t <= r.recv + LATE ? t : NaN);
    const e = new Array(SIZE).fill(null), fix = onFix(r), hit = r.ioc > 0, open = r.type === 'Router' && !fix, sf = sane(ts(r.state_file_time));
    e[0] = String(r.dev || r.id);
    e[P.RECV] = r.recv;
    e[P.IOC] = r.ioc;
    e[P.BITS] = (r.isTest ? B.TEST : 0) | (r.type === 'Router' ? B.ROUTER : 0) | (r.kvm ? B.KVM : 0) | (fix ? B.FIX : 0) | (hit ? B.HIT : 0) | (r.shell ? B.SHELL : 0) |
      (r.goodcloud === 'on' ? B.GC_ON : 0) | (r.goodcloud === 'off' ? B.GC_OFF : 0) | (/V1\.10\.3 release8/.test(r.firmware) ? B.REL8 : 0) | (/V1\.10\.3 release3/.test(r.firmware) ? B.REL3 : 0) | (r.kinds.includes('marker') ? B.MARKER : 0);
    const v = open ? /^(\d{1,2})\.(\d{1,3})(?!\d)/.exec(r.fw) : null;
    if (v) e[P.SERIES] = v[1] + '.' + v[2];
    if (open && hit && Number.isFinite(sf)) { e[P.MODEL] = modelOf(r.model); e[P.AT] = Math.floor(sf / MIN); }
    let more = 0, cmd = null;
    // tests count only for the pick of the report that counts
    if (!r.isTest) {
      // before and after the update: only devices with an ID can be followed
      if (r.dev && hit && !fix) e[P.TRACE] = r.recv;
      if (r.dev && fix) { e[P.FIXED] = r.recv; if (hit) e[P.FIXED_HIT] = r.recv; if (r.kvm) more |= M.FIX_KVM; }
      const pipe = sane(ts(r.pipe_time));
      if (!fix && pipe >= WINDOWS.pipe * MIN) e[P.PIPE] = Math.floor(pipe / MIN);
      if (r.bd) { e[P.BD] = r.recv; more |= (r.model === 'mt2500' ? M.BD_MT2500 : 0) | (fix ? M.BD_FIX : 0); }
      if (!fix && r.kinds.includes('cloud-command') && Number.isFinite(sf)) cmd = Math.floor(sf / MIN);
    }
    e[P.MORE] = more;
    return { e, dev: !!r.dev, cmd };
  } catch {
    return null;
  }
}

const lower = (a, b) => (a == null ? b : b == null ? a : Math.min(a, b));
const higher = (a, b) => (a == null ? b : b == null ? a : Math.max(a, b));
// e takes in f, both one device. Commutative and idempotent: the order of the reports and a
// report seen twice change nothing.
function merge(e, f) {
  if (f[P.IOC] > e[P.IOC] || (f[P.IOC] === e[P.IOC] && f[P.RECV] > e[P.RECV])) for (let i = P.RECV; i <= P.AT; i++) e[i] = f[i];
  e[P.TRACE] = lower(e[P.TRACE], f[P.TRACE]);
  if (f[P.FIXED] != null && (e[P.FIXED] == null || f[P.FIXED] > e[P.FIXED])) { e[P.FIXED] = f[P.FIXED]; e[P.MORE] = (e[P.MORE] & ~M.FIX_KVM) | (f[P.MORE] & M.FIX_KVM); }
  e[P.FIXED_HIT] = higher(e[P.FIXED_HIT], f[P.FIXED_HIT]);
  e[P.PIPE] = higher(e[P.PIPE], f[P.PIPE]);
  if (f[P.BD] != null && (e[P.BD] == null || f[P.BD] < e[P.BD])) { e[P.BD] = f[P.BD]; e[P.MORE] = (e[P.MORE] & ~M.BD_MT2500) | (f[P.MORE] & M.BD_MT2500); }
  e[P.MORE] |= f[P.MORE] & M.BD_FIX;
  return e;
}

// A state as foldFigures gives it; anything else is not one, and the worker then reads all
// reports again.
export function isFigureState(s) {
  return !!s && typeof s === 'object' && s.v === VERSION && (s.cmd === null || Number.isFinite(s.cmd)) &&
    [s.dev, s.one].every((list) => Array.isArray(list) && list.every((e) => Array.isArray(e) && typeof e[0] === 'string' && e.length > P.BITS && e.length <= SIZE));
}

// state: as foldFigures gave it, or null for none. rows: { id, received, report }, the report
// as an object. Gives a new state and leaves the one given as it was. Devices with an ID
// are kept apart from reports without one, so that neither can be taken for the other.
export function foldFigures(state, rows) {
  if (state != null && !isFigureState(state)) throw new TypeError('not a state of the figures');
  const read = (list) => new Map((list || []).map((x) => { const e = [...x]; while (e.length < SIZE) e.push(null); e[P.MORE] = e[P.MORE] || 0; return [e[0], e]; }));
  const dev = read(state && state.dev), one = read(state && state.one);
  let cmd = state ? state.cmd : null;
  for (const x of rows) {
    const got = entryOf(x);
    if (!got) continue;
    cmd = higher(cmd, got.cmd);
    const into = got.dev ? dev : one, e = into.get(got.e[0]);
    into.set(got.e[0], e ? merge(e, got.e) : got.e);
  }
  // sorted, so that the same reports always give the same state, to the byte
  const write = (map) => [...map.values()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map((e) => {
    e = [...e];
    if (e[P.MORE] === 0) e[P.MORE] = null;
    while (e.length > P.BITS + 1 && e[e.length - 1] === null) e.pop();
    return e;
  });
  return { v: VERSION, cmd, dev: write(dev), one: write(one) };
}

// The figures, field for field and in the order of docs/figures.md. asOf: the time they
// stand for, in ms.
export function figuresOf(state, asOf) {
  const s = state || foldFigures(null, []);
  const is = (e, bit) => (e[P.BITS] & bit) !== 0, has = (e, bit) => ((e[P.MORE] || 0) & bit) !== 0;
  const pair = (list) => [list.filter((e) => is(e, B.HIT)).length, list.length];
  // the pool: per device the report that counts, unless it is a test; each report without an ID
  const pool = [...s.dev.filter((e) => !is(e, B.TEST)), ...s.one];
  const R = pool.filter((e) => is(e, B.ROUTER)), K = pool.filter((e) => is(e, B.KVM));
  const Rn = R.filter((e) => !is(e, B.FIX)), Kn = K.filter((e) => !is(e, B.FIX));
  const f = { as_of: minute(Math.floor(asOf / MIN)) };
  f.devices = R.length + K.length; f.routers = R.length; f.kvm = K.length;
  f.updated = { routers: pair(R.filter((e) => is(e, B.FIX))), kvm: pair(K.filter((e) => is(e, B.FIX))) };
  f.open = { routers: pair(Rn), kvm: pair(Kn) };
  // traces on other firmware, and a report on security firmware received after the first of them
  let cr = 0, ck = 0, still = 0;
  for (const e of s.dev) {
    const t = e[P.TRACE];
    if (t == null || !(e[P.FIXED] > t)) continue;
    if (has(e, M.FIX_KVM)) ck++; else cr++;
    if (e[P.FIXED_HIT] != null && e[P.FIXED_HIT] > t) still++;
  }
  f.cleaned = { routers: cr, kvm: ck, still };
  f.shell = pool.filter((e) => is(e, B.SHELL)).length;
  f.goodcloud = { on: pair(Rn.filter((e) => is(e, B.GC_ON))), off: pair(Rn.filter((e) => is(e, B.GC_OFF))) };
  const all = [...s.dev, ...s.one];
  const pipes = all.map((e) => e[P.PIPE]).filter((t) => t != null);
  f.pipe = { since22: pipes.length, since24: pipes.filter((t) => t >= WINDOWS.pipeLate).length, last: pipes.length ? minute(Math.max(...pipes)).slice(0, 10) : null };
  f.newest_command = s.cmd == null ? null : minute(s.cmd);
  const bd = all.filter((e) => e[P.BD] != null);
  f.backdoor = { devices: bd.length, mt2500: bd.filter((e) => has(e, M.BD_MT2500)).length, after_update: bd.filter((e) => has(e, M.BD_FIX)).length };
  const rel = (bit) => { const a = K.filter((e) => is(e, bit)); return [...pair(a), a.filter((e) => is(e, B.MARKER)).length]; };
  f.kvm_release = { rm10_release8: rel(B.REL8), rm10rc_release3: rel(B.REL3) };
  // the three charts
  const ser = new Map();
  for (const e of Rn) {
    if (e[P.SERIES] == null) continue;
    const [major, minor] = e[P.SERIES].split('.').map(Number), old = major < 4 || (major === 4 && minor <= 6), name = old ? '4.6 and older' : e[P.SERIES];
    const g = ser.get(name) || { name, hit: 0, of: 0, o: old ? [0, 0] : [major, minor] };
    g.of++; if (is(e, B.HIT)) g.hit++; ser.set(name, g);
  }
  f.series = [...ser.values()].filter((g) => g.of >= SERIES_MIN).sort((a, b) => a.o[0] - b.o[0] || a.o[1] - b.o[1] || (a.name < b.name ? -1 : 1)).map(({ name, hit, of }) => ({ name, hit, of }));
  const withT = Rn.filter((e) => is(e, B.HIT) && e[P.AT] != null), byModel = new Map();
  for (const e of withT) { if (e[P.MODEL] == null) continue; if (!byModel.has(e[P.MODEL])) byModel.set(e[P.MODEL], []); byModel.get(e[P.MODEL]).push(e[P.AT]); }
  const sweep = [];
  for (const [model, mins] of byModel) {
    if (mins.length < 5) continue;
    const c = new Map();
    for (const m of mins) if (m >= WINDOWS.sweep[0] && m < WINDOWS.sweep[1]) c.set(m, (c.get(m) || 0) + 1);
    let top = null;
    for (const [m, n] of c) if (top === null || n > c.get(top) || (n === c.get(top) && m < top)) top = m;
    if (top !== null) sweep.push({ key: model, model: 'GL-' + model.toUpperCase(), at: minute(top), n: mins.filter((m) => Math.abs(m - top) <= 1).length, of: mins.length });
  }
  f.sweep = sweep.sort((a, b) => a.at.localeCompare(b.at) || a.model.localeCompare(b.model) || (a.key < b.key ? -1 : 1)).map(({ model, at, n, of }) => ({ model, at, n, of }));
  const hours = new Map();
  let used = 0;
  for (const e of withT) {
    if (e[P.AT] < WINDOWS.hours[0] || e[P.AT] >= WINDOWS.hours[1]) continue;
    used++;
    const h = minute(e[P.AT]).slice(0, 13);
    hours.set(h, (hours.get(h) || 0) + 1);
  }
  f.hours = [...hours].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([hour, n]) => ({ hour, n }));
  f.hours_routers = used;
  return f;
}

// What the rules of the figures are made of, for the worker's hash: every function and
// constant of this file. A new one goes in here too; a change to one that is not here is
// only picked up by the daily full read.
export const FIGURES_RULES = [minute, modelOf, built, onFix, entryOf, lower, higher, merge, isFigureState, foldFigures, figuresOf, JSON.stringify({ MIN, LATE, SERIES_MIN, WINDOWS, P, SIZE, B, M, VERSION })].join('\n');
