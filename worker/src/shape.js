// Generated from dashboard.html by build.mjs. Do not edit; change the HTML and run "node build.mjs".
// The code of the dashboard that shapes a report, from "const ts = (s) =>" up to "const count = (rows, key) =>".
const ts = (s) => (s ? Date.parse(s.replace(' UTC', 'Z').replace(' ', 'T')) : NaN);
// every time on the page: full date and time to the minute, UTC
const fmt = (ms) => (ms == null || !isFinite(ms) ? '–' : new Date(ms).toISOString().slice(0, 16).replace('T', ' '));
const HOUR = 3600e3, DAY = 24 * HOUR, ATTACK = Date.parse('2026-11-20T00:00:00Z'), // the chart's window: from before the attack to the end of today, because by reports devices are still being hit
  WIN = [Date.parse('2026-11-19T12:00:00Z'), Math.max(Date.parse('2026-11-22T00:00:00Z'), Math.ceil(Date.now() / (24 * 3600e3)) * 24 * 3600e3)];

const KIND = {
  'marker': 'Malware files on the device', 'applet-hijack': 'System tool replaced', 'persist-ref': 'Autostart entry starts the malware',
  'keep-ref': 'Survives a firmware update', 'persistence': 'rc.local or crontab changed', 'process implant': 'Malware process running',
  'process remote-shell': 'Remote shell running', 'process quick-check': 'GL.iNet’s crond indicator running', 'process replaced-tool': 'Replaced tool running',
  'pipe': 'Remote shell’s pipe left behind', 'connection': 'Open connection to the attacker', 'fw-rule': 'Firewall rule left by the attack',
  'installer-trace': 'Installer was at work (netstat link)', 'lua-bytecode': 'Compiled Lua in the overlay',
  'cloud-command': 'Command from the cloud ran (trace survives a restart)', 'cron-ref': 'Running crontab starts the malware',
  'rtty-server': 'Remote terminal set to the attacker’s server', 'ssh-key': 'SSH key added by the malware',
  'backdoor-init': 'Older backdoor: init script changed', 'backdoor-file': 'Older backdoor: its files', 'backdoor-keep': 'Older backdoor: survives an update',
  'backdoor-host': 'Older backdoor: server named', 'backdoor-proc': 'Older backdoor: running',
};

const BD = 'Not the attack of 20 November: an older backdoor that users of GL.iNet’s forum found, on some devices since 2025. ';
const WHY = {
  'installer-trace': 'A netstat link to busybox that was made on or after 20 November. The reports show it on KVMs, always made on the evening of the attack, on some next to the malware’s files and on others with nothing else left. The malware’s installer was at work on the device; its files may have been removed since.',
  'cloud-command': '/etc/mp_ip_mapping_info is the state file the cloud client writes each time its SD-WAN handler runs. The attack came in through that handler, with a message that leaves the file empty. An empty file written since 20 November on a device with AstroWarp off shows that such a command ran. Unlike the firewall rule it is still there after a restart. It does not say what the command did: the one that was recovered only looked for the malware and reported back.',
  'cron-ref': 'The crontab the firmware is running from (/tmp/gl_crontabs/root) has the malware’s watchdog line. It restarts the malware every three minutes.',
  'rtty-server': '/etc/rtty_conf names one of the malware’s servers. rtty is the remote terminal service of GL.iNet’s cloud; set like this, the terminal of the device is offered to the attacker.',
  'ssh-key': 'authorized_keys holds a key named gl-agent, which the malware’s installer can add. Whoever has the other half can log in as root.',
  'backdoor-init': BD + '/etc/init.d/urandom_seed (or another init script) has extra lines that copy the Lua interpreter to /usr/bin/monitord and run /bin/ulogd with it at every boot.',
  'backdoor-file': BD + '/bin/ulogd is its loader, compiled Lua that reports the device to a server imitating AdGuard or OpenWrt and fetches a second program. Its fingerprint differs from device to device. /usr/bin/monitord is a copy of the Lua interpreter under another name.',
  'backdoor-keep': BD + 'The list of files that a firmware update keeps was changed so that the backdoor survives an update with “keep settings”.',
  'backdoor-host': BD + 'A configuration file names a server the backdoor reports to: adguardns.com, adguardns.org, adsanalypro.com, lede-openproject.org, adxinsight.com or openwrt-project.org. None of them belongs to AdGuard or OpenWrt.',
  'backdoor-proc': BD + 'monitord (the loader) or ujaild (the second program, run from a deleted file in /tmp) was running during the check.',
  'marker': 'One of the files the malware puts on a device: gl-helper or gb in /etc/config/.gl/ or /etc/glinet/.cache/, or watch.sh there on a KVM. GL.iNet’s own cleanup in the KVM firmware looks for exactly these.',
  'applet-hijack': 'A system tool such as netstat was swapped for another program, so its output can no longer be trusted. GL.iNet’s cleanup for KVMs removes a replaced netstat.',
  'persist-ref': 'An autostart file (rc.local, the root crontab, an init script) has a line that points to the malware’s paths. It starts the malware again at every boot.',
  'keep-ref': 'The list of files that a firmware update keeps names the malware’s paths. An update with “keep settings” would carry the malware over.',
  'persistence': 'rc.local or the root crontab differs from the firmware image but does not point to the malware. Often the owner’s own change; it counts as “persistence”, not as a known trace.',
  'process implant': 'A program started from one of the malware’s paths was running during the check.',
  'process remote-shell': 'A root shell connected to the attacker’s server was running: a loop that pipes /bin/sh through /tmp/f and nc to 170.39.226.x. The attacker can type commands on the device.',
  'process quick-check': 'The process GL.iNet named in its forum check was running: crond -i /tmp/.log.',
  'process replaced-tool': 'A system tool that had been swapped for another program was running.',
  'pipe': '/tmp/f is the named pipe the remote shell talks through. It stays until the next restart, so it shows that the shell ran since the last boot, even when it is no longer running.',
  'connection': 'An open TCP connection to 170.39.226.0/24, the network of the server the remote shells connect to.',
  'fw-rule': 'nat:SDWAN_IP_MAPPING is a chain in the NAT table of the firewall. GL.iNet’s cloud client fills it for the AstroWarp / SD-WAN IP mapping. The attack came in as a made-up “address” for such a rule, which the client passed to the shell unchecked. The leftover rule that maps 127.0.0.1 to 127.0.0.1 shows that the injected command ran. RemoteToHome found this by reading the client’s code; GL.iNet has not confirmed it.',
};
const FIELD_WHY = {
  'Device ID': 'The same ID on two reports means the same device. It is made from a hash of a hardware address and a secret that only the server knows, so it cannot be turned back into that address.',
  'Shell pipe, last data': 'Time on /tmp/f: the last moment data went through the remote shell.',
  'Cloud handler first ran': 'The time /etc/mp_ip_mapping_info was created: the first call since the file last did not exist. Sent only where the filesystem does not update access times (noatime).',
  'Cloud handler last ran': 'Time on /etc/mp_ip_mapping_info, the state file the cloud client rewrites each time it handles an IP mapping. The attack came through that handler. Normal on devices that use AstroWarp.',
  'Counts': 'Known traces are matches for what we know of this malware. Persistence is a changed rc.local or crontab without a link to it. “To review” are other unusual changes, usually the owner’s own.',
};
const kindOf = (f) => { const w = f.split(' '); return w[0] === 'process' ? w[0] + ' ' + w[1] : w[0]; };


// Lines that every rc.local has: they come with the firmware and say nothing about the
// attack. rc.local is sent in full, so these would lead the grouped list on every device.
// They are left out there only; a single report still shows its rc.local as it was sent.
const STOCK = new Set(['exit 0', '. /lib/functions/gl_util.sh', 'remount_ubifs', '#!/bin/sh', '#!/bin/sh /etc/rc.common']);
const stock = (line) => { const t = line.trim(); return t === '' || t.startsWith('#') || STOCK.has(t); };

// The firmware as people name it: "4.9.0", or "4.9.0 beta4" for a test build. Newer
// scripts also send release, build number and date ("4.8.3 release2 build 540 2026-10-02"),
// KVMs a leading V; none of that belongs in a column heading.
function fwShort(fw) {
  const p = String(fw || '').trim().split(/\s+/);
  if (!p[0] || p[0] === 'unknown') return 'unknown';
  const v = p[0].replace(/^v/i, ''), t = (p[1] || '').toLowerCase();
  return /^(beta|rc|alpha|snapshot|test)/.test(t) ? v + ' ' + t : v;
}
const verKey = (v) => v.replace(/(\d+)/g, (n) => n.padStart(5, '0'));
const median = (a) => { const s = a.filter((n) => isFinite(n)).sort((x, y) => x - y); return s.length ? s[Math.floor((s.length - 1) / 2)] : NaN; };
// a file whose entry changed on the device long after its written time: the time was
// brought along (archive, copy) or set back. Minutes apart are normal: download, then chmod.
const LAG = 10 * 60000;
const lag = (f) => ts(f.ctime) - ts(f.mtime);
const dur = (ms) => { if (!isFinite(ms)) return '–'; const m = Math.round(ms / 60000); return m < 1 ? 'under a minute' : m < 90 ? m + ' min' : m < 48 * 60 ? Math.floor(m / 60) + ' h ' + (m % 60) + ' min' : Math.round(m / 1440) + ' days'; };

const ATTACK_FROM = Date.parse('2026-11-20T00:00:00Z');
const NOT_HIJACK = /^applet-hijack \/usr\/sbin\/tailscaled?$/;
// scripts before 2.38 took a copy of themselves, saved on the device, for a trace: the
// script names every indicator it searches for
const NOT_SELF = /^(backdoor-host|backdoor-init|persist-ref) \/\S*gl-helper-triage\.sh$/;
const BD_FILE = /^\/(bin\/ulogd|usr\/bin\/monitord)$/;
function shape(x) {
  const r = { files: [], persistence: [], fw_rules: [], commands: [], state_file_time: '', review_items: [], goodcloud: '', cloud_client: '', astrowarp: '', state_file_size: null, cloud_bound: '', rtty_ssh: '', rtty_web: '', note: '', state_file_first: '', vendor_cleanup: '', ...x.report };
  // script 2.16 and 2.17 took an updated Tailscale for a replaced system tool; not a trace
  const fp = (f) => NOT_HIJACK.test(f) || NOT_SELF.test(f);
  if (r.findings.some(fp)) { r.ioc = Math.max(0, r.ioc - r.findings.filter(fp).length); r.findings = r.findings.filter((f) => !fp(f)); r.files = r.files.filter((f) => !/^\/usr\/sbin\/tailscaled?$/.test(f.path)); }
  // Scripts before 2.17 did not know that the cloud handler's state file is a trace: they
  // sent its time and called the device clean. The reports show the rule holds (no router
  // has such a file from before the attack, and its times fall into the attack's waves),
  // so it is applied here to the older reports too.
  // Firmware built after the attack began has the fix. Script 2.46 still called an empty
  // state file a trace there, though the firmware's own SD-WAN module can write it at its
  // first start (issue 19). A state file from the build day on is no trace on such firmware.
  const built = (/(\d{4}-\d\d-\d\d)\s*$/.exec(r.firmware || '') || [])[1] || '', fresh = built >= '2026-11-20' && String(r.state_file_time || '').slice(0, 10) >= built;
  if (fresh && r.findings.some((f) => f.startsWith('cloud-command'))) { r.ioc = Math.max(0, r.ioc - r.findings.filter((f) => f.startsWith('cloud-command')).length); r.findings = r.findings.filter((f) => !f.startsWith('cloud-command')); }
  if (!fresh && r.platform === 'openwrt' && r.astrowarp !== 'on' && (r.state_file_size === null || r.state_file_size === 0) && ts(r.state_file_time) >= ATTACK_FROM && !r.findings.some((f) => f.startsWith('cloud-command'))) {
    r.findings = [...r.findings, 'cloud-command /etc/mp_ip_mapping_info']; r.ioc += 1; r.derived = true;
  }
  // Remote SSH and web access are stored settings, "on" by default on many firmware
  // versions, and only in use while GoodCloud is on. With GoodCloud off they count as off.
  if (r.goodcloud === 'off') { if (r.rtty_ssh === 'on') r.rtty_ssh = 'off'; if (r.rtty_web === 'on') r.rtty_web = 'off'; }
  r.id = x.id || x.received + JSON.stringify(x.report).length;
  r.recvIso = x.received;
  r.dev = r.device_id || '';
  r.fw = fwShort(r.firmware);
  r.recv = Date.parse(x.received);
  r.kinds = [...new Set(r.findings.map(kindOf))];
  // the older backdoor is counted apart: "with traces" means the attack of 20 November
  const bdN = r.findings.filter((f) => f.startsWith('backdoor-')).length;
  r.bd = bdN > 0; r.iocAll = r.ioc; r.ioc = Math.max(0, r.ioc - bdN);
  r.isTest = r.model === 'unknown' && r.platform === 'unknown' && r.ioc === 0;
  r.kvm = r.platform.startsWith('glkvm');
  r.type = r.kvm ? 'KVM' : r.platform === 'openwrt' ? 'Router' : r.platform;
  // three things that are not the same: a remote shell that was seen, malware on the
  // device, and only the trace that a command from the cloud ran
  r.shell = r.kinds.some((k) => ['process remote-shell', 'pipe', 'connection'].includes(k));
  r.implant = r.kinds.some((k) => ['marker', 'applet-hijack', 'persist-ref', 'keep-ref', 'process implant', 'process quick-check', 'cron-ref', 'rtty-server', 'ssh-key'].includes(k));
  r.cmd = !r.shell && !r.implant && r.kinds.some((k) => k === 'fw-rule' || k === 'cloud-command' || k === 'installer-trace');
  r.cls = r.implant ? 'malware' : r.shell ? 'shell' : r.cmd ? 'command' : r.bd ? 'backdoor' : r.ioc > 0 ? 'other' : 'clean';
  r.upSince = ts(r.checked_at) - r.uptime_s * 1000;
  r.restarted = r.upSince > ATTACK;
  // a file whose written time is much older than its change on the device brought that
  // time along or had it set back (the installer can do that); then the change time counts
  const ftime = (f) => (f.ctime && lag(f) > LAG ? ts(f.ctime) : ts(f.mtime));
  const times = [ts(r.shell_started), r.cmd ? ts(r.state_file_time) : NaN, ...r.files.filter((f) => r.ioc === 0 || !BD_FILE.test(f.path)).map(ftime)].filter((n) => !isNaN(n));
  // the newest time on a trace, the state file of a cloud command included. latestW takes the
  // written time of files only: a firmware update that keeps the settings puts the files back
  // and gives them a new change time.
  const sf = r.findings.some((f) => f.startsWith('cloud-command')) ? ts(r.state_file_time) : NaN, newest = (l) => { l = l.filter((n) => !isNaN(n)); return l.length ? Math.max(...l) : NaN; };
  r.latest = newest([...times, sf]);
  r.latestW = newest([ts(r.shell_started), sf, ...r.files.filter((f) => r.ioc === 0 || !BD_FILE.test(f.path)).map((f) => ts(f.mtime))]);
  r.first = times.length ? Math.min(...times) : NaN;
  r.story = story(r);
  r.hay = [r.model, r.platform, r.firmware, r.tool, r.dev, r.findings.join(' '), r.shell_ports.join(' '), r.files.map((f) => f.path + ' ' + f.sha256).join(' '), r.commands.join(' '), r.fw_rules.join(' '), r.review_items.map((i) => i.kind + ' ' + i.path + ' ' + i.sha256).join(' '), r.persistence.map((p) => p.path + ' ' + p.lines.join(' ')).join(' ')].join(' ').toLowerCase();
  return r;
}
function story(r) {
  if (r.ioc === 0 && !r.bd) return 'Nothing known found.';
  const s = [];
  if (r.bd) s.push(r.kinds.includes('backdoor-proc') ? 'Older backdoor (urandom_seed/ulogd) on the device and running.' : 'Older backdoor (urandom_seed/ulogd) on the device.');
  if (r.ioc === 0) return s.join(' ');
  if (r.cmd && r.kinds.includes('installer-trace')) s.push('The malware’s installer was at work (netstat link made during the attack). Its files are not there now.');
  else if (r.cmd) s.push(r.kinds.includes('fw-rule') ? 'A command from the cloud ran. No remote shell or malware found.' : 'A command from the cloud ran, seen after a restart. No remote shell or malware found.');
  if (r.kinds.includes('process remote-shell')) s.push(`Remote shell running${r.shell_ports.length ? ' on port ' + r.shell_ports.join(', ') : ''}.`);
  else if (r.kinds.includes('pipe')) s.push('Remote shell ran since the last restart, not running now.');
  if (r.kinds.includes('marker')) s.push(r.kinds.includes('process implant') ? 'gl-helper malware on the device and running.' : 'gl-helper malware files on the device.');
  if (r.kinds.includes('applet-hijack')) s.push('A system tool was replaced.');
  if (r.kinds.includes('persist-ref') || r.kinds.includes('keep-ref')) s.push('Starts again after a restart.');
  if (r.kinds.includes('process quick-check')) s.push('GL.iNet’s crond indicator is running.');
  return s.join(' ') || 'Known traces found.';
}
export { shape, ts };
export const SHAPE_SHA256 = '2bb2e69f90c7d667f9ad7ad80bb99cf3da102bf67f31f6b168ce5535d8a5a527';
