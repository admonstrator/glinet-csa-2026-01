#!/bin/sh
# shellcheck shell=sh disable=SC3043
#
# gl-helper-triage.sh - triage for the "gl-helper" implant (GL.iNet incident 2026-11-20)
#
# Runs ON the device as root: GL.iNet KVMs (buildroot) and GL.iNet / OpenWrt routers.
# Needs only busybox sh/ash or bash.
#
#   sh gl-helper-triage.sh [--check]            read-only detection (default)
#   sh gl-helper-triage.sh --archive [-o DIR]   collect evidence into DIR (default /tmp)
#   sh gl-helper-triage.sh --archive --stdout   stream the evidence tar.gz to stdout
#   sh gl-helper-triage.sh --fix [-o DIR]       archive first (mandatory), then remediate
#
# At the end the script offers to send a short anonymous report (model, firmware, which
# indicators, when) to the community, also from a device without indicators, so that we
# see which devices were not hit. It shows the report and sends it only
# after "y". --report sends it without asking, --no-report never asks, --show-report
# prints the complete report and sends nothing. The report carries a device ID so that
# several reports from one device count once: a hash of a hardware address, never the
# address itself, and the server hashes it again with a secret before it stores it.
# --no-device-id leaves it out. --note TEXT adds a short note of your own (where the
# report comes from, before or after a clean-up, a repeat); it is shown before sending.
#
# Output is coloured on a terminal. --color forces colours (e.g. through ssh without a
# tty), --no-color or NO_COLOR=1 turns them off. The report in the archive is plain text.
#
# From a PC (or use triage-remote.sh, which pulls and verifies the evidence before fixing):
#   ssh root@DEVICE 'sh -s -- --check' < gl-helper-triage.sh
#   ssh root@DEVICE 'sh -s -- --archive --stdout' < gl-helper-triage.sh > evidence.tar.gz
#
# The overlay is detected automatically: upper /userdata/overlay/upper (KVM) or
# /overlay/upper (OpenWrt), read-only base image /rom.
# Test options: --root DIR (merged root, default /), --upper DIR, --lower DIR.
#
# Exit codes: 0 clean | 1 IOC found | 2 fixed, no IOC left | 3 fix incomplete | 4 error
#
# The IOCs come from GL.iNet's own boot cleanup in RM1PE firmware 1.10.2
# (/etc/init.d/S08overlayfs). That cleanup only fires when one of four marker files
# exists and only removes a fixed set. This script also flags busybox applets replaced
# by foreign binaries, IOC processes and other overlay changes worth reviewing. It also
# runs GL.iNet's quick check for routers (a process "crond -i /tmp/.log") and looks for a
# remote shell that users reported in GL.iNet's forum.
# --fix only touches IOC items and their persistence. REVIEW items are archived and
# reported, never changed. This is a stopgap: a factory reset is still recommended.

VERSION=2.48
# When this version went out, in UTC. Changed together with VERSION. The guide on the
# website reads both lines to show the current version and how long ago it came out.
RELEASED='2026-11-22 22:53 UTC'

# Where the malware lives and what it puts there. The first two directories are the ones
# GL.iNet's cleanup in the KVM firmware knows. The rest comes from the installer itself
# (ni.sh, read by a forum user, topic 73056 post 90): it takes the first directory it can
# write to, keeps a copy of everything in /etc/config/.gl because that survives a firmware
# update, and writes these files. watch.sh runs every three minutes from cron.
MARKER_DIRS="etc/glinet/.cache etc/config/.gl"
MARKER_DIRS_ALT="etc/gl_nas/.cache userdata/.gl overlay/.gl tmp/.gl"
MARKER_FILES="gl-helper gb watch.sh run.sh wake.sh boot.sh rtty_keep.sh eco eco.tmp node .u .wc install.log"
PERSIST="etc/rc.local etc/crontabs/root"
APPLET_DIRS="bin sbin usr/bin usr/sbin"
REVIEW_PATHS="etc/init.d etc/rc.d etc/inittab etc/profile etc/profile.d etc/hotplug.d
etc/uci-defaults etc/kvmd/user/scripts etc/crontabs root/.ssh etc/dropbear
etc/sysupgrade.conf lib/upgrade/keep.d etc/udhcpc.user.d"
# etc/udhcpc.user.d: the router runs every script there on each DHCP event, and the keep
# list carries the directory across an update (read by RemoteToHome in two images).
IOC_RE='gl-helper|/\.gl/|/\.cache/gb|/\.cache/(watch|run|wake|boot|rtty_keep)\.sh|gl_nas/\.cache'
# Firewall configuration: files that fw3/fw4 and GL.iNet's scripts build the rules from.
FW_PATHS="etc/config/firewall etc/firewall.user etc/firewall.d etc/nftables.d usr/share/nftables.d"
# The command users found started with this rule (see SHELL_RE below): it is what is left
# in the firewall after that command ran.
# The handler behind that rule ends each run by writing its state file,
# /etc/mp_ip_mapping_info. It writes one line per entry that has a MAC address; the
# attack's message has none, so the file is empty. The rule is gone after a restart or
# when the cloud client stops, the file stays. An empty file written since the attack
# began, on a device that does not use AstroWarp, therefore shows that such a message
# ran, also after a restart. Worked out by a forum user from the memory of the cloud
# client on a GL-BE9300; the one message recovered there only listed the malware's
# folders and sent the listing to the attacker's server, it installed nothing.
ATTACK_FROM='2026-11-20 00:00:00 UTC'
FW_RULE_RE='^-A SDWAN_IP_MAPPING .*-d 127\.0\.0\.1(/32)? .*--to-destination 127\.0\.0\.1'
# Running processes. PROC_RE is GL.iNet's own quick check for routers (forum, 2026-11-21):
# "ps | grep tmp" shows "crond -i /tmp/.log". SHELL_RE is a remote root shell that users
# reported in the same thread (a loop around a pipe at /tmp/f and nc to SHELL_IP). GL.iNet
# staff recommends checking for it and for the tools in TOOL_RE, with
#   ps ww | grep -E '[n]c |[n]etcat|[s]ocat|[/]bin/sh -i|[m]kfifo'
# and for connections held by a shell or by such a tool (netstat -tnp).
PROC_RE='crond -i /tmp/\.log'
SHELL_IP='170.39.226.219'
# Three reports so far, the same address with a different port each. Connections are
# matched against the whole /24 in case the other end moves.
SHELL_NET='170.39.226.'
TOOL_RE='(^|[ /])(nc|netcat|socat) |/bin/sh -i|mkfifo'
# Addresses a forum user recorded from a KVM that was taken over on 2026-11-19 (topic
# 73056, post 79): a command channel and the server the malware was fetched from. One
# report, so a connection there is for a human to judge.
KVM_NETS='65.20.71.131 66.245.219.252'
# The same two addresses, and the name that KVM looked up, on a command line or in an
# autostart file. gl-inet.top is an old name of GL.iNet's that was registered anew on
# 2026-11-16; who holds it now is not known.
KVM_RE='65\.20\.71\.131|66\.245\.219\.252|gl-inet\.top'
# The two addresses alone. They are in the installer as well (the servers it fetches the
# malware from, ports 8000 and 8899, and the attacker's own rtty server), so with two
# sources they count as indicators.
# gl-inet.top counts too since the malware's helper was read (topic 73056, post 92): it
# is in there as a fallback server, gl-inet.top:8899.
KVM_IP_RE='65\.20\.71\.131|66\.245\.219\.252|gl-inet\.top'
CONN_RE='/(nc|netcat|socat|sh|ash|bash)$'
SHELL_RE="170\\.39\\.226\\.|/tmp/f([ ;|>]|\$)"
# A second, older backdoor that is not part of GL.iNet's notice of 2026-11-20. Users of
# GL.iNet's forum found it on a GL-AX1800 (4.8.3) and a GL-X2000 (4.7.13), dated back to
# 2025 (topic 73097 by ehidle; posts 26, 63 and 65 of the notice's topic 73056):
# Since then confirmed in that topic on a GL-MT3000 (4.11.0) and a second GL-AX1800,
# with dates from October 2025 to March 2026.
#   /etc/init.d/urandom_seed  extra lines at the top: copy /usr/bin/lua to
#                             /usr/bin/monitord, run /bin/ulogd with it
#   /bin/ulogd                compiled Lua, reports the device to a server whose name
#                             imitates AdGuard and fetches a second program
#   ujaild                    that second program, run from a deleted file in /tmp
#   lib/upgrade/keep.d/netifd /bin/ulogd and /etc/init.d/urandom_seed are appended, so a
#                             firmware update carries it over (post 78 of topic 73056)
# Findings of this family have a kind that starts with "backdoor-". --fix leaves them
# alone: the second stage runs in memory only and nobody has taken it apart yet, so a
# "cleaned" would promise more than a script can keep. The answer is a reflash.
BD_RE='monitord|/bin/ulogd|ujaild|adguardns|lede-openproject|adxinsight|openwrt-project'
BD_KEEP_RE='ulogd|monitord|urandom_seed|ujaild'
# Server names decoded from two variants of the loader (ehidle, acs). Other variants may
# use other names: /bin/ulogd differs from device to device, four hashes on four devices.
BD_HOST_RE='adguardns\.(com|org)|lede-openproject\.org|adxinsight\.com|openwrt-project\.org'
# The changed urandom_seed, the same file on three reported devices (X2000, MT3000, AX1800)
BD_INIT_SHA=3265f27feb954744581cdea2373b88ceae9d85b67e90487353fd48902cf4fc19
# /bin/ulogd as posted in topic 73097 (posts 1, 2, 3 and 6). The file differs from device
# to device, so these are no detection rule; a match only says "seen before".
# A survey of 28 routers with the backdoor found a different hash on every one, none of
# them in this list. The list is kept for the samples it came from.
BD_ULOGD_SHAS='c5e87c80f76415f399ce4d1644f5ddc3c8b46bbb2e698b3e05f49a1f7dcd7d06
af500b2a912c75ae08c96c3cff70339eb8b05365e34b577f7067547236e97abc
2a020364b1f993b542254db0053ff91248b3efa0dd728b1fa73facaa7e646272
e009cb771c52c66f5899151345b11aa2d1cc5e64147ade8059413d09b2ed5c87'
# The second stage ujaild, as the kernel holds it (/proc/<pid>/exe, run from a deleted
# /tmp/ujaild). Unlike the loader it is the same program on many devices: on 30 routers of
# four models it had one of these two hashes (6,815,892 bytes on 23, 6,750,356 bytes on 7).
# Another hash does not clear a process: the name alone is the indicator.
BD_STAGE_SHAS='311b5767e7d63e7dbdc1476c36608b8d7ef729c8bbcc64ded63b9470396351d6
53736d5db721a358bec5b9ddf6056df73b36fc5330300342c42f866a05191432'
# Names that stand in clear text in the loader although its strings are hidden
BD_ULOGD_NAMES='get_mac_form_proc|get_ddns_form_proc|ret_pts_num|domain_table'
# A line that blocks such a name instead of using it: a hosts entry to a null address, or
# dnsmasq's address=/name/ (also to a null address), server=/name/ and local=/name/ with
# nothing behind them, written directly or as a list in /etc/config/dhcp. The summary
# tells people to block these names, so a block must not count as the backdoor (issue 5).
BD_NULL='0\.0\.0\.0|127\.0\.0\.1|::1?'
BD_BLOCK_RE="^[[:space:]]*(($BD_NULL)[[:space:]]|(address|server|local)=/[^[:space:]]*/($BD_NULL|#)?[[:space:]]*\$|list[[:space:]]+(address|server)[[:space:]]+.?/[^[:space:]]*/($BD_NULL|#)?.?[[:space:]]*\$)"
BD_HOST_PATHS="etc/hosts etc/config etc/dnsmasq.conf etc/dnsmasq.d etc/rc.local etc/crontabs etc/init.d etc/hotplug.d"
BD_LOG_PATHS="etc/AdGuardHome/data/querylog.json etc/AdGuardHome/data/querylog.json.1 tmp/AdGuardHome/data/querylog.json"
FULL_UPPER_MAX_KB=65536
TAB=$(printf '\t')

SECRETS=0 MODE=check STDOUT=0 OUTDIR=/tmp ROOT=/ UPPER='' LOWER='' UPPER_SET=0 LOWER_SET=0 COLOR=auto REPORT=ask DEVICE_ID=1 NOTE=''
REPORT_URL=${GL_TRIAGE_REPORT_URL:-https://app.gl-i.net/csa-2026-01-report}

usage() {
	cat <<'EOF'
gl-helper-triage.sh - check, archive and remediate the GL.iNet "gl-helper" implant
(GL.iNet KVMs and GL.iNet / OpenWrt routers)

  --check              read-only detection (default)
  --archive            collect evidence as tar.gz into -o DIR (default /tmp)
  --stdout             with --archive: write the tar.gz to stdout, log to stderr
  --fix                archive (mandatory), kill IOC processes, remove IOC persistence,
                       restore replaced base files from the read-only image
  -o, --out DIR        output directory for the archive
  --color, --no-color  force or disable coloured output (default: only on a terminal)
  --report             send the short anonymous report without asking (it is shown first)
  --no-report          never offer to send a report
  --show-report        print the complete report and send nothing
  --no-device-id       leave the device ID out of the report
  --note TEXT          a note of your own in the report, at most 120 characters of
                       letters, digits, spaces and ._:/+@=,()-
  --with-secrets       keep the private keys and passwords the script would otherwise take
                       out of the archive (/etc/shadow is never included)
  --root/--upper/--lower DIR   override merged root, overlay upper and base image
  -V, --version        print version

Exit: 0 clean, 1 IOC found, 2 fixed, 3 fix incomplete, 4 error
EOF
}

# Colours: empty strings unless switched on, so every message works both ways.
palette() {
	if [ "$1" = 1 ]; then
		ESC=$(printf '\033')
		N="$ESC[0m" B="$ESC[1m" D="$ESC[2m"
		RED="$ESC[1;31m" YEL="$ESC[33m" CYA="$ESC[36m" GRN="$ESC[32m"
		# The one line every reader should see: a green bar, and its address underlined.
		# The bar is green in reverse video, not white on green: the text then takes the
		# terminal's own background colour, which stands out against green in a dark theme
		# and in a light one. White on a theme's pale green could not be read.
		HL="$ESC[1;7;32m" LINK="$ESC[1;4;36m"
	else
		N='' B='' D='' RED='' YEL='' CYA='' GRN='' HL='' LINK=''
	fi
}
palette 0
die() { printf '%sERROR:%s %s\n' "$RED" "$N" "$*" >&2; exit 4; }

while [ $# -gt 0 ]; do
	case $1 in
	--check) MODE=check ;;
	--archive) MODE=archive ;;
	--fix) MODE=fix ;;
	--stdout) STDOUT=1 ;;
	--color) COLOR=1 ;;
	--no-color) COLOR=0 ;;
	--report) REPORT=yes ;;
	--no-report) REPORT=no ;;
	--show-report) REPORT=show ;;
	--no-device-id) DEVICE_ID=0 ;;
	--with-secrets) SECRETS=1 ;;
	-o | --out) [ $# -ge 2 ] || die "$1 needs a directory"; OUTDIR=$2; shift ;;
	--root) [ $# -ge 2 ] || die "$1 needs a directory"; ROOT=$2; shift ;;
	--note) [ $# -ge 2 ] || die "$1 needs a text"; NOTE=$2; shift ;;
	--upper) [ $# -ge 2 ] || die "$1 needs a directory"; UPPER=$2; UPPER_SET=1; shift ;;
	--lower) [ $# -ge 2 ] || die "$1 needs a directory"; LOWER=$2; LOWER_SET=1; shift ;;
	-h | --help) usage; exit 0 ;;
	-V | --version) echo "$VERSION"; exit 0 ;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
	shift
done
[ "$STDOUT" = 1 ] && [ "$MODE" != archive ] && die "--stdout only works together with --archive"

# Log goes to fd 3: stdout normally, stderr when the archive itself goes to stdout.
if [ "$STDOUT" = 1 ]; then exec 3>&2; else exec 3>&1; fi
say() { printf '%s\n' "$*" >&3; }
if [ "$COLOR" = auto ]; then
	COLOR=0
	[ -t 3 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ] && COLOR=1
fi
palette "$COLOR"
# Not called "head": that would hide the command of that name.
section() { say ""; say "${B}== $*${N}"; }
kv() { printf '   %s%-14s%s %s\n' "$D" "$1" "$N" "$2" >&3; }
act() { say "   ${GRN}$*${N}"; }
# Progress while the checks run, so the screen is not empty until the report is ready.
# On a terminal one line is overwritten and removed at the end; otherwise (pipe, ssh
# without a terminal) each step is a line of its own.
STEPS=10
TTY=0
[ -t 3 ] && [ "${TERM:-dumb}" != dumb ] && TTY=1
progress() {
	STEP=$((STEP + 1))
	if [ "$TTY" = 1 ]; then
		printf '\r\033[K   %sChecking %s/%s: %s ...%s' "$D" "$STEP" "$STEPS" "$1" "$N" >&3
	else
		say "   ${D}checking $STEP/$STEPS: $1${N}"
	fi
}
progress_end() { [ "$TTY" = 1 ] && printf '\r\033[K' >&3; return 0; }
# The same while the evidence archive is built: hashing and copying the overlay can take a
# minute on a full device, and the screen stayed empty meanwhile.
working() {
	if [ "$TTY" = 1 ]; then
		printf '\r\033[K   %sArchive: %s ...%s' "$D" "$1" "$N" >&3
	else
		say "   ${D}archive: $1${N}"
	fi
}
umask 077

TMP=${TMPDIR:-/tmp}/.gl-triage.$$
mkdir -m 700 "$TMP" 2>/dev/null || die "cannot create work dir $TMP"
trap 'rm -rf "$TMP"' EXIT
trap 'exit 4' INT TERM HUP

LIVE=0
[ "$ROOT" = / ] && LIVE=1
[ -d "$ROOT" ] || die "root not found: $ROOT"
if [ "$UPPER_SET" = 0 ] && [ "$LIVE" = 1 ]; then
	for d in /userdata/overlay/upper /overlay/upper; do
		[ -d "$d" ] && { UPPER=$d; break; }
	done
fi
if [ "$LOWER_SET" = 0 ] && [ "$LIVE" = 1 ] && [ -d /rom/bin ]; then LOWER=/rom; fi
[ -z "$UPPER" ] || [ -d "$UPPER" ] || die "upper dir not found: $UPPER"
[ -z "$LOWER" ] || [ -d "$LOWER" ] || die "lower dir not found: $LOWER"

r() { if [ "$ROOT" = / ]; then printf '/%s' "$1"; else printf '%s/%s' "${ROOT%/}" "$1"; fi; }
u() { printf '%s/%s' "${UPPER%/}" "$1"; }
l() { printf '%s/%s' "${LOWER%/}" "$1"; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }

# Rules for every check in this script:
#   - It uses only tools that the busybox of GL.iNet's firmware brings. A tool this script
#     does not use yet (hexdump, strings, xxd, ...) is not added for one check; where one
#     may be missing on some model, there is a way without it (see filecmp).
#   - A tool that is missing or fails never stops the script. The check that needed it
#     says that it did not run, as "INFO tool-skipped" does, rather than finding nothing.
#   - A file is read as a stream, never into a shell variable: some devices have 64 MB.
#
# The implant replaced at least /usr/bin/netstat. Use the busybox from the base image
# for every tool this script calls, so a replaced applet cannot lie to us. Nothing may
# tell that busybox to load other libraries than its own.
unset LD_PRELOAD LD_LIBRARY_PATH
TRUSTED=no
OLDPATH=$PATH
if [ -n "$LOWER" ] && [ -x "$(l bin/busybox)" ] && "$(l bin/busybox)" true 2>/dev/null; then
	TBB=$(l bin/busybox)
	mkdir "$TMP/bin"
	for a in $("$TBB" --list 2>/dev/null); do ln -s "$TBB" "$TMP/bin/$a" 2>/dev/null; done
	PATH="$TMP/bin:$PATH"
	export PATH
	TRUSTED="yes ($TBB)"
fi

# Is it safe to open this path and read it to the end? A named pipe blocks until someone
# writes to it, and so do some files below /proc; one of them in a scanned place would
# hang the script, with no report and no archive. So only regular files are read, and a
# link only when it does not lead into /proc, /sys or /dev. Directory scans use
# "find -type f", which does not follow links at all.
safe() {
	[ -f "$1" ] || return 1
	[ -L "$1" ] || return 0
	# the busybox of some KVM firmware has no "readlink -f"; then the link's own target has
	# to do. Without this every linked file there counted as unsafe, /etc/rc.local among them.
	local t
	t=$(readlink -f "$1" 2>/dev/null); [ -n "$t" ] || t=$(readlink "$1" 2>/dev/null)
	case $t in '' | /proc/* | /sys/* | /dev/*) return 1 ;; esac
	return 0
}
rd() { safe "$1" && cat "$1" 2>/dev/null; }

if [ -f "$(r etc/openwrt_release)" ]; then
	PLATFORM=openwrt
elif rd "$(r etc/version)" | grep -q '^RK_MODEL='; then
	PLATFORM="glkvm-$(rd "$(r etc/version)" | sed -n 's/^RK_MODEL=//p' | head -n 1)"
else
	PLATFORM=unknown
fi

if [ "$LIVE" = 1 ]; then
	HOST=$(cat /proc/sys/kernel/hostname 2>/dev/null)
else
	HOST=$(rd "$(r etc/hostname)")
fi
HOST=$(printf '%s' "${HOST:-unknown}" | tr -c 'A-Za-z0-9._-' '_')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WHEN=$(printf '%s' "$STAMP" | sed 's/^\(....\)\(..\)\(..\)T\(..\)\(..\)\(..\)Z$/\1-\2-\3 \4:\5:\6 UTC/')

filecmp() {
	if command -v cmp >/dev/null 2>&1; then cmp -s "$1" "$2"; return; fi
	[ "$(cat "$1" 2>/dev/null | sha256sum)" = "$(cat "$2" 2>/dev/null | sha256sum)" ] && [ -r "$1" ] && [ -r "$2" ]
}

# ---------------------------------------------------------------- findings
# One line per finding: LEVEL<TAB>KIND<TAB>PATH<TAB>DETAIL
#   IOC      known indicator; remediated by --fix
#   PERSIST  persistence file; removed by --fix only when an IOC is present
#   REVIEW   unusual overlay change; archived and reported, never changed
#   INFO     context
# A copy of this script names every indicator it searches for: the malware's paths and
# the older backdoor's servers. Saved on the device, in /etc/config or an autostart
# directory, it matched its own search and the device was called infected (seen in a
# report from a clean router). Such a copy is listed for review instead, so that someone
# still looks at it if it is not theirs. It is known by three lines every version has.
self_copy() {
	safe "$1" || return 1
	grep -q '^# gl-helper-triage\.sh - triage for' "$1" 2>/dev/null &&
		grep -q '^BD_HOST_RE=' "$1" 2>/dev/null && grep -q '^IOC_RE=' "$1" 2>/dev/null
}
add() {
	case "$1 $2" in
	'IOC backdoor-init' | 'IOC backdoor-host' | 'IOC persist-ref' | 'IOC keep-ref' | 'IOC cron-ref')
		case $3 in /*)
			if self_copy "$(r "${3#/}")"; then
				set -- REVIEW script-copy "$3" "a copy of this script: it names the indicators it searches for. Not counted as a trace. If you did not put it here, look at it"
			fi ;;
		esac ;;
	esac
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$FIND"
}

# Package that installed a file: apk (OpenWrt 24.10+), opkg (older OpenWrt / GL 4.x).
pkg_owner() {
	local p db info
	p=${1#/}
	db=$(r lib/apk/db/installed)
	if [ -f "$db" ]; then
		awk -v t="$p" '/^P:/{pk=substr($0,3)} /^F:/{d=substr($0,3)}
			/^R:/{f = (d == "" ? "" : d "/") substr($0,3); if (f == t) {print pk; exit}}' "$db"
		return
	fi
	info=$(r usr/lib/opkg/info)
	[ -d "$info" ] && find "$info" -maxdepth 1 -type f -name '*.list' -exec grep -lxF "/$p" {} + 2>/dev/null | head -n 1 | sed 's#.*/##; s#\.list$##'
}

# A package explains a file only when the base image does not have that file: then it was
# installed later. The base image's own files are all owned by a package too, so for a
# file that differs from the base image the owner says nothing.
pkg_new() {
	[ -n "$LOWER" ] && exists "$(l "${1#/}")" && return 0
	pkg_owner "$1"
}

# Where a file of the overlay lives: the upper layer if we know it, else the merged view.
src() { if [ -n "$UPPER" ]; then u "$1"; else r "$1"; fi; }

# Absolute, normalized target of a symlink: $1 = relative path of the link, $2 = raw target.
# "busybox" and "/bin/busybox" for /bin/login are the same target.
link_target() {
	local t
	case $2 in /*) t=$2 ;; *) t="/${1%/*}/$2" ;; esac
	printf '%s\n' "$t" | awk -F/ '{n=0; for (i=1; i<=NF; i++) { if ($i=="" || $i==".") continue;
		if ($i=="..") { if (n>0) n--; continue } s[++n]=$i }
		o=""; for (i=1; i<=n; i++) o=o "/" s[i]; print (o=="" ? "/" : o)}'
}

# Overlay whiteout (char device 0/0): the file was deleted, e.g. a uci-defaults script
# after first boot or a disabled service link. Not a change we need to look at.
whiteout() { [ -c "$1" ]; }

same_as_lower() {
	[ -n "$LOWER" ] || return 1
	local a b
	a=$(src "$1") b=$(l "$1")
	if [ -L "$a" ]; then
		[ -L "$b" ] && [ "$(link_target "$1" "$(readlink "$a")")" = "$(link_target "$1" "$(readlink "$b")")" ]
		return
	fi
	[ -f "$a" ] && [ -f "$b" ] && [ ! -L "$b" ] && filecmp "$a" "$b"
}

# Is a path in the running system the base image's own file? Without a copy in the overlay
# it is; with one, when that copy does not differ.
base_same() {
	[ -n "$LOWER" ] || return 1
	if [ -n "$UPPER" ] && ! exists "$(u "$1")"; then exists "$(l "$1")"; return; fi
	same_as_lower "$1"
}

# What "trusted" rests on (issue 8). The busybox of the base image is linked dynamically on
# GL.iNet's routers: it loads its loader and libraries from /lib of the running system,
# where the overlay can put other files in their place. So before its tools count as
# trusted, those files have to be the base image's too; and with musl a file
# /etc/ld-musl-ARCH.path names other places to look for libraries, so that one as well.
# The names are read from the busybox itself. A static busybox loads nothing; where the
# names cannot be read, nothing is claimed about the libraries.
: >"$TMP/badlibs"
TRUST_LIBS=unchecked
# The text in a binary file, a piece per line. busybox grep reads a line as a C string and
# does not look behind a NUL byte, and a program or compiled Lua is full of them: a name
# stands behind its length or between NUL bytes (issue 24). So NUL becomes a line end first.
strs() { tr '\000' '\n' <"$1" 2>/dev/null; }
base_libs() {
	local ld n d
	ld=$(strs "$1" | grep -o '/lib/ld-[A-Za-z0-9._-]*' | head -n 1)
	[ -n "$ld" ] || return 1
	echo "${ld#/}"
	case $ld in */ld-musl-*) n=${ld##*/ld-musl-}; echo "etc/ld-musl-${n%%.so*}.path" ;; esac
	strs "$1" | grep -oE 'lib[A-Za-z0-9_+-]+\.so(\.[0-9]+)*' | sort -u | while IFS= read -r n; do
		for d in lib usr/lib; do exists "$(l "$d/$n")" && echo "$d/$n" && break; done
	done
	return 0
}
if [ -n "$LOWER" ] && [ -f "$(l bin/busybox)" ] && [ -r "$(l bin/busybox)" ]; then
	if base_libs "$(l bin/busybox)" >"$TMP/libs" 2>/dev/null; then
		TRUST_LIBS=same
		while IFS= read -r p; do
			exists "$(r "$p")" || continue
			base_same "$p" 2>/dev/null || echo "$p" >>"$TMP/badlibs"
		done <"$TMP/libs"
		[ -s "$TMP/badlibs" ] && TRUST_LIBS=differ
	else
		TRUST_LIBS=none
	fi
fi
case $TRUST_LIBS in
differ)
	# not the base image's libraries: its busybox is no better than the tools in $PATH
	PATH=$OLDPATH; export PATH
	TRUSTED=no ;;
same) [ "$TRUSTED" = no ] || TRUSTED="yes ($TBB, with the base image's own libraries)" ;;
esac

# May a tool that is not a busybox applet be run? iptables-save, nft, logread, curl and
# the like come from \$PATH. The malware replaces netstat to get itself started; a
# replaced one of these would run as root in a plain check. So on a running device such a
# tool is used only when it is the base image's file, and a skipped one is listed.
tool_ok() {
	local p x rel
	p=$(command -v "$1" 2>/dev/null) || return 1
	case $p in "$TMP"/bin/*) return 0 ;; /*) ;; *) return 1 ;; esac
	[ "$LIVE" = 1 ] && [ -n "$LOWER" ] || return 0
	x=$(readlink -f "$p" 2>/dev/null); [ -n "$x" ] || x=$p
	rel=${x#/}
	base_same "$rel" 2>/dev/null && return 0
	if ! grep -qxF "$p" "$TMP/skipped" 2>/dev/null; then
		echo "$p" >>"$TMP/skipped"
		[ -n "${FIND:-}" ] && add INFO tool-skipped "$p" "not run: this is not the base image's $1, and a replaced tool would run as root. What it would have shown is missing from this check"
	fi
	return 1
}

check_markers() {
	local p hit d
	for d in $MARKER_DIRS $MARKER_DIRS_ALT; do
		exists "$(r "$d")" || { [ -n "$UPPER" ] && exists "$(u "$d")"; } || continue
		for p in $MARKER_FILES; do
			p=$d/$p hit=
			[ -n "$UPPER" ] && exists "$(u "$p")" && hit=upper
			exists "$(r "$p")" && hit=${hit:+$hit+}merged
			[ -n "$hit" ] && add IOC marker "/$p" "present ($hit)"
		done
	done
	for d in $MARKER_DIRS $MARKER_DIRS_ALT; do
		if exists "$(src "$d")" && ! grep -q "${TAB}/$d/" "$FIND" && { [ -z "$LOWER" ] || ! exists "$(l "$d")"; }; then
			add REVIEW hidden-dir "/$d" "hidden directory not in base image, no known marker inside"
		fi
	done
}

# The older backdoor (see BD_RE above). Runs before the general overlay checks, which
# skip a path that already has a finding.
check_backdoor() {
	local f p sha owner
	# 1. the changed init script. Any init script from outside a package that names the
	#    backdoor's parts counts, urandom_seed is the one that was reported.
	if [ -d "$(r etc/init.d)" ]; then
		for f in "$(r etc/init.d)"/*; do
			[ -f "$f" ] && [ ! -L "$f" ] || continue
			p=etc/init.d/${f##*/}
			grep -qE "$BD_RE" "$f" 2>/dev/null || continue
			same_as_lower "$p" && continue
			[ -n "$(pkg_new "/$p")" ] && continue
			# only lines the base image's version does not have count
			if [ -n "$LOWER" ] && [ -f "$(l "$p")" ]; then
				grep -vxFf "$(l "$p")" "$f" 2>/dev/null | grep -qE "$BD_RE" || continue
			fi
			sha=
			[ "$(sha256sum "$f" 2>/dev/null | cut -c1-64)" = "$BD_INIT_SHA" ] && sha=", the same file as on other reported devices"
			add IOC backdoor-init "/$p" "older backdoor: starts $(grep -oE "$BD_RE" "$f" | sort -u | tr '\n' ' ' | sed 's/ $//') at boot$sha"
		done
	fi
	# 2. its loader. The real ulogd is a package and lives in /usr/sbin.
	f=$(r bin/ulogd)
	if [ -f "$f" ] && [ ! -L "$f" ] && [ -z "$(pkg_owner /bin/ulogd)" ] && { [ -z "$LOWER" ] || ! exists "$(l bin/ulogd)"; }; then
		sha=$(sha256sum "$f" 2>/dev/null | cut -c1-64)
		# no known hash to compare with: the file differs from device to device
		owner='not from a package'
		[ "$(head -c 4 "$f" 2>/dev/null | tr -d '\033')" = Lua ] && owner='compiled Lua, not from a package'
		strs "$f" | grep -qE "$BD_ULOGD_NAMES" && owner="$owner, holds the function names of the analysed loader"
		[ -n "$sha" ] && printf '%s\n' "$BD_ULOGD_SHAS" | grep -qxF "$sha" && owner="$owner, the same file as on another reported device"
		add IOC backdoor-file /bin/ulogd "older backdoor: its loader, $owner (sha256 ${sha:-unreadable})"
	fi
	# 2a. compiled Lua anywhere in the overlay. The firmware keeps its compiled Lua in the
	#     read-only image, so a file with that header in the overlay is unusual; with the
	#     loader's function names in it, it is the loader under another name.
	if [ -n "$UPPER" ]; then
		find "$UPPER" -xdev -type f -size +1k -size -8192k -exec grep -l 'LuaQ' {} + 2>/dev/null | while IFS= read -r f; do
			[ "$(head -c 4 "$f" 2>/dev/null | tr -d '\033')" = Lua ] || continue
			p=${f#"${UPPER%/}"/}
			grep -q "${TAB}/$p${TAB}" "$FIND" && continue
			[ -n "$(pkg_owner "/$p")" ] && continue
			if strs "$f" | grep -qE "$BD_ULOGD_NAMES"; then
				add IOC backdoor-file "/$p" "older backdoor: its loader under another name (compiled Lua with the loader's function names, sha256 $(sha256sum "$f" 2>/dev/null | cut -c1-64))"
			else
				add REVIEW lua-bytecode "/$p" "compiled Lua in the overlay, not from a package; the older backdoor's loader is such a file"
			fi
		done
	fi
	# 2b. Two owners found /etc/config/wireguard_server written eleven seconds after the
	#     loader was dropped. If that holds on more devices it points to how the backdoor got
	#     in, so the distance in time is noted. Times only, the file is not read.
	f=$(r bin/ulogd)
	if [ -f "$f" ] && [ -f "$(r etc/config/wireguard_server)" ]; then
		p=$(( $(date -u -r "$(r etc/config/wireguard_server)" +%s 2>/dev/null || echo 0) - $(date -u -r "$f" +%s 2>/dev/null || echo 0) ))
		[ "$p" -ge -120 ] && [ "$p" -le 120 ] &&
			add REVIEW backdoor-wg /etc/config/wireguard_server "written $p s after the older backdoor's loader /bin/ulogd; two owners reported the same"
	fi
	# 3. the Lua interpreter under another name
	f=$(r usr/bin/monitord)
	if [ -f "$f" ] && [ ! -L "$f" ] && [ -z "$(pkg_owner /usr/bin/monitord)" ] && [ -f "$(r usr/bin/lua)" ] && filecmp "$f" "$(r usr/bin/lua)"; then
		add IOC backdoor-file /usr/bin/monitord "older backdoor: a copy of /usr/bin/lua under another name"
	fi
	# 4. lists of files a firmware update keeps
	for f in "$(r etc/sysupgrade.conf)" "$(r lib/upgrade/keep.d)"/*; do
		[ -f "$f" ] && [ ! -L "$f" ] || continue
		p=${f#"${ROOT%/}"/}
		grep -qE "$BD_KEEP_RE" "$f" 2>/dev/null || continue
		same_as_lower "$p" && continue
		[ -n "$(pkg_new "/$p")" ] && continue
		if [ -n "$LOWER" ] && [ -f "$(l "$p")" ]; then
			grep -vxFf "$(l "$p")" "$f" 2>/dev/null | grep -qE "$BD_KEEP_RE" || continue
		fi
		add IOC backdoor-keep "/$p" "older backdoor: keeps its files across firmware updates"
	done
	# 5. its servers. In the configuration that is an indicator. In AdGuard Home's query
	#    log it means that some device in this network asked for the name, this one or
	#    another, so that is for a human to judge.
	for p in $BD_HOST_PATHS; do
		exists "$(r "$p")" || continue
		find "$(r "$p")" -xdev -type f -exec grep -lE "$BD_HOST_RE" {} + 2>/dev/null | head -n 5 | while IFS= read -r f; do
			p=${f#"${ROOT%/}"/}
			grep -q "${TAB}/$p${TAB}" "$FIND" && continue
			n=$(grep -oE "[a-z0-9.-]*($BD_HOST_RE)" "$f" | sort -u | head -n 4 | tr '\n' ' ' | sed 's/ $//')
			if grep -E "$BD_HOST_RE" "$f" | grep -qvE "$BD_BLOCK_RE"; then
				add IOC backdoor-host "/$p" "older backdoor: names its server ($n)"
			else
				add INFO backdoor-block "/$p" "blocks a server of the older backdoor ($n): that is the advice, not the backdoor"
			fi
		done
	done
	for p in $BD_LOG_PATHS; do
		f=$(r "$p")
		safe "$f" && grep -qE "$BD_HOST_RE" "$f" 2>/dev/null &&
			add REVIEW backdoor-dns "/$p" "a device in this network asked for a server of the older backdoor ($(grep -oE "$BD_HOST_RE" "$f" | sort -u | head -n 4 | tr '\n' ' ' | sed 's/ $//'))"
	done
	return 0
}

# Relative paths below the applet dirs that the overlay changed.
applet_candidates() {
	local d base
	if [ -n "$UPPER" ]; then base=$UPPER; elif [ -n "$LOWER" ]; then base=${ROOT%/}; else return 0; fi
	for d in $APPLET_DIRS; do
		[ -d "$base/$d" ] || continue
		find "$base/$d" -xdev ! -type d 2>/dev/null | sed "s#^${base%/}/##"
	done
}

# Is this tailscaled the build of the community Tailscale updater (version "...tiny.by.
# admon...")? The file is only read, never run: asking a program from the overlay who it
# is means running it as root, and a fake could answer the same. Two ways to tell
# without that: the uncompressed build carries its version in clear text; the compressed
# one (UPX) does not, so it counts when the updater's own traces are on the device. A
# string in a file can be faked too, which is why a match only makes the finding INFO
# instead of REVIEW: neither is an indicator, and the file stays in the archive.
own_tailscale() { # $1: the directory it lives in, usr/sbin on routers, usr/bin on KVMs
	local f
	f=$(r "$1/tailscaled")
	[ -f "$f" ] && [ ! -L "$f" ] || return 1
	if grep -q 'tiny\.by\.admon' "$f" 2>/dev/null; then
		echo "the community Tailscale updater's build (its version string is in the file)"
		return 0
	fi
	grep -q 'UPX!' "$f" 2>/dev/null || return 1
	if { safe "$(r etc/sysupgrade.conf)" && grep -q "^/$1/tailscaled\$" "$(r etc/sysupgrade.conf)" 2>/dev/null; } ||
		[ -d "$(r root/tailscale_config_backup)" ] ||
		{ safe "$(r usr/bin/gl_tailscale)" && grep -q 'stateful-filtering=false' "$(r usr/bin/gl_tailscale)" 2>/dev/null; }; then
		echo "a compressed build, and the community Tailscale updater's traces are on this device"
		return 0
	fi
	return 1
}

check_applets() {
	local p up lp owner ts
	# the files the base image's busybox loads, where they are not the base image's
	while IFS= read -r p; do
		case $p in
		etc/ld-musl-*.path) add REVIEW changed-lib "/$p" "tells the loader where to look for libraries, and is not the base image's: the busybox of the base image may load other libraries than its own" ;;
		*) add REVIEW changed-lib "/$p" "the busybox of the base image loads this file, and it is not the base image's: the script's own tools cannot be trusted" ;;
		esac
	done <"$TMP/badlibs"
	applet_candidates >"$TMP/cand"
	while IFS= read -r p; do
		up=$(src "$p") lp=
		[ -n "$LOWER" ] && lp=$(l "$p")
		same_as_lower "$p" && continue
		grep -q "${TAB}/$p${TAB}" "$FIND" && continue
		# without an upper layer only files that differ from an existing base file count
		if [ -z "$UPPER" ] && ! exists "$lp"; then continue; fi
		case $p in usr/sbin/tailscale | usr/sbin/tailscaled | usr/bin/tailscale | usr/bin/tailscaled)
			ts=$(own_tailscale "${p%/*}")
			if [ -n "$ts" ] && { [ ! -L "$up" ] || case $(readlink "$up") in tailscaled | "/${p%/*}/tailscaled") true ;; *) false ;; esac; }; then
				add INFO updater-file "/$p" "$ts"
				continue
			fi ;;
		esac
		# A netstat link to busybox that was made since the attack began. The reports show it
		# on KVMs, always made on the evening of 20 November, on some next to the malware's
		# files and on others with nothing else left. So the installer was at work here.
		if [ -L "$up" ] && [ "${p##*/}" = netstat ]; then
			case $(readlink "$up") in /bin/busybox | busybox | ../../bin/busybox)
				owner=$(file_ctime "$up")
				if [ -n "$owner" ] && awk -v a="$owner" -v b="$ATTACK_FROM" 'BEGIN { exit !(a >= b) }'; then
					add IOC installer-trace "/$p" "link to busybox made on $owner, during or after the attack: the malware's installer was at work on this device"
					continue
				fi ;;
			esac
		fi
		if [ -L "$up" ]; then
			if [ -n "$lp" ] && exists "$lp"; then
				add REVIEW symlink "/$p" "-> $(readlink "$up") (base: $(readlink "$lp" 2>/dev/null || echo file))"
			elif [ -n "$UPPER" ] && [ -z "$(pkg_owner "/$p")" ]; then
				# GL.iNet's cleanup deletes /usr/bin/netstat; a link there that the firmware
				# did not put there was reported on a KVM
				add REVIEW new-link "/$p" "-> $(readlink "$up"), not in base image, not owned by a package"
			fi
			continue
		fi
		[ -f "$up" ] || continue
		owner=$(pkg_new "/$p")
		if [ -n "$owner" ]; then
			add INFO package-file "/$p" "installed by package $owner"
		elif [ -n "$lp" ] && [ -L "$lp" ]; then
			# a link to busybox is an applet; replacing that is what the malware does. Other
			# links are replaced by ordinary updates, for example Tailscale's combined binary.
			case $(readlink "$lp") in
			busybox | */busybox)
				if grep -q 'busybox netstat' "$up" 2>/dev/null; then
					add IOC applet-hijack "/$p" "netstat replaced by a script that calls the real one and hides lines from its output"
				else
					add IOC applet-hijack "/$p" "regular file shadows base symlink -> $(readlink "$lp")"
				fi ;;
			*)
				add REVIEW replaced-link "/$p" "regular file where the base image has a link -> $(readlink "$lp"); an update of that program can do this$(case $p in usr/sbin/tailscale*) echo ". If you used the community Tailscale updater, tailscaled --version names it (tiny.by.admon)" ;; esac)" ;;
			esac
		elif [ "${p##*/}" = netstat ]; then
			if grep -q 'busybox netstat' "$up" 2>/dev/null; then
				add IOC applet-hijack "/$p" "netstat replaced by a script that calls the real one and hides lines from its output"
			else
				add IOC applet-hijack "/$p" "netstat replaced by a foreign regular file"
			fi
		elif [ -n "$lp" ] && [ -f "$lp" ]; then
			add REVIEW modified-binary "/$p" "differs from base image"
		else
			add REVIEW new-binary "/$p" "not in base image, not owned by a package"
		fi
	done <"$TMP/cand"
	# Without any base image, at least look at netstat itself.
	if [ -z "$LOWER" ] && [ -z "$UPPER" ]; then
		for p in usr/bin/netstat bin/netstat; do
			[ -f "$(r "$p")" ] && [ ! -L "$(r "$p")" ] && [ -z "$(pkg_owner "/$p")" ] &&
				add REVIEW netstat "/$p" "regular file instead of busybox symlink (no base image to compare)"
		done
	fi
}

check_persist() {
	local p f
	for p in $PERSIST; do
		f=$(src "$p")
		exists "$f" || continue
		same_as_lower "$p" && continue
		if ! safe "$f"; then
			add REVIEW odd-file "/$p" "not a regular file ($(ls -ld "$f" 2>/dev/null | cut -c1-10)), not read"
			continue
		fi
		if grep -qE "$IOC_RE" "$f" 2>/dev/null; then
			add IOC persist-ref "/$p" "references gl-helper paths"
		elif [ "$p" = etc/rc.local ] && ! { if [ -n "$LOWER" ] && [ -f "$(l "$p")" ]; then grep -vxFf "$(l "$p")" "$f"; else cat "$f"; fi 2>/dev/null |
			sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -vE '^(#.*)?$' | grep -qvxF -e 'exit 0' -e '. /lib/functions/gl_util.sh' -e 'remount_ubifs'; }; then
			# GL.iNet's firmware writes these lines into rc.local itself on some models; a
			# file that differs from the base image by nothing else is not a change of yours
			add INFO firmware-lines "/$p" "differs from the base image only by lines the firmware writes itself (gl_util.sh, remount_ubifs)"
		else
			add PERSIST persistence "/$p" "present in overlay ($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null) active lines)$(grep -qE "$KVM_RE" "$f" 2>/dev/null && echo '; names an address or name reported for the malware on a KVM')"
		fi
	done
}

# rc.d symlink to an init script from the base image or a package: normal service enable
known_service_link() {
	local t n
	[ -L "$1" ] || return 1
	t=$(readlink "$1") n=${t##*/}
	case $t in ../init.d/* | /etc/init.d/*) ;; *) return 1 ;; esac
	{ [ -n "$LOWER" ] && exists "$(l "etc/init.d/$n")"; } || [ -n "$(pkg_owner "/etc/init.d/$n")" ]
}

check_review() {
	local p e base
	if [ -n "$UPPER" ]; then base=$UPPER; elif [ -n "$LOWER" ]; then base=${ROOT%/}; else base=; fi
	if [ -n "$base" ]; then
		for p in $REVIEW_PATHS; do
			e="$base/$p"
			exists "$e" || continue
			find "$e" -xdev ! -type d 2>/dev/null | while IFS= read -r f; do
				rel=${f#"${base%/}"/}
				case $rel in
				etc/crontabs/root) continue ;;
				etc/dropbear/dropbear_*_host_key | etc/dropbear/dropbear_*_host_key.pub) continue ;;
				esac
				whiteout "$f" && continue
				same_as_lower "$rel" && continue
				grep -q "${TAB}/$rel${TAB}" "$FIND" && continue
				[ -n "$(pkg_new "/$rel")" ] && continue
				case $rel in etc/rc.d/*) known_service_link "$f" && continue ;; esac
				# any autostart/config file that starts the implant is persistence too
				if [ -f "$f" ] && [ ! -L "$f" ] && grep -qE "$IOC_RE" "$f" 2>/dev/null; then
					case $rel in
					etc/sysupgrade.conf | lib/upgrade/keep.d/*)
						add IOC keep-ref "/$rel" "keeps gl-helper paths across firmware updates" ;;
					*) add IOC persist-ref "/$rel" "references gl-helper paths" ;;
					esac
					continue
				fi
				if [ -f "$f" ] && [ ! -L "$f" ] && grep -qE "$KVM_IP_RE" "$f" 2>/dev/null; then
					add IOC persist-ref "/$rel" "names a server of the malware ($(grep -oE "$KVM_IP_RE" "$f" | sort -u | tr '\n' ' ' | sed 's/ $//'))"
					continue
				fi
				if [ -f "$f" ] && [ ! -L "$f" ] && grep -qE "$KVM_RE" "$f" 2>/dev/null; then
					add REVIEW kvm-ref "/$rel" "names an address or name reported for the malware on a KVM ($(grep -oE "$KVM_RE" "$f" | sort -u | tr '\n' ' ' | sed 's/ $//'))"
					continue
				fi
				if [ -n "$LOWER" ] && exists "$(l "$rel")"; then
					add REVIEW changed "/$rel" "differs from base image"
				elif [ -n "$UPPER" ]; then
					add REVIEW new "/$rel" "not in base image"
				fi
			done
		done
	fi
	# accounts
	rd "$(r etc/passwd)" | awk -F: '$3 == 0 && $1 != "root" {print "name=" $1 " uid=" $3 " shell=" $7 " pw=" ($2 == "" ? "empty" : "set")}' | while IFS= read -r a; do
		add REVIEW uid0-account "/etc/passwd" "second uid 0 account: $a"
	done
	if [ -n "$LOWER" ] && [ -f "$(l etc/passwd)" ] && safe "$(r etc/passwd)"; then
		awk -F: 'NR==FNR {seen[$1]=1; next} !($1 in seen) {print "name=" $1 " uid=" $3 " shell=" $7 " pw=" ($2 == "" ? "empty" : "set")}' \
			"$(l etc/passwd)" "$(r etc/passwd)" 2>/dev/null | while IFS= read -r a; do
			add REVIEW new-account "/etc/passwd" "account not in base image: $a"
		done
	fi
	# other hidden files and dirs in the overlay
	if [ -n "$UPPER" ]; then
		find "$UPPER" -xdev -name '.*' 2>/dev/null | sed "s#^${UPPER%/}/##" | while IFS= read -r rel; do
			case $rel in
			etc/glinet/.cache* | etc/config/.gl* | etc/gl_nas/.cache*) continue ;;
			root/.ash_history | root/.bash_history | root/.ssh | root/.ssh/*) continue ;;
			*/.uci | */.uci/* | etc/.extroot-uuid | .fs_state | etc/luci-uploads/.placeholder) continue ;;
			esac
			add REVIEW hidden "/$rel" "hidden file in overlay"
		done
	fi
}

# Credentials stored on the device. Whoever had a root shell on it could copy them, and
# neither --fix nor a firmware update nor a factory reset takes them back: they stay valid
# at the other end until they are revoked there. They are listed so the owner knows what
# to revoke: root's SSH client keys and what the VPN clients and the WireGuard server of
# GL.iNet firmware keep. Names and counts only, never the content; for an
# SSH key the fingerprint of its public half. This goes to its own file, not to the
# findings, so none of it is in the anonymous report. Other passwords and tokens in the
# configuration are not looked for.
cred() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$TMP/creds"; }

# Number of lines "option <name> <value>" with a value that is not empty. $1 file, $2 name
uci_count() {
	safe "$1" || { echo 0; return; }
	grep -cE "^[[:space:]]*option[[:space:]]+$2[[:space:]]+['\"]?[^'\"[:space:]]" "$1" 2>/dev/null </dev/null
}

check_credentials() {
	local f n dk fp zt
	: >"$TMP/creds"
	# dropbearkey from the read-only image, for the same reason as busybox above
	dk=
	[ -n "$LOWER" ] && [ -x "$(l usr/bin/dropbearkey)" ] && dk=$(l usr/bin/dropbearkey)
	# SSH client keys of root: ~/.ssh/id_dropbear is the name dropbear's help recommends
	# for client keys, the others are the usual OpenSSH names. The file name comes from
	# the device, so only its plain characters are printed.
	for f in "$(r root/.ssh)"/id_*; do
		safe "$f" || continue
		case $f in *.pub) continue ;; esac
		fp=
		[ -n "$dk" ] && fp=$("$dk" -y -f "$f" 2>/dev/null </dev/null | sed -n 's/^Fingerprint: *//p' | head -n 1)
		cred "SSH client key" "$(printf '%s' "${f#"${ROOT%/}"}" | tr -c 'A-Za-z0-9._/@+=,:-' '?')" "${fp:-fingerprint not available}"
	done
	# WireGuard and AmneziaWG on GL.iNet firmware: the client keys are in
	# /etc/config/wireguard (in a profile or once for a group of profiles), the server
	# key is in /etc/config/wireguard_server
	for f in etc/config/wireguard etc/config/wireguard_server; do
		n=$(uci_count "$(r "$f")" private_key)
		[ "${n:-0}" -gt 0 ] || continue
		case $f in
		*/wireguard) cred "WireGuard client" "/$f" "$n private key(s)" ;;
		*) cred "WireGuard server" "/$f" "$n private key(s)" ;;
		esac
	done
	# OpenVPN client on GL.iNet firmware: profiles are .ovpn files below /etc/openvpn/profiles
	f=$(r etc/openvpn/profiles)
	if [ -d "$f" ]; then
		n=$(find "$f" -type f -name '*.ovpn' 2>/dev/null | wc -l | tr -d ' ')
		[ "${n:-0}" -gt 0 ] && cred "OpenVPN client" /etc/openvpn/profiles "$n profile(s)"
	fi
	# ZeroTier: OpenWrt's init script keeps the identity in /etc/config/zerotier and writes
	# identity.secret to a RAM disk at every start; the KVM firmware keeps the file itself.
	# One identity, so one line.
	zt=
	n=$(uci_count "$(r etc/config/zerotier)" secret)
	[ "${n:-0}" -gt 0 ] && zt=etc/config/zerotier
	for f in etc/kvmd/user/zerotier/identity.secret var/lib/zerotier-one/identity.secret; do
		[ -z "$zt" ] && [ -s "$(r "$f")" ] && zt=$f
	done
	[ -n "$zt" ] && cred "ZeroTier" "/$zt" "identity of this node"
	# Tailscale on GL.iNet routers: the state file
	f=etc/tailscale/tailscaled.state
	[ -s "$(r "$f")" ] && cred "Tailscale" "/$f" "state of this node, with its key once it was signed in"
	return 0
}

# When a process started, in UTC, from its start tick in /proc/<pid>/stat and the boot
# time. The reported shells all started at about the same time (21:40 UTC, 2026-11-20).
proc_start() {
	local bt tk
	bt=$(awk '/^btime /{print $2}' /proc/stat 2>/dev/null)
	tk=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}')
	[ -n "$bt" ] && [ -n "$tk" ] || return 0
	date -u -d "@$((bt + tk / 100))" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null
}

# Time a file was last written, in UTC.
file_time() { date -u -r "$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null; }

# Time the kernel last changed a file's entry (ctime), in UTC. Unlike the time above it
# cannot be set back by touch or by unpacking an archive, so the two together show whether
# a file brought its time along. Empty where neither stat nor ls can tell.
file_ctime() {
	local t
	t=$(stat -c %Z "$1" 2>/dev/null)
	case $t in
	'' | *[!0-9]*) ;;
	*) date -u -d "@$t" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null && return 0 ;;
	esac
	TZ=UTC0 ls -lcd --full-time "$1" 2>/dev/null |
		sed -n 's/.* \([0-9]\{4\}-[0-9][0-9]-[0-9][0-9]\) \([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\)[.0-9]* +0000 .*/\1 \2 UTC/p' | head -n 1
}

# A file time as the user reads it. A router without a battery clock has a wrong date until
# it has synced the time; on some routers the older backdoor's files carry times a few
# seconds after 1 January 1970. Before 2020 is not a real date. The report keeps the time.
shown_time() {
	case $1 in
	19[0-9][0-9]-* | 20[01][0-9]-*) printf '%s (clock was not set, not a real date)' "$1" ;;
	*) printf '%s' "$1" ;;
	esac
}

# Time a file was last read (atime), in UTC, and only where the filesystem holding it is
# mounted noatime: there it stays at the time the file was created. Empty everywhere else,
# also when the mount cannot be found in /proc/mounts.
file_atime() {
	local t
	awk -v p="$1" '$2 == "/" || index(p, $2 "/") == 1 { if (length($2) >= l) { l = length($2); o = "," $4 "," } }
		END { exit !(o ~ /,noatime,/) }' /proc/mounts 2>/dev/null || return 0
	t=$(stat -c %X "$1" 2>/dev/null)
	case $t in
	'' | *[!0-9]*) ;;
	*) date -u -d "@$t" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null && return 0 ;;
	esac
	TZ=UTC0 ls -lud --full-time "$1" 2>/dev/null |
		sed -n 's/.* \([0-9]\{4\}-[0-9][0-9]-[0-9][0-9]\) \([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\)[.0-9]* +0000 .*/\1 \2 UTC/p' | head -n 1
}

# Process scan (live system only). Also maps socket inodes to pids for the net output.
check_procs() {
	[ "$LIVE" = 1 ] && [ -r /proc/1/cmdline ] || return 0
	: >"$TMP/procs"
	: >"$TMP/sockets"
	: >"$TMP/exes"
	local d pid exe comm cmd sha known
	for d in /proc/[0-9]*; do
		pid=${d#/proc/}
		[ "$pid" = $$ ] && continue
		# A process can end between the listing and these reads (this script's own helpers
		# do all the time). Read through cat, whose error can be silenced; with "<file" the
		# shell itself reports a missing file. A process that is gone is skipped.
		comm=$(cat "$d/comm" 2>/dev/null)
		[ -n "$comm" ] || continue
		exe=$(readlink "$d/exe" 2>/dev/null)
		cmd=$(cat "$d/cmdline" 2>/dev/null | tr '\0' ' ')
		printf '%s\t%s\t%s\t%s\n' "$pid" "$comm" "$exe" "$cmd" >>"$TMP/procs"
		# shellcheck disable=SC2012 # fd names are numbers
		ls -l "$d/fd" 2>/dev/null | awk -v p="$pid" -v c="$comm" \
			'/socket:\[/ {s=$NF; gsub(/[^0-9]/,"",s); print s "\t" p "\t" c}' >>"$TMP/sockets"
		case "$cmd" in *gl-helper-triage*) continue ;; esac
		if printf '%s\n%s\n%s\n' "$exe" "$cmd" "$comm" | grep -qE "$IOC_RE"; then
			add IOC process "$pid" "comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		case "$comm $exe $cmd" in
		monitord\ * | ujaild\ * | */monitord\ * | */ujaild\ * | *'/ujaild (deleted)'* | *monitord.pid*)
			# the program the kernel runs, up to 64 MiB as for other deleted programs
			sha=
			[ "$(cat "$d/exe" 2>/dev/null | wc -c)" -le 67108864 ] && sha=$(sha256sum "$d/exe" 2>/dev/null | cut -c1-64)
			known=
			[ -n "$sha" ] && printf '%s\n' "$BD_STAGE_SHAS" | grep -qxF "$sha" && known=" known second stage, the same program as on other reported devices (sha256 $sha):"
			add IOC backdoor-proc "$pid" "older backdoor:$known comm=$comm started $(proc_start "$pid") exe=$exe cmd=$cmd"
			continue ;;
		esac
		if printf '%s\n' "$cmd" | grep -qE "$PROC_RE"; then
			add IOC process "$pid" "GL.iNet's quick check (crond -i /tmp/.log, the name gl-helper gives itself): started $(proc_start "$pid") comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$SHELL_RE"; then
			add IOC process "$pid" "remote shell reported by users (GL.iNet staff: treat the router as compromised): started $(proc_start "$pid") comm=$comm cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$KVM_IP_RE"; then
			add IOC process "$pid" "names a server of the malware: started $(proc_start "$pid") comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$KVM_RE"; then
			add REVIEW process "$pid" "names an address or name reported for the malware on a KVM: started $(proc_start "$pid") comm=$comm cmd=$cmd"
		fi
		if printf '%s\n' "$cmd" | grep -qE "$TOOL_RE"; then
			add REVIEW process "$pid" "tool that remote shells use (GL.iNet staff's process check): started $(proc_start "$pid") comm=$comm cmd=$cmd"
		fi
		if [ -n "$exe" ] && grep -q "^IOC${TAB}applet-hijack${TAB}${exe}${TAB}" "$FIND"; then
			add IOC process "$pid" "runs replaced applet: comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		case "$exe" in
		*' (deleted)') add REVIEW deleted-exe "$pid" "running from deleted binary: comm=$comm exe=$exe" ;;
		/*) printf '%s\t%s\n' "$exe" "$pid" >>"$TMP/exes" ;;
		esac
	done
	check_exes
}

# Where does every running program come from? Anything that is not the unchanged file
# from the read-only base image is listed: programs started from a RAM disk (they are in
# neither the base image nor the overlay, so the file checks cannot see them), programs
# that are not in the base image and programs that differ from it. Packages are INFO.
# A script run by a shell from the base image is not caught here; the patterns above are.
check_exes() {
	local exe rel pids owner
	cut -f1 "$TMP/exes" | sort -u | while IFS= read -r exe; do
		pids=$(awk -F '\t' -v e="$exe" '$1==e {printf "%s%s", sep, $2; sep=","}' "$TMP/exes")
		grep -q "^IOC${TAB}applet-hijack${TAB}${exe}${TAB}" "$FIND" && continue
		grep -q "^INFO${TAB}updater-file${TAB}${exe}${TAB}" "$FIND" && continue
		case $exe in
		/tmp/* | /var/* | /run/* | /dev/shm/*)
			add REVIEW running "$exe" "started from a RAM disk, in neither the base image nor the overlay (pid $pids)"
			continue ;;
		esac
		[ -n "$LOWER" ] || continue
		case $exe in "${LOWER%/}"/*) continue ;; esac
		rel=${exe#/}
		if exists "$(l "$rel")"; then
			[ -f "$exe" ] && [ -f "$(l "$rel")" ] && filecmp "$exe" "$(l "$rel")" && continue
			add REVIEW running "$exe" "differs from the base image (pid $pids)"
		else
			owner=$(pkg_owner "$exe")
			if [ -n "$owner" ]; then
				add INFO running "$exe" "not in the base image, installed by package $owner (pid $pids)"
			else
				add REVIEW running "$exe" "not in the base image, not owned by a package (pid $pids)"
			fi
		fi
	done
}

# Files that belong to the process indicators. /tmp is RAM, so these are gone after a
# restart. The pipe /tmp/f stays after the shell was stopped: it shows that the shell ran
# since the last boot, and its time is the last data that went through it.
# /etc/mp_ip_mapping_info is the state file of the cloud handler (SD-WAN IP mapping) that
# the reported command came through; the handler rewrites it each time it runs. It creates
# the file on its first call, so where the overlay is mounted noatime the access time is
# that first call and the time written the last.
# Is AstroWarp (SD-WAN) switched on? "option enable '1'" in the global section of
# /etc/config/mptun, which is what the firmware's own check reads.
astrowarp_on() {
	safe "$(r etc/config/mptun)" || return 1
	awk '/^[[:space:]]*config[[:space:]]/ { g = ($0 ~ /global/) }
		g && /^[[:space:]]*option[[:space:]]+enable[[:space:]]/ { v = $0; gsub(/.*enable[[:space:]]+|[\047"]/, "", v); if (v == "1") f = 1 }
		END { exit !f }' "$(r etc/config/mptun)" 2>/dev/null
}

check_tmp() {
	local f
	exists "$(r tmp/.log)" && add REVIEW tmp-file /tmp/.log "path from GL.iNet's quick check (crond -i /tmp/.log) exists"
	f=$(r tmp/f)
	[ -p "$f" ] && add IOC pipe /tmp/f "named pipe of the reported remote shell: the shell ran since the last boot, last data $(shown_time "$(file_time "$f")")"
	exists "$(r tmp/.dg)" && add REVIEW tmp-file /tmp/.dg "the malware's installer leaves a file of this name after its first report following a restart"
	# the live crontab of GL.iNet's firmware; the installer adds its watchdog there too
	f=$(r tmp/gl_crontabs/root)
	safe "$f" && grep -qE "$IOC_RE" "$f" 2>/dev/null &&
		add IOC cron-ref /tmp/gl_crontabs/root "the running crontab starts the malware: $(grep -E "$IOC_RE" "$f" | head -n 2 | tr '\n' ' ' | cut -c1-160)"
	# The firmware keeps crontab files of its own in /etc/gl_crontabs/crontabs.d, and they
	# survive a restart. GL.iNet's cleanup (router firmware 4.9.3) removes the malware's lines
	# there too, so they are looked for here as well; --fix drops those lines and no others.
	for f in "$(r etc/gl_crontabs/crontabs.d)"/*; do
		safe "$f" && grep -qE "$IOC_RE" "$f" 2>/dev/null &&
			add IOC cron-ref "/etc/gl_crontabs/crontabs.d/${f##*/}" "a crontab file of the firmware starts the malware: $(grep -E "$IOC_RE" "$f" | head -n 2 | tr '\n' ' ' | cut -c1-160)"
	done
	# GL.iNet's fixed router firmware cleans up by itself at its first start
	vendor_cleanup && add INFO vendor-cleanup gl-sdk4-system-check "this firmware removes known traces of the malware at its first start (GL.iNet's cleanup)"
	# the remote terminal service pointed at the attacker's server
	f=$(r etc/rtty_conf)
	safe "$f" && grep -qE "$KVM_IP_RE" "$f" 2>/dev/null &&
		add IOC rtty-server /etc/rtty_conf "the remote terminal service (rtty) is set to a server of the malware ($(grep -oE "$KVM_IP_RE" "$f" | sort -u | tr '\n' ' ' | sed 's/ $//'))"
	# a key the installer can add; it marks its own with this name
	for f in etc/dropbear/authorized_keys root/.ssh/authorized_keys; do
		safe "$(r "$f")" && grep -q 'gl-agent' "$(r "$f")" 2>/dev/null &&
			add IOC ssh-key "/$f" "holds a key named gl-agent, as the malware's installer adds: whoever has the other half can log in"
	done
	f=$(r etc/mp_ip_mapping_info)
	if safe "$f"; then
		local t n aw w a
		t=$(file_time "$f") n=$(cat "$f" 2>/dev/null | wc -c | tr -d ' ')
		aw=off; astrowarp_on && aw=on
		w="written $(shown_time "$t")"
		a=$(file_atime "$f"); [ -n "$a" ] && w="first call $(shown_time "$a"), last call $(shown_time "$t")"
		# Firmware with the fix refuses the attack's command, so a state file written after that
		# firmware first started is not the attack's. One owner found it written at the first
		# start after the upgrade, in the same seconds as the SD-WAN module's other state files
		# (/etc/mp_connection_info, /etc/mphosts; issue 19). "After" is told by the day the
		# firmware was built. A file that tells the first start, /etc/board.json, is no help:
		# it is written before the clock is set and carries a date in 1970 on real devices.
		if [ "$n" = 0 ] && [ "$aw" = off ] && vendor_cleanup && a=$(built_epoch) &&
			[ "$(date -u -r "$f" +%s 2>/dev/null || echo 0)" -ge "$a" ]; then
			add REVIEW state-file /etc/mp_ip_mapping_info "$w, empty: written after this firmware was built. This firmware has the fix and refuses the attack's command; its SD-WAN module can write the file at its own start. Not counted as a trace"
		elif [ "$n" = 0 ] && [ "$aw" = off ] && awk -v a="$t" -v b="$ATTACK_FROM" 'BEGIN { exit !(a >= b) }'; then
			add IOC cloud-command /etc/mp_ip_mapping_info "$w, empty, AstroWarp off: a crafted command from the cloud ran here, as in the reported attack. This trace survives a restart"
		else
			add REVIEW state-file /etc/mp_ip_mapping_info "$w, $n bytes, AstroWarp $aw: the cloud handler for SD-WAN IP mapping ran then. The reported attack came through it; normal if you use AstroWarp"
		fi
	fi
	return 0
}

# Firewall. The running rules are generated from configuration, so no rule "comes from
# the firmware image" as such. What can be compared with the image is that configuration:
# every line of it that the image does not contain is listed. The running rules are
# saved for the archive, and the ones that redirect traffic are shown in the report.
check_firewall() {
	local base p e f rel n
	: >"$TMP/fw-added"
	: >"$TMP/fw-ioc"
	if [ -n "$UPPER" ]; then base=$UPPER; elif [ -n "$LOWER" ]; then base=${ROOT%/}; else base=; fi
	if [ -n "$base" ]; then
		for p in $FW_PATHS; do
			e="$base/$p"
			exists "$e" || continue
			find "$e" -xdev -type f 2>/dev/null | while IFS= read -r f; do
				rel=${f#"${base%/}"/}
				same_as_lower "$rel" && continue
				[ -n "$(pkg_new "/$rel")" ] && continue
				if [ -n "$LOWER" ] && [ -f "$(l "$rel")" ]; then
					grep -vxFf "$(l "$rel")" "$f" 2>/dev/null | grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' >"$TMP/fw-lines"
					n=$(wc -l <"$TMP/fw-lines" | tr -d ' ')
					add REVIEW fw-config "/$rel" "differs from the firmware image: $n lines that are not in it (listed under Firewall)"
				else
					grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' "$f" >"$TMP/fw-lines" 2>/dev/null
					add REVIEW fw-config "/$rel" "not in the firmware image (content listed under Firewall)"
				fi
				{ echo "/$rel"; sed 's/^/    /' "$TMP/fw-lines"; } >>"$TMP/fw-added"
			done
		done
	fi
	[ "$LIVE" = 1 ] || return 0
	: >"$TMP/fw-redirect"
	if tool_ok iptables-save && iptables-save >"$TMP/iptables-save.txt" 2>/dev/null; then
		tool_ok ip6tables-save && ip6tables-save >"$TMP/ip6tables-save.txt" 2>/dev/null
		awk '/^\*/ {t=substr($0,2); next} /^-A / {print t "\t" $0}' "$TMP/iptables-save.txt" >"$TMP/fw-rules"
		awk -F '\t' '$2 ~ /-j (DNAT|REDIRECT)/ || $2 ~ /^-A SDWAN_IP_MAPPING / {print $1 ": " $2}' "$TMP/fw-rules" >>"$TMP/fw-redirect"
		awk -F '\t' -v re="$FW_RULE_RE" '$2 ~ re' "$TMP/fw-rules" >"$TMP/fw-ioc"
		while IFS="$TAB" read -r p f; do
			add IOC fw-rule "$p:SDWAN_IP_MAPPING" "rule left by the command of the reported remote shell: $f"
		done <"$TMP/fw-ioc"
	fi
	if tool_ok nft && nft list ruleset >"$TMP/nft-ruleset.txt" 2>/dev/null; then
		# with iptables-nft the same rules appear in both; show the nft view only without iptables
		[ -s "$TMP/iptables-save.txt" ] || grep -E 'dnat|redirect|SDWAN_IP_MAPPING' "$TMP/nft-ruleset.txt" | sed 's/^[[:space:]]*/nft: /' >>"$TMP/fw-redirect"
		if [ ! -s "$TMP/fw-ioc" ] && grep -qE 'daddr 127\.0\.0\.1 .*dnat to 127\.0\.0\.1' "$TMP/nft-ruleset.txt"; then
			add REVIEW fw-rule "nft" "a rule redirects 127.0.0.1 to 127.0.0.1, like the command of the reported remote shell (see Firewall)"
		fi
	fi
	return 0
}

# Byte order of this machine, from the ELF header of the running shell (byte 5: 1 = little
# endian, 2 = big endian). /proc/net/tcp prints addresses in the machine's byte order, and
# some GL.iNet routers (MIPS) are big endian.
BIG_ENDIAN=0
case $(dd if=/proc/self/exe bs=1 skip=5 count=1 2>/dev/null | tr '\001\002' 'LB') in B) BIG_ENDIAN=1 ;; esac

decode_tcp() {
	# IPv4 and IPv6 connections from /proc/net/tcp and tcp6 with the owning process:
	# established ones, or with $1 = 02 those still waiting for an answer (SYN_SENT). Input: socket owners, then the tcp tables. An IPv6 address that only wraps
	# an IPv4 one (::ffff:a.b.c.d, a dual-stack socket) is shown as IPv4.
	local files=/proc/net/tcp
	[ -r /proc/net/tcp6 ] && files="$files /proc/net/tcp6"
	# shellcheck disable=SC2086 # $files is a list
	awk -v be="$BIG_ENDIAN" -v st="${1:-01}" '
		function h(s,  i,n){n=0; s=toupper(s); for(i=1;i<=length(s);i++) n=n*16+index("0123456789ABCDEF",substr(s,i,1))-1; return n}
		# the four bytes of one 32-bit word in network order
		function word(x){return be ? x : substr(x,7,2) substr(x,5,2) substr(x,3,2) substr(x,1,2)}
		function ip4(w){return h(substr(w,1,2)) "." h(substr(w,3,2)) "." h(substr(w,5,2)) "." h(substr(w,7,2))}
		function ip(x,  i,w,o,g){
			if (length(x) == 8) return ip4(word(x))
			w = ""; for (i = 0; i < 4; i++) w = w word(substr(x, i*8+1, 8))
			w = tolower(w)
			if (substr(w,1,24) == "00000000000000000000ffff") return ip4(substr(w,25,8))
			o = ""; for (i = 0; i < 8; i++) { g = substr(w, i*4+1, 4); sub(/^0+/, "", g); if (g == "") g = "0"; if (i) o = o ":"; o = o g }
			return "[" o "]"
		}
		FNR==1 {nfile++}
		nfile==1 {own[$1]=$2 "/" $3; next}
		FNR>1 && $4==st {split($2,a,":"); split($3,b,":");
			printf "%s:%d -> %s:%d  %s\n", ip(a[1]), h(a[2]), ip(b[1]), h(b[2]), ($10 in own ? own[$10] : "?")}' \
		"$TMP/sockets" $files 2>/dev/null
}

detect() {
	FIND=$1
	: >"$FIND"
	STEP=0
	progress "marker files of the malware"; check_markers
	progress "traces of the older backdoor"; check_backdoor
	progress "replaced system tools"; check_applets
	progress "autostart entries"; check_persist
	progress "running processes"; check_procs
	progress "files in /tmp"; check_tmp
	progress "firewall"; check_firewall
	progress "network connections"
	if [ "$LIVE" = 1 ] && [ -r /proc/net/tcp ]; then
		decode_tcp >"$TMP/conns"
		grep -F -- "-> $SHELL_NET" "$TMP/conns" | while IFS= read -r line; do
			add IOC connection "${SHELL_NET}0/24" "open connection to the network of the reported remote shell ($SHELL_IP): $line"
		done
		# The attacker's server was suspended on 21 November, so a shell loop that still
		# runs gets no answer: its connection is never established, only attempted.
		decode_tcp 02 >"$TMP/conns-syn"
		grep -F -- "-> $SHELL_NET" "$TMP/conns-syn" | while IFS= read -r line; do
			add IOC connection "${SHELL_NET}0/24" "connection attempt, not answered, to the network of the reported remote shell ($SHELL_IP): $line"
		done
		for f in $KVM_NETS; do
			grep -F -- "-> $f:" "$TMP/conns" "$TMP/conns-syn" | sed 's/^[^:]*://' | while IFS= read -r line; do
				add IOC connection "$f" "connection to a server of the malware: $line"
			done
		done
		grep -vF -- "-> $SHELL_NET" "$TMP/conns" | grep -E "$CONN_RE" | while IFS= read -r line; do
			add REVIEW connection "${line##* }" "connection held by a shell or a netcat-like tool: $line"
		done
	fi
	progress "other changes in the overlay"; check_review
	progress "stored keys and VPN profiles"; check_credentials
	progress_end
}

count() { grep -c "^$1${TAB}" "$FIND"; }
# IOC findings of the incident of 2026-11-20 (--fix handles these) and of the older backdoor
count_gl() { awk -F '\t' '$1=="IOC" && $2 !~ /^backdoor-/ && $2 != "cloud-command" && $2 != "rtty-server" && $2 != "installer-trace"' "$FIND" | wc -l | tr -d ' '; }
# Traces that only say "a crafted command from the cloud ran": the rule it leaves in the
# firewall and the handler's empty state file. And everything else of this incident:
# malware files, autostart entries, a remote shell.
count_cmd() { awk -F '\t' '$1=="IOC" && ($2=="cloud-command" || $2=="fw-rule" || $2=="installer-trace")' "$FIND" | wc -l | tr -d ' '; }
count_hard() { awk -F '\t' '$1=="IOC" && $2 !~ /^backdoor-/ && $2 != "cloud-command" && $2 != "fw-rule" && $2 != "installer-trace"' "$FIND" | wc -l | tr -d ' '; }
# Findings that show the malware itself, not only the remote shell: its files, its
# autostart entries, its processes. The shell's process, pipe, connection and the
# firewall rule leave no autostart entry (RemoteToHome, R-7), so --fix leaves rc.local
# and the root crontab alone when those are all there is (issue 5).
count_implant() { awk -F '\t' '$1=="IOC" && $2 !~ /^backdoor-/ && $2 != "cloud-command" && $2 != "rtty-server" && $2 != "installer-trace" && $2 != "fw-rule" && $2 != "pipe" && !(($2=="process" || $2=="connection") && $4 ~ /reported remote shell|^remote shell reported/)' "$FIND" | wc -l | tr -d ' '; }
count_bd() { awk -F '\t' '$1=="IOC" && $2 ~ /^backdoor-/' "$FIND" | wc -l | tr -d ' '; }

# Under a clean verdict on a running device: when it last started. The remote shell, its
# pipe and the firewall rule live in memory only, and a KVM firmware update can remove
# the malware's files, so a device started since the attacks began is clean now, which
# says nothing about before (issue 5; GL.iNet staff say the same of their quick check).
RESTART_FROM='2026-11-19 00:00:00 UTC'
# GL.iNet's fixed router firmware (4.9.3 on) brings the package gl-sdk4-system-check. Its
# script /etc/uci-defaults/00-system-check runs once, at the first start after the update:
# where /etc/config/.gl exists it deletes that directory, the malware's line in rc.local
# and its cron lines, and it always puts /etc/init.d/urandom_seed back. So on such
# firmware the traces this script looks for may be gone, and a clean result says nothing
# about the time before the update. The script is deleted after it ran; the package stays
# in the list of installed packages, and the base image keeps the script.
vendor_cleanup() {
	rd "$(r usr/lib/opkg/status)" | grep -qx 'Package: gl-sdk4-system-check' && return 0
	[ -n "$LOWER" ] && exists "$(l etc/uci-defaults/00-system-check)"
}
# The start of the day this firmware was built, in seconds, from /etc/version.date. Only
# the day is taken: the file does not say which time zone its time is in.
built_epoch() {
	local d s
	d=$(rd "$(r etc/version.date)" | cut -c1-10)
	case $d in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;; *) return 1 ;; esac
	s=$(date -u -d "$d 00:00:00" +%s 2>/dev/null) || return 1
	case $s in '' | *[!0-9]*) return 1 ;; esac
	echo "$s"
}
vendor_cleanup_state() {
	if vendor_cleanup; then echo on; elif safe "$(r usr/lib/opkg/status)"; then echo off; else echo unknown; fi
}

restart_note() {
	local up bt
	[ "$LIVE" = 1 ] || return 0
	up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
	case $up in '' | *[!0-9]*) return 0 ;; esac
	bt=$(date -u -d "@$(($(date +%s) - up))" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)
	[ -n "$bt" ] || return 0
	say "   ${D}Running since $bt.${N}"
	awk -v a="$bt" -v b="$RESTART_FROM" 'BEGIN { exit !(a >= b) }' || return 0
	say "   ${YEL}It was restarted since the attacks began. A remote shell and what it left in memory are${N}"
	say "   ${YEL}gone after a restart, so this result says little about the time before it.${N}"
	case $PLATFORM in glkvm*)
		say "   ${YEL}On a KVM a firmware update can also have removed the malware's files.${N}" ;;
	esac
}

level_color() {
	case $1 in IOC) printf '%s' "$RED" ;; PERSIST) printf '%s' "$YEL" ;; REVIEW) printf '%s' "$CYA" ;; *) printf '%s' "$D" ;; esac
}

# "IOC=3", coloured like its level unless the count is 0
tally() {
	local n
	n=$(count "$1")
	if [ "$n" -gt 0 ]; then printf '%s%s=%s%s' "$(level_color "$1")" "$1" "$n" "$N"; else printf '%s%s=0%s' "$D" "$1" "$N"; fi
}

# The head is printed before the checks start, the body when they are done.
report() { report_head; report_body; result_block; }

# GoodCloud as it is set now, and the version of its client. GL.iNet staff says the main
# question is whether it was connected when the commands went out; this shows only the
# setting at the time of the check.
goodcloud_state() {
	local f st=unknown v
	f=$(r etc/config/gl-cloud)
	if safe "$f"; then
		st=off
		grep -qE "^[[:space:]]*option[[:space:]]+enable[[:space:]]+['\"]?1" "$f" 2>/dev/null && st=on
	else
		f=$(r etc/glinet/gl-cloud.conf)
		if safe "$f"; then
			st=off
			grep -qE '"enable"[[:space:]]*:[[:space:]]*("?1"?|true)' "$f" 2>/dev/null && st=on
		fi
	fi
	v=$(rd "$(r usr/lib/opkg/status)" | awk '/^Package: gl-sdk4-cloud$/ {f=1; next} f && /^Version:/ {print $2; exit} /^$/ {f=0}')
	printf '%s%s' "$st" "${v:+ (gl-sdk4-cloud $v)}"
}

# Is the device bound to a GoodCloud account, and are remote SSH and the remote web
# interface through the cloud switched on? Three answers, on, off or unknown each. People
# ask whether a device that was only bound, with remote access off, was at risk; the
# reports can answer that. Only yes or no is read: never the account's name or address.
cloud_opt() { # file, option: on when the option has a value that is not empty or 0
	safe "$1" || { echo unknown; return; }
	if grep -qE "^[[:space:]]*option[[:space:]]+$2[[:space:]]+['\"]?[^'\"0[:space:]]" "$1" 2>/dev/null; then echo on; else echo off; fi
}
cloud_bound() {
	local f
	f=$(r etc/config/gl-cloud)
	safe "$f" || { echo unknown; return; }
	# the cloud's "bind" command writes these four; "unbind" deletes them
	if grep -qE "^[[:space:]]*option[[:space:]]+(bindtime|username|email|bindtype)[[:space:]]+['\"]?[^'\"[:space:]]" "$f" 2>/dev/null; then echo on; else echo off; fi
}

report_head() {
	say "${B}== gl-helper triage $VERSION${N}  ${D}(CSA-2026-01)${N}"
	kv Host "$HOST"
	kv Platform "$PLATFORM"
	kv Time "$WHEN"
	kv Mode "$MODE"
	kv Root "$ROOT"
	kv Overlay "${UPPER:-unknown}"
	kv "Base image" "${LOWER:-none}"
	kv "Trusted tools" "$TRUSTED"
	# The two remote access options are stored settings, and "on" is what the firmware
	# sets by itself on many versions. They only matter while GoodCloud is on; with it off
	# the admin panel shows them as off, and so does this line (issue 12).
	local gc ssh web
	gc=$(goodcloud_state); ssh=$(cloud_opt "$(r etc/config/rtty)" ssh_en); web=$(cloud_opt "$(r etc/config/rtty)" web_en)
	kv "GoodCloud now" "$gc, bound to an account: $(cloud_bound)"
	case ${gc%% *} in
	off) kv "Remote access" "not in use, GoodCloud is off (stored settings: SSH $ssh, web $web)" ;;
	*) kv "Remote access" "SSH: $ssh, web: $web (through GoodCloud)" ;;
	esac
	if [ "$TRUST_LIBS" = differ ]; then
		say "   ${YEL}WARNING: the busybox of the base image would load files that are not the base image's${N}"
		say "   ${YEL}($(sed 's#^#/#' "$TMP/badlibs" | tr '\n' ' ' | sed 's/ $//')), so tools come from \$PATH and could be tampered${N}"
	elif [ "$TRUSTED" = no ]; then
		say "   ${YEL}WARNING: no usable busybox in a base image, tools come from \$PATH and could be tampered${N}"
	fi
	[ -z "$UPPER" ] && say "   ${YEL}NOTE: overlay upper layer unknown, results are less precise${N}"
	return 0
}

report_body() {
	local n_ioc lvl pat n_conn
	n_ioc=$(count IOC)
	if [ -s "$FIND" ]; then
		section "Findings"
		for lvl in IOC PERSIST REVIEW INFO; do
			[ "$(count "$lvl")" -gt 0 ] || continue
			say ""
			grep "^$lvl${TAB}" "$FIND" | awk -F '\t' -v c="$(level_color "$lvl")" -v n="$N" -v b="$B" -v d="$D" \
				'{printf "   %s%-8s%s %-15s %s%s%s\n   %24s %s%s%s\n", c, $1, n, $2, b, $3, n, "", d, $4, n}' >&3
		done
	fi
	if [ "$LIVE" = 1 ] && [ -r /proc/net/tcp ]; then
		decode_tcp >"$TMP/established"
		section "Network"
		n_conn=$(wc -l <"$TMP/established" | tr -d ' ')
		say "   Established TCP connections, IPv4 and IPv6: $n_conn ${D}(local -> remote, owning process)${N}"
		# aligned columns, connections to the reported shell address in red, at most 40 lines
		head -n 40 "$TMP/established" | awk -v ip="$SHELL_NET" -v red="$RED" -v n="$N" -v d="$D" \
			'{c = (index($3, ip) == 1) ? red : ""; printf "   %s%-21s -> %-21s%s %s%s%s\n", c, $1, $3, (c == "" ? "" : n), d, $4, n}' >&3
		[ "$n_conn" -gt 40 ] && say "   ${D}... $((n_conn - 40)) more in the archive${N}"
		pat=$(awk -F '\t' '$1=="IOC" && $2=="process" {printf "%s  %s/", sep, $3; sep="|"}' "$FIND")
		[ -n "$pat" ] && grep -E "$pat" "$TMP/established" | sed "s/^/   ${RED}IOC process connection:${N} /" >&3
	fi
	if [ -s "$TMP/fw-added" ] || [ -s "$TMP/fw-redirect" ]; then
		section "Firewall"
		if [ -s "$TMP/fw-added" ]; then
			say "   Configuration that is not in the firmware image ${D}(your own port forwards and rules are here too)${N}"
			head -n 60 "$TMP/fw-added" | awk -v b="$B" -v n="$N" '{ if ($0 ~ /^\//) printf "   %s%s%s\n", b, $0, n; else printf "   %s\n", $0 }' >&3
			[ "$(wc -l <"$TMP/fw-added")" -gt 60 ] && say "   ${D}... more in the archive${N}"
		fi
		if [ -s "$TMP/fw-redirect" ]; then
			[ -s "$TMP/fw-added" ] && say ""
			say "   Running rules that redirect traffic: $(wc -l <"$TMP/fw-redirect" | tr -d ' ') ${D}(all rules are in the archive)${N}"
			head -n 40 "$TMP/fw-redirect" | awk -v re="$FW_RULE_RE" -v red="$RED" -v n="$N" \
				'{ r = $0; sub(/^[^:]*: /, "", r); if (r ~ re) printf "   %s%s%s\n", red, $0, n; else printf "   %s\n", $0 }' >&3
			[ "$(wc -l <"$TMP/fw-redirect")" -gt 40 ] && say "   ${D}... more in the archive${N}"
		fi
	fi
	if [ -s "$TMP/creds" ]; then
		section "Credentials on this device"
		say "   Keys and VPN profiles stored here. Whoever had a shell on this device could copy them."
		say "   ${D}Not findings, and not in the anonymous report. Other passwords and tokens are not listed.${N}"
		awk -F '\t' -v b="$B" -v n="$N" -v d="$D" \
			'{printf "   %-16s %s%s%s\n   %16s %s%s%s\n", $1, b, $2, n, "", d, $3, n}' "$TMP/creds" >&3
		[ "$n_ioc" -gt 0 ] && say "   ${YEL}Indicators were found: treat all of these as copied and revoke them where they are trusted.${N}"
	fi
}

# The result: summary, verdict and the address of the page that explains it. Printed after
# the GoodCloud advice, as the last thing before the next steps and the question about the
# report: what a reader looks for should be where the output ends, not above two screens
# of advice.
result_block() {
	section "Result"
	say "   Summary: $(tally IOC) $(tally PERSIST) $(tally REVIEW) $(tally INFO)"
	[ "$(count_hard)" -gt 0 ] && say "   ${RED}IOC${N}      a known trace of the malware or of a remote shell. --fix removes it."
	[ "$(count_cmd)" -gt 0 ] && say "   ${RED}IOC${N}      cloud-command, fw-rule, installer-trace: the attack reached this device."
	[ "$(count_bd)" -gt 0 ] && say "   ${RED}IOC${N}      backdoor-*: a trace of the older backdoor. --fix does NOT remove it, see below."
	[ "$(count PERSIST)" -gt 0 ] && say "   ${YEL}PERSIST${N}  a changed rc.local or root crontab. --fix resets it only when an IOC was found."
	[ "$(count REVIEW)" -gt 0 ] && say "   ${CYA}REVIEW${N}   an unusual change, not proof of an infection. Check whether it is yours. Never modified."
	[ "$(count INFO)" -gt 0 ] && say "   ${D}INFO     context, for example files installed by a package.${N}"
	say ""
	if [ "$(count_hard)" -gt 0 ] && [ "$(count_bd)" -gt 0 ]; then
		say "   ${RED}Verdict: INFECTED - gl-helper indicators and the older backdoor (urandom_seed/ulogd) found${N}"
	elif [ "$(count_bd)" -gt 0 ]; then
		say "   ${RED}Verdict: INFECTED - older backdoor (urandom_seed/ulogd) found${N}"
		say "   ${D}Not the incident of 2026-11-20: no gl-helper indicators found.${N}"
		[ "$(count_cmd)" -gt 0 ] && say "   ${D}A crafted command from the cloud also ran on this device (cloud-command / fw-rule).${N}"
	elif [ "$(count_hard)" -gt 0 ]; then
		say "   ${RED}Verdict: INFECTED - gl-helper indicators found${N}"
	elif [ "$(count_cmd)" -gt 0 ]; then
		if grep -q "^IOC${TAB}installer-trace${TAB}" "$FIND"; then
			say "   ${RED}Verdict: ATTACKED - the malware's installer was at work on this device${N}"
			say "   ${D}Its files are not here now. They may have been removed since, by a firmware update${N}"
			say "   ${D}or by the attacker. Treat the device as one that was infected.${N}"
		else
			say "   ${RED}Verdict: ATTACKED - a command sent through GoodCloud ran on this device${N}"
			say "   ${D}Someone could run commands on this device through GoodCloud, and ran at least one.${N}"
			say "   ${D}Which ones, and what they did, cannot be told from the device, least of all after a${N}"
			say "   ${D}restart. It may have been a first scan with nothing installed yet, or something not${N}"
			say "   ${D}known so far. No malware files and no remote shell were found. The one such command${N}"
			say "   ${D}that was recovered only looked for the malware and reported back; others opened a${N}"
			say "   ${D}remote shell.${N}"
		fi
	else
		say "   ${GRN}${B}Verdict: no gl-helper indicators found${N}"
		restart_note
		if vendor_cleanup; then
			say "   ${YEL}This firmware cleans up by itself: at its first start it deletes the malware's known${N}"
			say "   ${YEL}traces. So this result does not show what was on the device before the update.${N}"
		fi
		say "   ${D}Not proof that nothing happened: several functions of the cloud client took commands,${N}"
		say "   ${D}and a trace is known for one of them only (the state file). Others may leave none.${N}"
	fi
	# directly under the verdict, not at the end: whoever stops the run at the question
	# about the report has seen it by then
	result_link 0
}

# ---------------------------------------------------------------- archive
# People hand these archives to others, so secrets are taken out of the copies made for
# the archive. Only files below $1 (the archive's work directory) are touched, never the
# device, and links are not followed. /etc/shadow always goes. Private keys go unless
# --with-secrets is given. In configuration files only the values of options that hold a
# key or password are replaced, so an added peer or account stays visible. What was left
# out is listed in REDACTED.txt. This is a best effort and the archive says so: files in
# other formats can still hold passwords and hashes. What was left out is listed there; hashes of the originals stay in overlay/upper-sha256.txt.
# option names that END in one of these hold a secret (wpa_passphrase, api_key, ...); a
# public key is none and stays, an added peer is evidence
SECRET_END='key|password|passwd|passphrase|secret|token|psk'
scrub() {
	local E=$1 f rel
	: >"$TMP/redacted"
	[ -d "$E/files" ] || return 0
	find "$E/files" -type f 2>/dev/null | while IFS= read -r f; do
		rel=${f#"$E"/files/}; rel=${rel#*/}
		case $rel in
		etc/shadow | etc/shadow[-.~]* | etc/gshadow*)
			rm -f "$f" && printf 'removed\t/%s\tpassword hashes (see etc/shadow-summary.txt)\n' "$rel" >>"$TMP/redacted"
			continue ;;
		esac
		[ "$SECRETS" = 1 ] && continue
		case $rel in
		*.pub | */authorized_keys | */known_hosts) continue ;;
		root/.ssh/* | etc/dropbear/dropbear_*_host_key | etc/ssh/ssh_host_*_key | \
			etc/openvpn/* | etc/tailscale/* | var/lib/tailscale/* | */identity.secret | \
			etc/wireguard/* | *.pem | *.key | *.p12 | *.pfx | etc/ppp/*-secrets | \
			etc/kvmd/user/*passwd* | etc/kvmd/user/*totp* | etc/kvmd/user/*.secret)
			rm -f "$f" && printf 'removed\t/%s\tprivate key or VPN profile\n' "$rel" >>"$TMP/redacted"
			continue ;;
		esac
		case $rel in
		etc/config/* | etc/kvmd/user/*)
			awk -v e="($SECRET_END)\$" '
				match($0, /^[ \t]*(option|list)[ \t]+/) {
					name = substr($0, RLENGTH + 1); sub(/[ \t].*/, "", name); gsub(/[\047"]/, "", name)
					l = tolower(name)
					if (l ~ e && l !~ /(public_?key|pubkey)$/) { print substr($0, 1, RLENGTH) name " \047REDACTED\047"; ch = 1; next }
				}
				{ print }
				END { exit !ch }' "$f" >"$TMP/scrub" 2>/dev/null &&
				cat "$TMP/scrub" >"$f" && printf 'values replaced\t/%s\tkeys and passwords\n' "$rel" >>"$TMP/redacted" ;;
		esac
	done
	{
		echo "THIS ARCHIVE CAN STILL HOLD PASSWORDS, TOKENS AND PASSWORD HASHES."
		echo "It is a copy of the device's configuration. Treat it as secret: hand it only to"
		echo "someone you would give the device's passwords to, and never post it publicly."
		echo
		if [ "$SECRETS" = 1 ]; then
			echo "Run with --with-secrets: nothing was taken out except /etc/shadow."
		else
			echo "What the script knows about was taken out or replaced, see the list below: /etc/shadow,"
			echo "private keys, VPN profiles, and in /etc/config the values of options whose name ends"
			echo "in key, password, passphrase, secret, token or psk. That is a best effort, not a"
			echo "guarantee. Files in other formats are copied as they are, for example the settings"
			echo "of AdGuard Home, files below /etc/glinet and /etc/kvmd/user, and the shell history."
			echo "--with-secrets keeps everything except /etc/shadow."
		fi
		echo
		sort -u "$TMP/redacted"
	} >"$E/REDACTED.txt"
}

ARCHIVE=
collect() {
	local E list f pid size avail base_shadow
	E=$TMP/evidence
	working "details of the device and the report"
	mkdir -p "$E/meta" "$E/overlay" "$E/files" "$E/proc" "$E/net" "$E/logs" "$E/etc"
	cp "$FIND" "$E/findings.tsv"
	palette 0
	report 3>"$E/report.txt"
	palette "$COLOR"

	{
		echo "tool: gl-helper-triage $VERSION"
		echo "collected: $STAMP"
		echo "host: $HOST"
		echo "platform: $PLATFORM"
		echo "root=$ROOT upper=${UPPER:-none} lower=${LOWER:-none} trusted-busybox=$TRUSTED"
		uname -a 2>/dev/null
		if [ "$LIVE" = 1 ]; then
			echo "uptime: $(cat /proc/uptime 2>/dev/null)"
			echo "gl model: $(cat /proc/gl-hw-info/model 2>/dev/null)"
			id 2>/dev/null
		fi
	} >"$E/meta/info.txt"
	for f in etc/version etc/glversion etc/version.type etc/version.build etc/version.date etc/os-release etc/openwrt_release etc/openwrt_version etc/manifest; do
		[ -f "$(r "$f")" ] && cp "$(r "$f")" "$E/meta/$(echo "$f" | tr / _)"
	done
	if [ "$LIVE" = 1 ]; then
		cp /proc/mounts "$E/meta/mounts.txt" 2>/dev/null
		cp /proc/cmdline "$E/meta/kernel-cmdline.txt" 2>/dev/null
		df -k >"$E/meta/df.txt" 2>/dev/null
	fi

	working "fingerprints of every changed file (this can take a while)"
	# Overlay upper: listing with hashes always, complete copy if small and /tmp has room.
	if [ -n "$UPPER" ]; then
		find "$UPPER" -xdev -exec stat -c '%A %U:%G %s %y %N' {} + >"$E/overlay/upper-listing.txt" 2>/dev/null ||
			find "$UPPER" -xdev -exec ls -lad {} + >"$E/overlay/upper-listing.txt" 2>/dev/null
		find "$UPPER" -xdev -type f -size -51200k -exec sha256sum {} + >"$E/overlay/upper-sha256.txt" 2>/dev/null
		size=$(du -sk "$UPPER" 2>/dev/null | awk '{print $1}')
		avail=$(df -k "$TMP" 2>/dev/null | tail -n 1 | awk '{print $(NF-2)}')
		if [ "${size:-0}" -le "$FULL_UPPER_MAX_KB" ] && [ $((${size:-0} * 3)) -lt "${avail:-0}" ]; then
			mkdir -p "$E/files/upper"
			tar -C "$UPPER" -cf - . 2>/dev/null | tar -C "$E/files/upper" -xf - 2>/dev/null
			echo "complete copy of the upper layer (${size} KiB)" >"$E/overlay/README.txt"
		else
			echo "upper layer is ${size:-?} KiB (free in work dir: ${avail:-?} KiB): only finding paths copied" >"$E/overlay/README.txt"
		fi
	fi
	working "copies of the files that were found"
	# Always copy the finding paths (merged view) and key files.
	list=$TMP/copylist
	awk -F '\t' '$3 ~ /^\// {print substr($3,2)}' "$FIND" >"$list"
	for f in etc/mp_ip_mapping_info etc/rtty_conf tmp/gl_crontabs etc/gl_crontabs $FW_PATHS $MARKER_DIRS $MARKER_DIRS_ALT $PERSIST etc/crontabs root/.ssh etc/dropbear/authorized_keys \
		etc/passwd etc/group etc/sysupgrade.conf lib/upgrade/keep.d; do echo "$f"; done >>"$list"
	mkdir -p "$E/files/merged"
	sort -u "$list" | while IFS= read -r f; do
		exists "$(r "$f")" || continue
		tar -C "${ROOT%/}/" -cf - "./$f" 2>/dev/null | tar -C "$E/files/merged" -xf - 2>/dev/null
	done
	working "processes, network and logs"
	# shadow: whether a hash changed, never the hash itself
	if safe "$(r etc/shadow)" && [ -r "$(r etc/shadow)" ]; then
		base_shadow=/dev/null
		[ -n "$LOWER" ] && [ -r "$(l etc/shadow)" ] && base_shadow=$(l etc/shadow)
		awk -F: 'FILENAME==ARGV[1] {b[$1]=$2; next}
			{st = ($1 in b) ? (b[$1]==$2 ? "same as base" : "CHANGED vs base") : "not in base"
			 printf "%s\t%s\tlastchg=%s\n", $1, ($2 ~ /^[!*]/ || $2=="" ? "locked/empty" : "hash set, " st), $3}' \
			"$base_shadow" "$(r etc/shadow)" >"$E/etc/shadow-summary.txt" 2>/dev/null
	fi

	if [ "$LIVE" = 1 ]; then
		cp "$TMP/procs" "$E/proc/all-processes.tsv" 2>/dev/null
		cp "$TMP/sockets" "$E/net/socket-owners.tsv" 2>/dev/null
		awk -F '\t' '($1=="IOC" || $2=="deleted-exe") && $3 ~ /^[0-9]+$/ {print $3}' "$FIND" | sort -u | while read -r pid; do
			[ -d "/proc/$pid" ] || continue
			mkdir -p "$E/proc/$pid"
			for f in cmdline environ status maps stat; do cat "/proc/$pid/$f" >"$E/proc/$pid/$f" 2>/dev/null; done
			readlink "/proc/$pid/exe" >"$E/proc/$pid/exe.link" 2>/dev/null
			readlink "/proc/$pid/cwd" >"$E/proc/$pid/cwd.link" 2>/dev/null
			ls -l "/proc/$pid/fd" >"$E/proc/$pid/fd.txt" 2>/dev/null
			cat "/proc/$pid/exe" >"$E/proc/$pid/exe.bin" 2>/dev/null
		done
		for f in tcp tcp6 udp udp6 raw raw6 unix route arp; do cat "/proc/net/$f" >"$E/net/$f" 2>/dev/null; done
		decode_tcp >"$E/net/tcp-established.txt"
		for f in iptables-save.txt ip6tables-save.txt nft-ruleset.txt; do
			[ -s "$TMP/$f" ] && cp "$TMP/$f" "$E/net/$f"
		done
		dmesg >"$E/logs/dmesg.txt" 2>/dev/null
		tool_ok logread && logread >"$E/logs/logread.txt" 2>/dev/null
		for f in /var/log/messages /var/log/messages.0 /var/log/messages.1 /userdata/log/messages; do
			[ -f "$f" ] && cp "$f" "$E/logs/$(echo "${f#/}" | tr / _)" 2>/dev/null
		done
	fi

	working "taking passwords and keys out of the copies"
	scrub "$E"
	(cd "$E" && find . -type f -exec sha256sum {} + >"$TMP/manifest") && mv "$TMP/manifest" "$E/MANIFEST.sha256"

	working "packing"
	if [ "$STDOUT" = 1 ]; then
		progress_end
		tar -C "$TMP" -czf - evidence || die "writing archive to stdout failed"
		say "   Evidence archive written to stdout."
		return 0
	fi
	mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"
	ARCHIVE=$OUTDIR/gl-triage-$HOST-$STAMP.tar.gz
	tar -C "$TMP" -czf "$ARCHIVE" evidence || { rm -f "$ARCHIVE"; die "writing $ARCHIVE failed"; }
	tar -tzf "$ARCHIVE" >/dev/null 2>&1 || die "archive verification failed: $ARCHIVE"
	(cd "$OUTDIR" && sha256sum "${ARCHIVE##*/}" >"${ARCHIVE##*/}.sha256")
	progress_end
	section "Evidence archive"
	kv File "${B}$ARCHIVE${N}"
	kv sha256 "$(cut -d ' ' -f1 "$ARCHIVE.sha256")"
	say "   ${YEL}The archive can still hold passwords and tokens (see REDACTED.txt in it). Treat it as${N}"
	say "   ${YEL}secret and never post it publicly.${N}"
	case $OUTDIR in /tmp | /tmp/* | /var/run* | /run* | /var/tmp*)
		say "   ${YEL}/tmp is RAM: copy it off the device before rebooting.${N}" ;;
	esac
}

# ---------------------------------------------------------------- fix
restore_from_lower() {
	local p="$1"
	rm -rf "$(r "$p")" || return 1
	if [ -n "$LOWER" ] && exists "$(l "$p")"; then
		cp -a "$(l "$p")" "$(r "$p")" && act "restored /$p from base image"
	else
		act "removed /$p (not in base image)"
	fi
}

fix() {
	local pid p f failed=0
	if [ "$LIVE" = 1 ] && [ "$(id -u)" != 0 ]; then die "--fix needs root"; fi
	if [ "$(count_gl)" = 0 ]; then
		say ""
		if [ "$(count_bd)" -gt 0 ]; then
			say "   ${YEL}Nothing was changed. --fix does not remove the older backdoor: reflash the firmware.${N}"
		elif [ "$(count_cmd)" -gt 0 ]; then
			say "   Nothing to remove: the state file only shows that the command ran. It was left in place."
		else
			say "   No IOC found, nothing to remediate. REVIEW items were not touched."
		fi
		return 0
	fi
	section "Remediation"
	# 1. processes: freeze all first so they cannot restart each other, then kill
	awk -F '\t' '$1=="IOC" && $2=="process" {print $3}' "$FIND" | sort -u >"$TMP/pids"
	while read -r pid; do kill -STOP "$pid" 2>/dev/null; done <"$TMP/pids"
	while read -r pid; do kill -KILL "$pid" 2>/dev/null && act "killed pid $pid"; done <"$TMP/pids"
	# 2. the implant's own files
	for p in $MARKER_DIRS; do
		exists "$(r "$p")" || continue
		if rm -rf "$(r "$p")"; then act "removed /$p"; else failed=1; fi
	done
	# the other directories only when one of the malware's files was found in them
	for p in $MARKER_DIRS_ALT; do
		exists "$(r "$p")" && grep -q "^IOC${TAB}marker${TAB}/$p/" "$FIND" || continue
		if rm -rf "$(r "$p")"; then act "removed /$p"; else failed=1; fi
	done
	if [ -p "$(r tmp/f)" ] && grep -q "^IOC${TAB}pipe${TAB}" "$FIND"; then
		if rm -f "$(r tmp/f)"; then act "removed the pipe /tmp/f"; else failed=1; fi
	fi
	# 3. persistence, only because the malware itself was found (same set as the vendor
	#    cleanup). With nothing but the remote shell's traces these files stay as they are.
	if [ "$(count_implant)" -gt 0 ]; then
		for p in $PERSIST; do
			exists "$(src "$p")" || continue
			same_as_lower "$p" && continue
			restore_from_lower "$p" || failed=1
			say "     ${D}(previous version: files/merged/$p in the archive)${N}"
		done
	else
		for p in $PERSIST; do
			exists "$(src "$p")" || continue
			same_as_lower "$p" && continue
			say "   left /$p as it is: only traces of the remote shell were found, and the shell is not"
			say "   known to write there. Read the file yourself (files/merged/$p in the archive)."
		done
	fi
	# 4. other files that start the implant (init scripts, hotplug, profile, ...)
	#    and replaced applets: put the base image version back or remove them
	awk -F '\t' '$1=="IOC" && ($2=="persist-ref" || $2=="applet-hijack") {print substr($3,2)}' "$FIND" |
		while IFS= read -r p; do
			case " $PERSIST " in *" $p "*) continue ;; esac
			exists "$(r "$p")" || continue
			restore_from_lower "$p" || echo fail >>"$TMP/fixfail"
			case $p in etc/init.d/*) exists "$(r "$p")" || echo "${p##*/}" >>"$TMP/removed-init" ;; esac
		done
	[ -f "$TMP/fixfail" ] && failed=1
	# 5. OpenWrt: service links to init scripts removed in step 4
	if [ -s "$TMP/removed-init" ] && [ -d "$(r etc/rc.d)" ]; then
		for f in "$(r etc/rc.d)"/*; do
			[ -L "$f" ] || continue
			grep -qxF "$(readlink "$f" | sed 's#.*/##')" "$TMP/removed-init" || continue
			rm -f "$f" && act "removed service link /etc/rc.d/${f##*/}"
		done
	fi
	# 6. sysupgrade keep lists: drop only the lines that keep implant paths
	# 6a. the running crontab and added SSH keys: drop only the malware's lines
	awk -F '\t' '$1=="IOC" && ($2=="cron-ref" || $2=="ssh-key") {print $2 "\t" substr($3,2)}' "$FIND" | while IFS="$TAB" read -r pid p; do
		f=$(r "$p")
		safe "$f" || continue
		if [ "$pid" = ssh-key ]; then grep -v 'gl-agent' "$f" >"$TMP/keep.new"; else grep -vE "$IOC_RE" "$f" >"$TMP/keep.new"; fi
		cat "$TMP/keep.new" >"$f" && act "removed the malware's lines from /$p" || echo fail >>"$TMP/fixfail"
	done
	awk -F '\t' '$1=="IOC" && $2=="keep-ref" {print substr($3,2)}' "$FIND" | while IFS= read -r p; do
		f=$(r "$p")
		safe "$f" || continue
		grep -vE "$IOC_RE" "$f" >"$TMP/keep.new"
		cat "$TMP/keep.new" >"$f" && act "removed gl-helper lines from /$p" || echo fail >>"$TMP/fixfail"
	done
	[ -f "$TMP/fixfail" ] && failed=1
	# 7. the firewall rule that the command of the reported remote shell left behind
	if [ "$LIVE" = 1 ] && [ -s "$TMP/fw-ioc" ]; then
		while IFS="$TAB" read -r p f; do
			# shellcheck disable=SC2086 # the saved rule is a list of iptables arguments
			if ! tool_ok iptables; then
				say "   ${YEL}left the firewall rule ($p): iptables is not the base image's, so it was not run${N}"
				echo fail >>"$TMP/fixfail"
			elif iptables -t "$p" $(printf '%s' "$f" | sed 's/^-A /-D /') 2>/dev/null; then
				act "removed firewall rule ($p): $f"
			else
				echo fail >>"$TMP/fixfail"
			fi
		done <"$TMP/fw-ioc"
	fi
	[ -f "$TMP/fixfail" ] && failed=1
	# 8. make cron forget a removed crontab (KVM: S50crond, OpenWrt: cron)
	if [ "$LIVE" = 1 ]; then
		for s in /etc/init.d/S50crond /etc/init.d/cron; do
			# an init script that is not the firmware's is not run
			[ -x "$s" ] && { [ -z "$LOWER" ] || base_same "${s#/}" 2>/dev/null; } && "$s" restart >/dev/null 2>&1 && act "restarted cron ($s)" && break
		done
		sync
	fi
	return $failed
}

recommend() {
	section "Next steps"
	say "   - Copy the evidence archive off the device and keep it."
	if [ "$(count_cmd)" -gt 0 ] && [ "$(count_hard)" = 0 ]; then
		say "   - A command from the attacker ran here as root. It could read every key and password on"
		say "     the device, so the steps below apply even though nothing was installed."
	fi
	if [ "$(count_bd)" -gt 0 ]; then
		say "   ${B}- The older backdoor: reflash the firmware with \"keep settings\" OFF. Where it added${N}"
		say "   ${B}  itself to the keep list it survives an update that keeps settings. Do not restore a${N}"
		say "   ${B}  backup taken from this device.${N}"
		say "   - Its second stage runs in memory only. Until the reflash, take the device off the"
		say "     internet. Known server names, to block in your network: adguardns.com, adguardns.org,"
		say "     lede-openproject.org, adxinsight.com, openwrt-project.org. Other variants may use others."
		say "   - It may have been there for months: treat every password and key on it as copied."
	fi
	case $PLATFORM in
	openwrt)
		say "   - Update the firmware WITHOUT keeping settings: OpenWrt keeps /etc/config across"
		say "     sysupgrade, and the implant hides in /etc/config/.gl."
		say "   - A factory reset (firstboot / reset button) wipes the whole overlay and is the safe option."
		say "   - Check every client that used this router as gateway or DNS." ;;
	glkvm-*)
		say "   - Install GL.iNet's security firmware. Only RM1PE 1.10.2 removes these IOCs at boot;"
		say "     an update that keeps settings also keeps the password, SSH keys and /etc/kvmd/user."
		say "   - A factory reset is still recommended: this cleanup only removes known IOCs."
		say "   - Check the computer connected to the KVM (unknown software, accounts, autostart)." ;;
	*)
		say "   - Update the firmware and do a factory reset: this cleanup only removes known IOCs." ;;
	esac
	say "   - Change the device password, the GL.iNet cloud account password and SSH keys."
	say "   - Everything this device held a key for is exposed too: remove its VPN profile on the"
	say "     server or with the VPN provider and create a new one, and remove its SSH keys from"
	say "     every machine that trusts them."
	[ -s "$TMP/creds" ] && say "     What was found on this device is listed above under \"Credentials on this device\"."
	return 0
}

# ---------------------------------------------------------------- anonymous report
# A few facts for the community's picture of the incident. Built from the first scan,
# before anything is changed. When indicators were found it also carries what the attacker
# left: the changed lines of autostart files, the firewall rules of the chain the attack
# used, and the command lines of its processes. All of it is shown before it is sent.
# JSON string of free text: printable ASCII only, tabs become spaces, quotes escaped.
jtxt() { printf '"%s"' "$(printf '%s' "$1" | tr '\t' ' ' | tr -cd '\40-\176' | cut -c1-"${2:-300}" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
jlines() { while IFS= read -r line; do printf '%s,' "$(jtxt "$line" "${1:-300}")"; done | sed 's/,$//'; }

jstr() { printf '"%s"' "$(printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._:/+@=,()-' | cut -c1-"${2:-64}")"; }

# Model and firmware of the device, for the report and for the code of the result page.
# On a running device from the system; with --root from the files of that root.
DEV_MODEL='' DEV_FW='' DEV_KNOWN=0
device_info() {
	local f
	[ "$DEV_KNOWN" = 1 ] && return 0
	DEV_KNOWN=1
	if [ "$LIVE" = 1 ]; then
		DEV_MODEL=$(cat /proc/gl-hw-info/model 2>/dev/null)
		[ -n "$DEV_MODEL" ] || DEV_MODEL=$(rd /tmp/sysinfo/model)
	else
		DEV_MODEL=$(rd "$(r tmp/sysinfo/model)")
	fi
	# GL.iNet re-issues builds under the same version number, so the build tells them
	# apart: "4.8.3 release2 build 1024 2026-05-29"
	DEV_FW=$(rd "$(r etc/glversion)")
	if [ -n "$DEV_FW" ]; then
		f=$(rd "$(r etc/version.type)"); [ -n "$f" ] && DEV_FW="$DEV_FW $f"
		f=$(rd "$(r etc/version.build)"); [ -n "$f" ] && DEV_FW="$DEV_FW build $f"
		f=$(rd "$(r etc/version.date)" | cut -c1-10); [ -n "$f" ] && DEV_FW="$DEV_FW $f"
	fi
	# KVM devices keep it in /etc/version: RK_VERSION=V1.10.2 release1
	[ -n "$DEV_FW" ] || DEV_FW=$(rd "$(r etc/version)" | sed -n 's/^RK_VERSION=//p' | head -n 1)
}

build_report() {
	local model fw up quick started ports ptime list files stime sfirst f persist rules cmds kind mac devid n revs sha gc aw ssize mt ct pid
	# Device ID: the hardware address of the first network interface, hashed. The address
	# itself never leaves the device.
	devid=''
	if [ "$DEVICE_ID" = 1 ]; then
		mac=$(cat /sys/class/net/eth0/address 2>/dev/null)
		if [ -z "$mac" ] || [ "$mac" = 00:00:00:00:00:00 ]; then
			mac=$(for f in /sys/class/net/*/address; do case $f in */lo/address) continue ;; esac; cat "$f" 2>/dev/null; done | grep -v '^00:00:00:00:00:00$' | sort | head -n 1)
		fi
		[ -n "$mac" ] && devid=$(printf 'csa-2026-01:%s' "$mac" | tr 'A-F' 'a-f' | sha256sum 2>/dev/null | cut -c1-16)
	fi
	device_info; model=$DEV_MODEL fw=$DEV_FW
	up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
	quick=false
	grep -q "^IOC${TAB}process${TAB}[0-9]*${TAB}GL.iNet's quick check" "$FIND" && quick=true
	started=$(grep "^IOC${TAB}process${TAB}[0-9]*${TAB}remote shell" "$FIND" |
		sed -n 's/.*started \([0-9-]* [0-9:]* UTC\).*/\1/p' | sort | head -n 1)
	ports=$(grep "^IOC${TAB}" "$FIND" | grep -oE '170\.39\.226\.[0-9]+[: ][0-9]+' | sed 's/.*[: ]//' | sort -un | head -n 10 | tr '\n' ',' | sed 's/,$//')
	ptime=$(grep "^IOC${TAB}pipe${TAB}" "$FIND" | sed -n 's/.*last data \([0-9-]* [0-9:]* UTC\).*/\1/p' | head -n 1)
	# kind and what was found: a path or a name. For a process, what sort it is and its
	# binary, never its number or its full command line.
	list=$(awk -F '\t' '$1=="IOC" || $1=="PERSIST" {
			if ($2 == "backdoor-proc") { c = ""; if (match($4, /comm=[^ ]+/)) c = substr($4, RSTART + 5, RLENGTH - 5); print $2 " " c; next }
			if ($2 != "process") { print $2 " " $3; next }
			exe = ""; if (match($4, /exe=[^ ]+/)) exe = " " substr($4, RSTART + 4, RLENGTH - 4)
			if ($4 ~ /^GL.iNet.s quick check/) print "process quick-check"
			else if ($4 ~ /^remote shell/) print "process remote-shell"
			else if ($4 ~ /^runs replaced applet/) print "process replaced-tool" exe
			else print "process implant" exe
		}' "$FIND" | sort -u | head -n 30 |
		while IFS= read -r line; do printf '%s,' "$(jstr "$line" 120)"; done | sed 's/,$//')
	# fingerprints of the implant's own files and of replaced system tools: the hash shows
	# whether everyone has the same variant, the time when it arrived
	files=$(awk -F '\t' '$1=="IOC" && ($2=="marker" || $2=="applet-hijack" || $2=="backdoor-file") {print $3}' "$FIND" | sort -u | head -n 12 |
		while IFS= read -r f; do
			[ -f "$(r "${f#/}")" ] && [ ! -L "$(r "${f#/}")" ] || continue
			printf '{"path": %s, "sha256": %s, "size": %s, "mtime": %s, "ctime": %s},' "$(jstr "$f" 120)" \
				"$(jstr "$(sha256sum "$(r "${f#/}")" 2>/dev/null | cut -c1-64)")" \
				"$(cat "$(r "${f#/}")" 2>/dev/null | wc -c | tr -d ' ')" "$(jstr "$(file_time "$(r "${f#/}")")")" "$(jstr "$(file_ctime "$(r "${f#/}")")")"
		done | sed 's/,$//')
	stime=
	sfirst=
	[ -f "$(r etc/mp_ip_mapping_info)" ] && stime=$(file_time "$(r etc/mp_ip_mapping_info)") && sfirst=$(file_atime "$(r etc/mp_ip_mapping_info)")
	# What the attacker left, only when indicators were found. /etc/rc.local in full (up
	# to 60 lines); other autostart files: the lines that are not in the base image (up to
	# 20 per file); from the lists of files a firmware update keeps only the lines that
	# name the implant, the rest is yours.
	persist='' rules='' cmds=''
	: >"$TMP/rlines"   # the same lines as plain text, to show before asking
	if [ "$(count IOC)" -gt 0 ]; then
		persist=$(awk -F '\t' '$2=="persist-ref" || $2=="keep-ref" || $2=="persistence" || $2=="backdoor-init" || $2=="backdoor-keep" {print $2 "\t" $3}' "$FIND" | sort -u -k2 | head -n 6 |
			while IFS="$TAB" read -r kind f; do
				safe "$(r "${f#/}")" || continue
				n=20
				if [ "$kind" = keep-ref ]; then
					grep -E "$IOC_RE" "$(r "${f#/}")"
				elif [ "$kind" = backdoor-keep ]; then
					grep -E "$BD_KEEP_RE" "$(r "${f#/}")"
				elif [ "$f" = /etc/rc.local ]; then
					# the whole file: what stands around the attacker's line matters too
					n=60; cat "$(r "${f#/}")"
				elif [ -n "$LOWER" ] && [ -f "$(l "${f#/}")" ]; then
					grep -vxFf "$(l "${f#/}")" "$(r "${f#/}")"
				else
					cat "$(r "${f#/}")"
				fi 2>/dev/null | grep -v '^[[:space:]]*$' | head -n "$n" >"$TMP/plines"
				sed "s|^|$f:  |" "$TMP/plines" >>"$TMP/rlines"
				printf '{"path": %s, "lines": [%s]},' "$(jstr "$f" 120)" "$(jlines <"$TMP/plines")"
			done | sed 's/,$//')
		# the chain the reported attack writes to, as it is now
		if [ -s "$TMP/fw-rules" ]; then
			awk -F '\t' '$2 ~ /^-A SDWAN_IP_MAPPING / {print "firewall " $1 ": " $2}' "$TMP/fw-rules" | head -n 10 >"$TMP/rfw"
			cat "$TMP/rfw" >>"$TMP/rlines"
			rules=$(sed 's/^firewall //' "$TMP/rfw" | jlines)
		fi
		cmds=$(grep "^IOC${TAB}process${TAB}" "$FIND" | sed -n 's/.* cmd=//p' | sort -u | head -n 5 | jlines 400)
	fi
	# Since schema 6: what the script listed for review, so that a pattern across devices
	# can be seen before anyone knows it is one (the older backdoor stood there for a day).
	# Kind and path only, never the description: that can hold addresses, command lines
	# and account names. For a file its fingerprint, which shows whether two devices have
	# the same file or only the same path, and its two times (schema 7): when it was written
	# and when the kernel last changed its entry, which cannot be set back. A process is sent as its kind alone, a
	# connection as the program that holds it, a deleted program as its path. An account
	# that the firmware does not have goes with its name, number and shell, and whether its
	# password field is empty: the same odd account on many devices is a pattern, and a
	# forum user found one (glcloud, uid 2, empty password) that nobody can explain yet.
	: >"$TMP/revlines"
	revs=$(awk -F '\t' '$1=="REVIEW" {
			p = $3; pid = ""; x = ""
			if ($2 == "process") p = ""
			else if ($2 == "connection") { sub(/^[0-9]*\//, "", p) }
			else if ($2 == "new-account" || $2 == "uid0-account") { x = $4; sub(/^[^:]*: /, "", x) }
			else if ($2 == "deleted-exe") { pid = $3; p = ""; if (match($4, /exe=.*/)) p = substr($4, RSTART + 4) }
			else if ($2 == "backdoor-wg") { x = $4; sub(/ s after.*/, "s", x); sub(/^written /, "after=", x) }
			else if ($2 == "new-link" || $2 == "symlink") {
				# where the link points, and for a changed link where it pointed in the firmware
				t = $4; sub(/^-> /, "", t); b = ""
				if (match(t, / \(base: [^)]*\)/)) { b = substr(t, RSTART + 8, RLENGTH - 9); t = substr(t, 1, RSTART - 1) }
				sub(/,.*/, "", t); x = "to=" t
				# not "t (b ...)": some busybox versions read a name followed by a bracket as a
				# call to a function and stop with "Call to undefined function"
				if (b != "") x = x " base=" b
			}
			# "-" stands for an empty field: the shell would swallow two tabs in a row
			print $2 "\t" (p == "" ? "-" : p) "\t" (pid == "" ? "-" : pid) "\t" (x == "" ? "-" : x)
		}' "$FIND" | sort -u | head -n 40 |
		while IFS="$TAB" read -r kind f pid x; do
			sha='' mt='' ct=''
			[ "$f" = - ] && f=''; [ "$pid" = - ] && pid=''; [ "$x" = - ] && x=''
			case $f in /*)
				n=$(r "${f#/}")
				if [ -n "$pid" ]; then
					# a program that runs from a deleted file: the kernel still has it
					[ "$(cat "/proc/$pid/exe" 2>/dev/null | wc -c)" -le 67108864 ] && sha=$(sha256sum "/proc/$pid/exe" 2>/dev/null | cut -c1-64)
				elif [ -L "$n" ] || [ -e "$n" ]; then
					# the time the kernel last changed the entry, also for a link or a directory
					ct=$(file_ctime "$n")
					if [ -f "$n" ] && [ ! -L "$n" ]; then
						mt=$(file_time "$n")
						# up to 64 MiB: an added program is often large (Tailscale has about 30 MiB),
						# and those are the ones worth comparing across devices
						# not for the WireGuard configuration: only its times matter, and it holds keys
						[ "$kind" != backdoor-wg ] && [ -n "$(find "$n" -maxdepth 0 -size -65537k 2>/dev/null)" ] && sha=$(sha256sum "$n" 2>/dev/null | cut -c1-64)
					fi
				fi ;;
			esac
			f="$f${x:+ $x}"
			printf '%s  %s\n' "$kind" "$f" >>"$TMP/revlines"
			printf '{"kind": %s, "path": %s, "sha256": %s, "mtime": %s, "ctime": %s},' "$(jstr "$kind" 24)" "$(jstr "$f" 160)" "$(jstr "$sha")" "$(jstr "$mt")" "$(jstr "$ct")"
		done | sed 's/,$//')
	gc=$(goodcloud_state); aw=off; astrowarp_on && aw=on
	ssize=-1; safe "$(r etc/mp_ip_mapping_info)" && ssize=$(cat "$(r etc/mp_ip_mapping_info)" 2>/dev/null | wc -c | tr -d ' ')
	cat >"$TMP/report.json" <<EOF
{
"schema": 10,
"tool": $(jstr "$VERSION" 16),
"platform": $(jstr "$PLATFORM" 48),
"model": $(jstr "${model:-unknown}"),
"firmware": $(jstr "${fw:-unknown}" 48),
"checked_at": $(jstr "$WHEN"),
"uptime_s": ${up:-0},
"ioc": $(count IOC),
"persist": $(count PERSIST),
"review": $(count REVIEW),
"findings": [$list],
"quick_check": $quick,
"shell_started": $(jstr "$started"),
"shell_ports": [$ports],
"pipe_time": $(jstr "$ptime"),
"state_file_time": $(jstr "$stime"),
"files": [$files],
"persistence": [$persist],
"fw_rules": [$rules],
"commands": [$cmds],
"goodcloud": $(jstr "${gc%% *}" 8),
"cloud_client": $(jstr "$(printf '%s' "$gc" | sed -n 's/.*(gl-sdk4-cloud \(.*\))$/\1/p')" 32),
"cloud_bound": $(jstr "$(cloud_bound)" 8),
"rtty_ssh": $(jstr "$(cloud_opt "$(r etc/config/rtty)" ssh_en)" 8),
"rtty_web": $(jstr "$(cloud_opt "$(r etc/config/rtty)" web_en)" 8),
"astrowarp": $(jstr "$aw" 8),
"state_file_size": ${ssize:--1},
"state_file_first": $(jstr "$sfirst"),
"review_items": [$revs],
"note": $(jstr "$NOTE" 120),
"vendor_cleanup": $(jstr "$(vendor_cleanup_state)" 8),
"device_id": $(jstr "$devid")
}
EOF
}

send_report() {
	if tool_ok curl; then
		curl -fsS -m 20 -o /dev/null -H 'Content-Type: application/json' --data-binary "@$TMP/report.json" "$REPORT_URL" 2>/dev/null
	elif tool_ok wget; then
		wget -q -T 20 -O /dev/null --header='Content-Type: application/json' --post-file="$TMP/report.json" "$REPORT_URL" 2>/dev/null ||
			wget -q -T 20 -O /dev/null --header='Content-Type: application/json' --post-data="$(cat "$TMP/report.json")" "$REPORT_URL" 2>/dev/null
	else
		return 1
	fi
}

# Offered at the very end on a live device, with or without indicators: clean devices
# show which models and firmware versions were not hit. The summary says in a
# few lines what the report holds. The lines taken from the user's own files and firewall
# are always shown word for word: they are the only part that can hold a secret of theirs.
offer_report() {
	local answer n ioc extra note nl nr
	[ "$LIVE" = 1 ] && [ "$REPORT" != no ] && [ -s "$TMP/report.json" ] || return 0
	if [ "$REPORT" = show ]; then
		section "Anonymous report (not sent)"
		sed 's/^/   /' "$TMP/report.json" >&3
		return 0
	fi
	ioc=$(sed -n 's/^"ioc": \(.*\),$/\1/p' "$TMP/report.json")
	section "Anonymous report (optional)"
	# yellow, so the offer stands apart from the result above. A few lines only: on a
	# device with a long firewall configuration the full list ran over several screens and
	# pushed the result out of sight. "v" shows all of it: what each part is, the lines
	# from the owner's own files word for word, and the complete report.
	ysay() { say "   ${YEL}$*${N}"; }
	extra=''
	grep -q '^"shell_started": "..*",$' "$TMP/report.json" && extra="$extra, shell start and port"
	n=$(grep -o '"sha256"' "$TMP/report.json" | wc -l | tr -d ' ')
	[ "$n" -gt 0 ] && extra="$extra, fingerprints of $n file(s)"
	grep -q '^"commands": \[\],$' "$TMP/report.json" || extra="$extra, the attacker's commands"
	nl=0; [ -s "$TMP/rlines" ] && nl=$(wc -l <"$TMP/rlines" | tr -d ' ')
	nr=0; [ -s "$TMP/revlines" ] && nr=$(wc -l <"$TMP/revlines" | tr -d ' ')
	if [ "$ioc" = 0 ]; then
		ysay "Nothing known was found. Sending that helps too: it shows which devices were not hit."
		ysay "Sent: model, firmware, time of the check, the cloud settings (on or off) and that no"
		ysay "known traces were found."
	else
		ysay "Help the community see which devices were hit and how."
		ysay "Sent: model, firmware, time of the check, the cloud settings (on or off) and the $ioc"
		ysay "known traces above${extra:+; also ${extra#, }}."
	fi
	[ "$nr" -gt 0 ] && ysay "Also what was listed for review: $nr paths, with fingerprints of the files."
	if [ "$nl" -gt 0 ]; then
		ysay "${B}Also $nl lines of your own autostart files and firewall, word for word.${N}"
		ysay "Look at them with v first: if one holds a password or token of yours, do not send."
	fi
	# the note leaves the device: show it as the report holds it, after jstr's filter
	note=$(sed -n 's/^"note": "\(.*\)",$/\1/p' "$TMP/report.json")
	if [ -n "$note" ]; then
		ysay "And your note, as it will be sent:"
		printf '        %s\n' "$note" >&3
	fi
	ysay "Not sent: host name, IP or MAC addresses, keys, account names."
	# everything, for "v"
	report_details() {
		say ""
		ysay "What the report holds:"
		ysay "- model, firmware, script version, time of the check, time since the last start"
		ysay "- the kinds of the known traces and their paths; for malware files a fingerprint and times"
		grep -q '^"device_id": "..*"$' "$TMP/report.json" && ysay "- a device ID (a hash, not an address), so repeated reports count once"
		ysay "- whether GoodCloud and AstroWarp are on, whether the device is bound to a GoodCloud"
		ysay "  account (yes or no, never the account), whether remote SSH and web access are on"
		ysay "- whether the firmware brings GL.iNet's own cleanup"
		if [ -s "$TMP/rlines" ]; then
			ysay "- these lines from your autostart files (rc.local in full) and firewall:"
			sed 's/^/        /' "$TMP/rlines" >&3
			ysay "  If one of them is a password or token of yours, do not send."
		fi
		if [ -s "$TMP/revlines" ]; then
			ysay "- what was listed for review, as kind and path, with fingerprint and times for files:"
			sed 's/^/        /' "$TMP/revlines" >&3
			ysay "  If a path here says more about you than you want to share, do not send."
		fi
		ysay "Not sent: host name, IP or MAC addresses, keys, the content of any other file."
		say ""
		ysay "The complete report, as it would be sent:"
		sed 's/^/      /' "$TMP/report.json" >&3
	}
	if [ "$REPORT" != yes ]; then
		if [ -t 0 ] && [ -t 3 ]; then
			while :; do
				say ""
				printf '   %sSend it? [y/N, v = show everything that would be sent]%s ' "$B" "$N" >&3
				read -r answer || answer=
				case $answer in
				v | V) report_details ;;
				y | Y | yes | Yes | YES) break ;;
				*) say "   Not sent."; return 0 ;;
				esac
			done
		else
			say ""
			say "   Not sent. To send it, run the script again with --report (--show-report prints all of it)."
			return 0
		fi
	fi
	if send_report; then act "Sent. Thank you."; else say "   ${YEL}Could not send the report (no connection, or no curl or wget). Nothing was sent.${N}"; fi
}

# Said at the end of every run, whatever was found: the attack came in through GoodCloud,
# and by reports of 22 November devices are still being hit. The code that was used is on
# the device and runs whenever the cloud client runs, with AstroWarp on or off.
CLOUD_SAID=0
cloud_advice() {
	local gc
	[ "$CLOUD_SAID" = 1 ] && return 0
	CLOUD_SAID=1
	gc=$(goodcloud_state); gc=${gc%% *}
	section "GoodCloud"
	if [ "$gc" = off ]; then
		say "   ${GRN}GoodCloud is switched off on this device. Leave it off until fixed firmware is installed.${N}"
		say "   ${D}Check again after every firmware upgrade: one owner reports that an upgrade with settings${N}"
		say "   ${D}kept switched it back on.${N}"
		astrowarp_on && say "   ${YEL}AstroWarp is still switched on. It works through GoodCloud; switch it off as well.${N}"
		return 0
	fi
	say "   ${RED}${B}Switch GoodCloud and AstroWarp off now, if you can.${N}"
	if [ "$gc" = on ]; then say "   ${RED}GoodCloud is ON on this device.${N} The attack came in through it, and by reports of"
	else say "   Whether GoodCloud is on could not be read here. The attack came in through it, and by reports of"; fi
	say "   22 November devices are still being hit. Until fixed firmware is installed:"
	case $PLATFORM in
	glkvm-*) say "     switch the cloud service off in the KVM's web interface (a user reports it under More Settings)." ;;
	*)
		# the four commands RemoteToHome ran on a GL-AXT1800; afterwards the client was
		# neither running nor set to start
		say "     ${B}/etc/init.d/gl-cloud stop; uci set 'gl-cloud.@cloud[0].enable=0'; uci commit gl-cloud; /etc/init.d/gl-cloud disable${N}"
		say "     or use the GoodCloud switch in the admin panel." ;;
	esac
	say "   ${D}The device then disappears from GoodCloud and AstroWarp stops working: make sure you can${N}"
	say "   ${D}reach a remote device another way first. This does not clean a device that was already hit.${N}"
	say "   ${D}\"I never used AstroWarp\" and \"remote access was off\" do not help: the code runs regardless.${N}"
	say "   ${D}Check again after every firmware upgrade: one owner reports that an upgrade with settings${N}"
	say "   ${D}kept switched it back on.${N}"
}

# The result as an address, printed under the verdict (and under the verdict after a
# clean-up): https://csa.gl-i.net/#AA006011D. The page behind it explains in plain words,
# in English, German and Chinese, what was found and what to do; the output above is
# written for people who know these devices. Over ssh the address often cannot be
# clicked and has to be typed, so the result is packed into nine characters: capitals or
# not, without I, L, O and U, the ninth a check character against slips of the finger.
# The eight others hold 40 bits:
#    7  this script's version (the number after "2.")
#    2  0 unknown device, 1 router, 2 KVM
#   24  one per kind of finding, in the order of RESULT_KINDS (two are spare)
#    2  GoodCloud: 0 not known, 1 on, 2 off
#    1  restarted since the attacks began
#    2  --fix: 0 not run, 1 done, 2 incomplete
#    2  other changes listed for review: 0 none, 1 some
# Where model and firmware are known, five more characters follow after a dash, so that
# the page can say whether newer firmware exists for this device: AA006011D-K7Q2X.
#    7  the model, as its place in RESULT_MODELS (0: not in the list)
#    2  firmware version, first number minus one
#    5  second number, 5 third number (up to 31 each)
#    1  a test build (beta, rc, snapshot)
# and a check character of their own. The first nine work without them.
# Kinds of findings, never a path; a model and a version, never a serial number. Nothing
# in the code tells this device from another of its kind, or names its owner. The code
# stands after "#", a part of the address a browser does not send. The page holds the
# same tables; the worker's tests compare them, and the tests here read every code back.
RESULT_URL=${GL_TRIAGE_RESULT_URL:-https://csa.gl-i.net/}
RESULT_CODES='marker=mk applet-hijack=ah persist-ref=pr keep-ref=kr cron-ref=cr ssh-key=sk rtty-server=rt pipe=pp fw-rule=fw cloud-command=cc installer-trace=it backdoor-init=bi backdoor-file=bf backdoor-keep=bk backdoor-host=bh backdoor-proc=bp persistence=pe process-quick=pq process-shell=ps process-implant=pi connection-shell=cs connection-malware=cm vendor-cleanup=vc'
RESULT_KINDS='mk ah pr kr cr sk rt pq pi ps pp cs cm fw cc it bi bf bk bh bp pe vc'
# the models as firmware.gl-i.net names them; new ones go at the end, the order never changes
RESULT_MODELS='be10000 be14000 be3600 be9300 e5800 mg1300 mt3000 mt3600be mt5000 mt6000 axt1800 be6500 sft1200 x3000 xe3000 ax1800 mt2500 x2000 a1300 b3000 ar300m ar300m16 ar750 ar750s b1300 e750 mt1300 mt300n-v2 x300b x750 xe300 ap1300 ar150 b2200 mifi mt300a mt300n mv1000 s1300 sf1200 usb150 x1200 n300 vixmini s10 s20ble s20otbr s200 rm1 rm10 rm10rc rm1pe rm1v2 rm4pe rmq1'
result_link() {
	local now k p g n up bt f rv code ext m mi i ver tb
	# what was found before any clean-up: that is what the owner has to know about
	now=$FIND; FIND=$TMP/findings
	k=$(awk -F '\t' -v map="$RESULT_CODES" 'BEGIN { n = split(map, a, " "); for (i = 1; i <= n; i++) { split(a[i], kv, "="); c[kv[1]] = kv[2] } }
		$1 == "IOC" || $1 == "PERSIST" || ($1 == "INFO" && $2 == "vendor-cleanup") {
			x = $2
			if (x == "process") { if ($4 ~ /^GL.iNet.s quick check/) x = "process-quick"; else if ($4 ~ /^remote shell/) x = "process-shell"; else x = "process-implant" }
			if (x == "connection") { if ($4 ~ /reported remote shell/) x = "connection-shell"; else x = "connection-malware" }
			if (!(x in c) || (c[x] in seen)) next
			seen[c[x]] = 1
			out = out " " c[x]
		} END { print out }' "$FIND" 2>/dev/null)
	rv=0; [ "$(count REVIEW)" -gt 0 ] && rv=1
	FIND=$now
	case $PLATFORM in openwrt) p=1 ;; glkvm-*) p=2 ;; *) p=0 ;; esac
	g=$(goodcloud_state); case ${g%% *} in on) g=1 ;; off) g=2 ;; *) g=0 ;; esac
	n=0
	if [ "$LIVE" = 1 ]; then
		up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
		case $up in '' | *[!0-9]*) ;; *)
			bt=$(date -u -d "@$(($(date +%s) - up))" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)
			[ -n "$bt" ] && awk -v a="$bt" -v b="$RESTART_FROM" 'BEGIN { exit !(a >= b) }' && n=1 ;;
		esac
	fi
	f=0; case $1 in 2) f=1 ;; 3) [ "$MODE" = fix ] && f=2 ;; esac
	code=$(awk -v minor="${VERSION#*.}" -v plat="$p" -v have="$k" -v order="$RESULT_KINDS" -v g="$g" -v n="$n" -v f="$f" -v rv="$rv" '
		function bin(x, w,    s, i, d) { s = ""; for (i = 0; i < w; i++) { d = x % 2; s = d s; x = int(x / 2) } return s }
		BEGIN {
			alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
			bits = bin(minor, 7); bits = bits bin(plat, 2)
			m = split(order, o, " "); h = " " have " "
			for (i = 1; i <= 24; i++) { d = 0; if (i <= m && index(h, " " o[i] " ") > 0) d = 1; bits = bits d }
			bits = bits bin(g, 2); bits = bits bin(n, 1); bits = bits bin(f, 2); bits = bits bin(rv, 2)
			sum = 0; out = ""
			for (i = 0; i < 8; i++) {
				v = 0
				for (j = 1; j <= 5; j++) v = v * 2 + substr(bits, i * 5 + j, 1)
				sum = sum + (i + 1) * v
				out = out substr(alpha, v + 1, 1)
			}
			out = out substr(alpha, sum % 31 + 1, 1)
			print out
		}' 2>/dev/null)
	case $code in ?????????) ;; *) return 0 ;; esac
	# model and firmware, where both are known and fit
	ext=
	device_info
	m=$(printf '%s' "$DEV_MODEL" | tr 'A-Z' 'a-z' | sed 's/^gl\.inet *//; s/^gl-//; s/[ (].*$//')
	mi=0; i=0
	for f in $RESULT_MODELS; do i=$((i + 1)); [ "$f" = "$m" ] && mi=$i; done
	ver=$(printf '%s' "$DEV_FW" | sed -n 's/^[^0-9]*\([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\).*/\1 \2 \3/p')
	tb=0; printf '%s' "$DEV_FW" | grep -qiE 'beta|rc[0-9]|snapshot|alpha|test' && tb=1
	if [ "$mi" -gt 0 ] && [ -n "$ver" ]; then
		ext=$(awk -v mi="$mi" -v ver="$ver" -v tb="$tb" -v code="$code" '
			function bin(x, w,    s, i, d) { s = ""; for (i = 0; i < w; i++) { d = x % 2; s = d s; x = int(x / 2) } return s }
			BEGIN {
				alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
				split(ver, v, " ")
				if (v[1] < 1 || v[1] > 4 || v[2] > 31 || v[3] > 31) exit
				bits = bin(mi, 7); bits = bits bin(v[1] - 1, 2); bits = bits bin(v[2], 5); bits = bits bin(v[3], 5); bits = bits bin(tb, 1)
				sum = index(alpha, substr(code, 9, 1)) - 1; out = ""
				for (i = 0; i < 4; i++) {
					x = 0
					for (j = 1; j <= 5; j++) x = x * 2 + substr(bits, i * 5 + j, 1)
					sum = sum + (i + 1) * x
					out = out substr(alpha, x + 1, 1)
				}
				out = out substr(alpha, sum % 31 + 1, 1)
				print out
			}' 2>/dev/null)
		case $ext in ?????) ext="-$ext" ;; *) ext= ;; esac
	fi
	say ""
	# set apart by colour, and by the arrows where there is no colour
	say "   ${HL} >>> This result in plain words, with what to do (English, German, Chinese): ${N}"
	say "   ${B}>>>${N} ${LINK}${RESULT_URL}#$code$ext${N}"
	say "   ${D}Open the address in a browser on any device, or type it; capitals do not matter. The code${N}"
	say "   ${D}stands for this result${ext:+, the model and its firmware version}. Nothing in it tells this device from another of${N}"
	say "   ${D}its kind, and opening the address sends nothing from here.${N}"
}

finish() { cloud_advice; offer_report; exit "$1"; }

# ---------------------------------------------------------------- main
report_head
detect "$TMP/findings"
[ "$LIVE" = 1 ] && build_report
case $MODE in
check)
	report_body
	cloud_advice
	result_block
	[ "$(count IOC)" -gt 0 ] && { recommend; finish 1; }
	finish 0
	;;
archive)
	report_body
	collect
	cloud_advice
	result_block
	[ "$(count IOC)" -gt 0 ] && finish 1
	finish 0
	;;
fix)
	report_body
	collect
	{ [ -n "$ARCHIVE" ] && [ -s "$ARCHIVE" ]; } || die "no verified archive, refusing to change anything"
	if [ "$(count_gl)" = 0 ]; then
		fix
		cloud_advice
		result_block
		{ [ "$(count_bd)" -gt 0 ] || [ "$(count_cmd)" -gt 0 ]; } && { recommend; finish 1; }
		finish 0
	fi
	fix
	FIXRC=$?
	sleep 2
	cloud_advice
	section "Result after remediation"
	detect "$TMP/findings.after"
	if [ "$(count_gl)" -gt 0 ]; then
		grep "^IOC${TAB}" "$FIND" | awk -F '\t' '{printf "   still present: %s %s %s\n", $2, $3, $4}' >&3
		say "   ${RED}Verdict: remediation INCOMPLETE${N}"
		result_link 3
		recommend
		finish 3
	fi
	if [ "$(count_bd)" -gt 0 ]; then
		grep "^IOC${TAB}backdoor-" "$FIND" | awk -F '\t' '{printf "   still present: %s %s %s\n", $2, $3, $4}' >&3
		say "   ${RED}Verdict: gl-helper indicators removed, the older backdoor is STILL THERE${N}"
		result_link 3
		recommend
		finish 3
	fi
	if [ "$FIXRC" != 0 ]; then say "   ${YEL}Verdict: IOCs gone, but some steps reported errors${N}"; result_link 3; recommend; finish 3; fi
	say "   ${GRN}${B}Verdict: no gl-helper indicators left${N}"
	[ "$(count_cmd)" -gt 0 ] && say "   ${D}The state file /etc/mp_ip_mapping_info was left in place: it only shows that the command ran.${N}"
	grep -q "^IOC${TAB}rtty-server${TAB}" "$FIND" && say "   ${YEL}/etc/rtty_conf still names the attacker's server and was not changed. A factory reset or reflash puts it right.${N}"
	result_link 2
	recommend
	finish 2
	;;
esac
