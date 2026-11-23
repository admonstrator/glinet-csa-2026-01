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
# reported, never changed; only the malware's own lines in the firewall's start script,
# which is listed for review too, are taken out. This is a stopgap: a reinstall of the
# firmware without kept settings is still recommended.

VERSION=2.54
# When this version went out, in UTC. Changed together with VERSION. The guide on the
# website reads both lines to show the current version and how long ago it came out.
RELEASED='2026-11-23 18:44 UTC'

# Where the malware lives and what it puts there. The first two directories are the ones
# GL.iNet's cleanup in the KVM firmware knows. The rest comes from the installer itself
# (ni.sh, read by a forum user, topic 73056 post 90): it takes the first directory it can
# write to, keeps a copy of everything in /etc/config/.gl because that survives a firmware
# update, and writes these files. watch.sh runs every three minutes from cron.
MARKER_DIRS="etc/glinet/.cache etc/config/.gl"
MARKER_DIRS_ALT="etc/gl_nas/.cache userdata/.gl overlay/.gl tmp/.gl"
MARKER_FILES="gl-helper gb watch.sh run.sh wake.sh boot.sh rtty_keep.sh eco eco.tmp node .u .wc install.log"
# The malware's programs and its installer as forum users posted them (topic 73056, posts
# 101 and 153): gl-helper (n5), gb for 64-bit (gb3) and for 32-bit ARM (gb7), the
# downloader (l5) and ni.sh. The same on every device of one processor type until the
# operator builds anew, so a match is noted. Another hash clears nothing.
GLH_SHAS='795ccb39fe2fc7f96bfe0bd8e1ffaf718382988a77c94d0260e5d11d95f6a347
29d2c70d36b5713d4e6523514ee49d0198a8e8aff4ca02ca86ac429dee908be3
eab746b6dafc69f829ab23c11bcc80cb6b2f9206f159173e52d3e7c2083b0d7f
53ba45b9ef490a0200323d582630fa4eb2dad07c0e9adeaa50071d68f63267ca
36e04e10b4667e59b0a3a25147b032dc038c5a9971a7df88be80f8882e30dd87'
# gl-helper and its downloader are wrapped in a packer of their own that names itself in
# clear text (post 94). A program with this text is the malware, whatever it is called.
GLH_PACKER='Node hardened executable packer'
PERSIST="etc/rc.local etc/crontabs/root"
APPLET_DIRS="bin sbin usr/bin usr/sbin"
REVIEW_PATHS="etc/init.d etc/rc.d etc/inittab etc/profile etc/profile.d etc/hotplug.d
etc/uci-defaults etc/kvmd/user/scripts etc/crontabs root/.ssh etc/dropbear
etc/sysupgrade.conf lib/upgrade/keep.d etc/udhcpc.user.d"
# etc/udhcpc.user.d: the router runs every script there on each DHCP event, and the keep
# list carries the directory across an update (read by RemoteToHome in two images).
# The name gl-helper counts as a word of its own: not gl-helper-triage.sh (this script, which
# owners also start from cron), not a gl-helper.log of the owner's. Files are matched on
# their active lines only, see active() (review of 2.53).
IOC_RE='(^|[^-[:alnum:]_.])gl-helper([^-[:alnum:]_.]|$)|/\.gl/|/\.cache/gb|/\.cache/(watch|run|wake|boot|rtty_keep)\.sh|gl_nas/\.cache'
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
# The same two addresses, and the name that KVM looked up, on a command line, in a file or
# in /etc/rtty_conf. They are in the installer as well (the servers it fetches the malware
# from, ports 8000 and 8899, and the attacker's own rtty server), so with two sources they
# count as the malware's servers. gl-inet.top is an old name of GL.iNet's that was
# registered anew on 2026-11-16; it is in the malware's helper as a fallback server,
# gl-inet.top:8899 (topic 73056, post 92).
# A name alone is not the malware: an owner who blocks these servers names them too. What
# uses a server decides, see SRV_FETCH_RE and SRV_BLOCK_RE (issue 20).
KVM_IP_RE='65\.20\.71\.131|66\.245\.219\.252|gl-inet\.top'
CONN_RE='/(nc|netcat|socat|sh|ash|bash)$'
SHELL_RE="170\\.39\\.226\\.|/tmp/f([ ;|>]|\$)"
# A second, older backdoor that is not part of GL.iNet's notice of 2026-11-20. Users of
# GL.iNet's forum found it on a GL-AX1800 (4.8.3) and a GL-X2000 (4.7.13), dated back to
# 2025 (topic 73097 by ehidle; posts 26, 63 and 65 of the notice's topic 73056):
# Since then confirmed in that topic on a GL-MT3000 (4.11.0) and a second GL-AX1800,
# with dates from October 2025 to March 2026. RemoteToHome found it on 49 routers it
# manages, installed from September 2025 to May 2026, and took apart all 49 loaders and
# both builds of the second stage (its repository, 23 November 2026).
#   /etc/init.d/urandom_seed  extra lines at the top: copy /usr/bin/lua to
#                             /usr/bin/monitord, run /bin/ulogd with it
#   /bin/ulogd                compiled Lua, reports the device to a server whose name
#                             imitates AdGuard or OpenWrt and fetches a second program
#   ujaild                    that second program, run from a deleted file in /tmp
#   lib/upgrade/keep.d/netifd /bin/ulogd and /etc/init.d/urandom_seed are appended, so a
#                             firmware update carries it over (post 78 of topic 73056)
# Findings of this family have a kind that starts with "backdoor-". --fix leaves them
# alone: the second stage runs in memory only and runs any command, writes any file and
# opens a proxy for its server, so what was done with it cannot be listed, and a
# "cleaned" would promise more than a script can keep. The answer is a reflash.
BD_RE='monitord|/bin/ulogd|ujaild|adguardns|adsanalypro|lede-openproject|adxinsight|openwrt-project'
# Its lines in a list of files a firmware update keeps: whole paths, not /etc/ulogd.conf of
# the real ulogd (review of 2.54)
BD_KEEP_RE='(^|[[:space:]])(/bin/ulogd|/usr/bin/monitord|/etc/init\.d/urandom_seed|/[^[:space:]]*ujaild[^[:space:]]*)/?([[:space:]]|$)'
# Server names decoded from both variants of the loader (ehidle, acs; RemoteToHome in all
# 49 of its copies: cdn.adguardns.com/.org, cdn.lede-openproject.org, cdn.adxinsight.com,
# cdn.openwrt-project.org) and from both builds of the second stage (RemoteToHome:
# up.adguardns.com/.org, and up.adsanalypro.com in the build on 7 of its 49 routers).
# Other variants may use other names: /bin/ulogd differs from device to device.
BD_HOST_RE='adguardns\.(com|org)|adsanalypro\.com|lede-openproject\.org|adxinsight\.com|openwrt-project\.org'
# The changed urandom_seed, the same file on three reported devices (X2000, MT3000, AX1800)
# and on all 49 of RemoteToHome's
BD_INIT_SHA=3265f27feb954744581cdea2373b88ceae9d85b67e90487353fd48902cf4fc19
# /bin/ulogd as posted in topic 73097 (posts 1, 2, 3 and 6). The file differs from device
# to device, so these are no detection rule; a match only says "seen before".
# RemoteToHome found a different hash on each of its 49 routers (each copy holds an id of its
# own), none of them in this list. The list is kept for the samples it came from.
# Added from issues 14, 23 and 24: one more device each, and two posts of topic 73097.
BD_ULOGD_SHAS='c5e87c80f76415f399ce4d1644f5ddc3c8b46bbb2e698b3e05f49a1f7dcd7d06
204b884cdbeba1d07f2fc954c80d7ec32a59df9e3914e0f13ada7e15d0e0bb83
8ff619e1913b64215b4a75ce577a5a76eae6aad07590faf5a38c915af0069d44
aaff75ff9c111620e0ee5bc103e5f8262dbfe0aa42554bd716c5b7a3f3d1d192
c1f79858041d096d7a7dc6837385fdae4670d77dfaa101ea31040d64e96574b4
af500b2a912c75ae08c96c3cff70339eb8b05365e34b577f7067547236e97abc
2a020364b1f993b542254db0053ff91248b3efa0dd728b1fa73facaa7e646272
e009cb771c52c66f5899151345b11aa2d1cc5e64147ade8059413d09b2ed5c87'
# The second stage ujaild, as the kernel holds it (/proc/<pid>/exe, run from a deleted
# /tmp/ujaild). Unlike the loader it is the same program on many devices: on the 49
# routers of five models that RemoteToHome checked it had one of these two hashes
# (6,815,892 bytes on 42, 6,750,356 bytes on 7). Another hash does not clear a process:
# the name alone is the indicator.
BD_STAGE_SHAS='311b5767e7d63e7dbdc1476c36608b8d7ef729c8bbcc64ded63b9470396351d6
53736d5db721a358bec5b9ddf6056df73b36fc5330300342c42f866a05191432'
# Names that stand in clear text in the loader although its strings are hidden
BD_ULOGD_NAMES='get_mac_form_proc|get_ddns_form_proc|ret_pts_num|domain_table'
# A line that blocks such a name instead of using it: a hosts entry to a null address, or
# dnsmasq's address=/name/ (also to a null address), server=/name/ and local=/name/ with
# nothing behind them, written directly or as a list in /etc/config/dhcp, and a set that
# the firewall can block (ipset=/name/, nftset=/name/, a list in an ipset section). The
# summary tells people to block these names, so a block must not count as the backdoor
# (issue 5).
BD_NULL='0\.0\.0\.0|127\.0\.0\.1|::1?'
BD_BLOCK_RE="^[[:space:]]*(($BD_NULL)[[:space:]]|(address|server|local)=/[^[:space:]]*/($BD_NULL|#)?[[:space:]]*\$|list[[:space:]]+(address|server)[[:space:]]+.?/[^[:space:]]*/($BD_NULL|#)?.?[[:space:]]*\$|(ipset|nftset)=/|list[[:space:]]+(ipset|nftset|domain)[[:space:]])"
# What a command does with a server of the malware (KVM_IP_RE), issue 20. It fetches from
# it or talks to it: a download tool, nc and its kin, an SSH or TLS client, rtty, a pipe
# into a shell, or a program from a RAM disk that gets the server as an argument. That is
# the malware or a variant of it, in any file and on any command line. Or it only asks
# whether the server answers (is_probe): an owner who checks that a block holds. Or it
# blocks it: a firewall rule that drops or rejects, a route that leads nowhere, a hosts or
# dnsmasq entry as in BD_BLOCK_RE, and not a command that takes such a block away
# (UNBLOCK_RE), though a script that deletes a rule before it adds it again still blocks.
# That is an owner who keeps the device away from these servers. A command that does both
# counts as fetching.
SH_PIPE_RE='[|][[:space:]]*([^[:space:]|]*/)?(ba|a)?sh([[:space:]]|$)'
SRV_FETCH_RE="(^|[^[:alnum:]_.-])(wget(-[[:alnum:]]+)?|curl|uclient-fetch|tftp|ftpget|ftpput|nc|netcat|ncat|socat|telnet|rtty|ssh|dbclient|scp|sftp|openssl|rsync)([[:space:]]|\$)|$SH_PIPE_RE"
UNBLOCK_RE='(^|[[:space:]])(-D|--delete|-F|--flush|del|delete|flush)([[:space:]]|$)'
RAM_RE='^/(tmp|var|run|dev/shm)/'
# A process that names the shell's address or its pipe is the shell only when it is made of
# what such a shell is made of: a tool that talks to a server (SRV_FETCH_RE: nc, ncat,
# socat, telnet, ...), a pipe made with mkfifo, an interactive shell, or cat reading the
# pipe. The reported process lines all have one of these (sh -c "... mkfifo /tmp/f ...",
# nc 170.39.226.219 <port>, cat /tmp/f). An owner's tcpdump or grep for the address has
# none, and is listed for review instead (issue 7).
SHELL_USE_RE="$SRV_FETCH_RE|$TOOL_RE|(^|[ /])(ba|a)?sh -i|(^|[ /])cat /tmp/f([ ;|>]|\$)"
SRV_BLOCK_RE="$BD_BLOCK_RE|-j[[:space:]]+(DROP|REJECT)|(^|[[:space:]])(drop|reject)([[:space:];]|\$)|(^|[[:space:]])(blackhole|unreachable|prohibit)([[:space:]]|\$)|($BD_NULL)[[:space:]]+gl-inet\\.top"
BD_HOST_PATHS="etc/hosts etc/config etc/dnsmasq.conf etc/dnsmasq.d etc/rc.local etc/crontabs etc/init.d etc/hotplug.d"
BD_LOG_PATHS="etc/AdGuardHome/data/querylog.json etc/AdGuardHome/data/querylog.json.1 tmp/AdGuardHome/data/querylog.json"
FULL_UPPER_MAX_KB=65536
TAB=$(printf '\t')

SECRETS=0 MODE=check STDOUT=0 OUTDIR=/tmp ROOT=/ UPPER='' LOWER='' UPPER_SET=0 LOWER_SET=0 COLOR=auto REPORT=ask DEVICE_ID=1 NOTE='' UNSIGNED=0
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
  --report             send the short anonymous report without asking (a summary is shown)
  --update             replace this script by the current version, after checking its
                       signature. Changes nothing else and checks nothing
  --unsigned           with --update on firmware that has no tool to check the
                       signature: update all the same, without asking
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
archive_failed() { progress_end; printf '%sERROR:%s %s\n' "$RED" "$N" "$*" >&2; ARCHIVE=; }

while [ $# -gt 0 ]; do
	case $1 in
	--check) MODE=check ;;
	--archive) MODE=archive ;;
	--fix) MODE=fix ;;
	--update) MODE=update ;;
	--unsigned) UNSIGNED=1 ;;
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
	'IOC backdoor-init' | 'IOC backdoor-host' | 'IOC persist-ref' | 'IOC keep-ref' | 'IOC cron-ref' | 'REVIEW server-ref' | 'REVIEW path-ref' | 'INFO server-block')
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
# The active text of a script, crontab or command line, one command per line: lines that
# are comments and comments at the end of a line are dropped; a line that ends in \ goes
# on in the next, unless $1 is 1 (a crontab or a keep list, which know no such thing, so
# that a \ there cannot hide the next line); lines are split at ; && || and &, so that a
# name and a tool count together only in the same command. A comment that names the
# malware or its server is the owner's note (review of 2.53).
# Quotes (review of 2.54): a ; & | or # inside a quoted string on one line splits nothing
# and starts no comment, as in wget -qO- "http://.../ni.sh?a=1&b=2" | sh, unless the
# string is a command itself (after sh -c, eval, watch, xargs and the like). Such a line
# is given both ways, read with its quotes and plainly, so that nothing the plain reading
# finds is lost where the quotes are read otherwise than sh reads them. The plain reading
# alone is used for a quote that does not close on its line, for $( or ` inside double
# quotes, for $'...', for the text of a here-document (sh reads no quotes there; a \ at
# the end goes on there too) and for a line of more than 4096 characters, which is also
# given whole. A # right after ; & | ( or ) is cut as a comment and kept in the plain
# reading, since sh may read it as part of a word (\;# or ${x%)#*}). << inside $(( ))
# is a shift and starts no here-document. $2 is 1 for the
# command line of a process: it has no comments.
active_in() {
	awk -v nj="${1:-0}" -v pc="${2:-0}" '
	function out(l) {
		gsub(/[0-9]*>&[0-9-]*/, " ", l); gsub(/&>/, " >", l); gsub(/\|\||&&|;|&/, "\n", l)
		gsub(/\001/, ";", l); gsub(/\002/, "\\&", l); gsub(/\003/, "|", l); gsub(/\004/, "#", l)
		print l
	}
	# the reading of 2.53: a comment from # on, then split
	function plain(l) { if (!pc) sub(/(^|[[:space:]])#.*$/, "", l); out(l) }
	# the line with ; & | # inside a quoted string of data replaced and a comment cut off;
	# sets pr (something was replaced), bail (read plainly) and hd, hdash (a here-document
	# follows, and whether its end may be indented with tabs)
	function scan(l,   i, n, c, o, r, sg, q, code, ar) {
		o = ""; n = length(l); q = ""; pr = 0; bail = 0
		for (i = 1; i <= n; i++) {
			c = substr(l, i, 1)
			if (q == "") {
				if (c == "\\") { o = o substr(l, i, 2); i++; continue }
				# a # right after ; & | ( or ) may be no comment for sh (\;# or ${x%)#*}): plain too
				if (c == "#" && !pc && (i == 1 || substr(l, i - 1, 1) ~ /[[:space:];&|()]/)) { if (i > 1 && substr(l, i - 1, 1) !~ /[[:space:]]/) pr = 1; break }
				if (c == "\047" && substr(l, i - 1, 1) == "$") { bail = 1; return l }
				if (c == "\"" || c == "\047") {
					sg = o; sub(/.*[;&|(]/, "", sg)
					code = (o ~ /(^|[[:space:]])-[A-Za-z]*c[[:space:]]*$/ || sg ~ /(^|[[:space:]\/])(eval|trap|watch|ssh|xargs|su|sudo|timeout|nohup|setsid|env|nice|ionice|flock|chrt|taskset|busybox)[[:space:]]/)
					q = c; o = o c; continue
				}
				# << in $(( )) is a shift, no here-document
				ar = o; if (c == "<" && substr(l, i, 2) == "<<" && substr(l, i, 3) != "<<<" && gsub(/\(\(/, "", ar) <= gsub(/\)\)/, "", ar)) {
					# the word as sh takes it, its quotes removed: <<"E"OF ends at EOF
					r = substr(l, i + 2); hdash = (r ~ /^-/); sub(/^-/, "", r); sub(/^[[:space:]]*/, "", r)
					if (match(r, /^[^[:space:];&|<>()]+/)) { hd = substr(r, 1, RLENGTH); gsub(/["\047\\]/, "", hd) }
				}
				o = o c; continue
			}
			if (c == q) { q = ""; o = o c; continue }
			if (q == "\"" && c == "\\") { o = o substr(l, i, 2); i++; continue }
			if (q == "\"" && (c == "`" || substr(l, i, 2) == "$(")) { bail = 1; return l }
			if (!code && c ~ /[;&|#]/) { c = (c == ";") ? "\001" : (c == "&") ? "\002" : (c == "|") ? "\003" : "\004"; pr = 1 }
			o = o c
		}
		if (q != "") bail = 1
		return o
	}
	# the text of a here-document, up to its end word (after tabs with <<-), plainly
	# (a \ at its end goes on in the next line there too)
	body != "" {
		t = $0; if (bdash) sub(/^\t*/, "", t)
		if (t == body) { if (hb != "") plain(hb); hb = ""; body = ""; next }
		t = hb $0; hb = ""; c = t; if (!pc) sub(/(^|[[:space:]])#.*$/, "", c)
		if (!nj && c ~ /(^|[^\\])(\\\\)*\\$/) { sub(/\\$/, "", t); hb = t " " } else plain(t)
		next
	}
	length($0) > 4096 { if (b != "") { plain(b); b = "" } plain($0); if (/["\047]/) print; next }
	b == "" && !pc && /^[[:space:]]*#/ { next }
	{
		l = b $0; b = ""
		hd = ""; s = scan(l)
		# a \ at the end goes on in the next line, not when it ends a comment
		c = bail ? l : s; if (bail && !pc) sub(/(^|[[:space:]])#.*$/, "", c)
		if (!nj && c ~ /(^|[^\\])(\\\\)*\\$/) { sub(/\\$/, "", l); b = l " "; next }
		if (bail) plain(l)
		else { out(s); if (pr) plain(l) }
		if (hd != "") { body = hd; bdash = hdash }
	}
	END { if (b != "") plain(b); if (hb != "") plain(hb) }'
}
# Files that are read line by line: crontabs and the lists of files a firmware update keeps
linewise() { case $1 in *crontabs/* | *crontabs.d/* | *sysupgrade.conf | */keep.d/*) return 0 ;; esac; return 1; }
active() { if linewise "$1"; then strs "$1" | active_in 1; else strs "$1" | active_in; fi; }
# The programs that the commands on stdin run, one command per line as active_in gives
# them; one program per line. That is a command's first word, and behind sh, ., source,
# nohup, exec, env, timeout, flock, watch and their kin the word that follows; the command
# of sh -c and of procd's "command"; the script that sh -s reads with <; what
# start-stop-daemon starts; a cron line's command behind its time fields; what $( ) or
# ` ` runs, and not its arguments; ./name after cd. A command that is piped into a shell
# runs everything it names. A path that only stands as an argument, as with rm, grep,
# pgrep, pidof, kill, [ -e ] or command -v, is not run (review of 2.53). Words are taken
# as they stand: a program in a variable is not known.
ran() {
	awk 'function unq(s) { gsub(/["\047`]/, "", s); sub(/^[({!]+/, "", s); sub(/[)};]+$/, "", s); return s }
	function base(s) { sub(/.*\//, "", s); return s }
	{
		i = 1
		if ($1 ~ /^@[a-z]+$/) i = 2
		else if (NF > 5 && ($1 $2 $3) ~ /^[0-9*\/,-]+$/ && ($4 $5) ~ /^[0-9A-Za-z*\/,-]+$/) i = 6
		if ($0 ~ /[|][[:space:]]*([^[:space:]|]*\/)?(ba|a)?sh([[:space:]]|$)/) { for (; i <= NF; i++) print unq($i); next }
		pre = 0; sh = 0; skip = 0; arg = 0
		for (; i <= NF; i++) {
			r = $i
			# the words of a $( ) or ` ` that is still open: its arguments
			if (skip) { if (r ~ /[)`]/) skip = 0; continue }
			if (r ~ /\$\(|`/) {
				s = r; sub(/^[^`$]*(\$\(|`)/, "", s); print unq(s)
				if (s !~ /[)`]/) skip = 1
				continue
			}
			if (arg) { arg = 0; continue }
			if (r ~ /^[0-9]*>/) { if (r ~ /^[0-9]*>>?$/) i++; continue }
			if (r ~ /^[0-9]*</) { s = r; sub(/^[0-9]*</, "", s); if (s == "") s = $(++i); if (sh) { print unq(s); next } continue }
			if (r ~ /^[A-Za-z_][A-Za-z0-9_]*\(\)/) { r = substr(r, index(r, "()") + 2); if (r == "" || r == "{") continue }
			if (r ~ /\)$/ && r !~ /\(/ && i < NF) continue
			if (r ~ /^command=/) { print unq(substr(r, 9)); continue }
			w = unq(r)
			if (w == "" || w ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue
			if (w == "case") { while (i < NF && $i != "in") i++; continue }
			if (w == "cd") { cwd = unq($(i + 1)); next }
			if (w == "procd_set_param") { if ($(i + 1) != "command") next; i++; pre = 1; continue }
			# command -v and -V only look a name up, they start nothing
			if (base(w) == "command" && $(i + 1) ~ /^-[A-Za-z]*[vV]/) next
			if (w ~ /^(do|then|else|elif|if|while|until|time|eval|\.|source)$/ || base(w) ~ /^(nohup|exec|setsid|command|builtin|env|nice|ionice|timeout|watch|chrt|taskset)$/) { pre = 1; sh = 0; continue }
			if (base(w) == "flock") { pre = 1; sh = 0; arg = 1; continue }
			if (pre && w ~ /^-/) {
				# sh -c: what follows is a command, not a script
				if (sh && w ~ /^-[A-Za-z]*c[A-Za-z]*$/) { sh = 0; continue }
				if (sh && w ~ /^-[A-Za-z]*s/) {
					for (i++; i <= NF; i++) if ($i ~ /^[0-9]*</) { s = $i; sub(/^[0-9]*</, "", s); if (s == "") s = $(i + 1); print unq(s); break }
					next
				}
				if (w ~ /^-[sku]$/) arg = 1
				continue
			}
			if (pre && w ~ /^[0-9.]+[smhd]?$/) continue
			print w
			if (cwd != "" && (w ~ /^\.\// || (sh && w !~ /\//))) print cwd "/" w
			if (base(w) ~ /^-?(sh|ash|bash|dash|busybox)$/) { sh = 1; pre = 1; continue }
			if (base(w) == "start-stop-daemon") { for (i++; i <= NF; i++) { if ($i ~ /^(-K|--stop)$/) next; if ($i !~ /^-/) print unq($i) } }
			next
		}
	}'
}
# What echo or printf writes into a file that starts programs, or pipes into crontab, is a
# command as well: echo "*/3 * * * * /etc/config/.gl/watch.sh" >>/etc/crontabs/root puts
# the malware's cron entry back (review of 2.54). The lines on stdin, as active_in gives
# them, and behind such a line what it writes, one line per line of it.
writes() {
	awk '{ print; l = $0 }
	l !~ /^[[:space:](!{]*(echo|printf)[[:space:]]/ { next }
	l !~ /(>>?|[|][[:space:]]*tee([[:space:]]+-a)?)[[:space:]]*["\047]?([^[:space:]"\047]*crontabs?\/|([^[:space:]"\047]*\/etc\/|(\.\/)?)(rc\.local|init\.d\/|rc\.d\/|uci-defaults\/|hotplug\.d\/|udhcpc\.user|firewall\.user|firewall\.d\/|kvmd\/user\/scripts\/|profile\.d\/|profile([[:space:]"\047;&|)]|$))|[^[:space:]"\047]*\/\.(ash_)?profile([[:space:]"\047;&|)]|$))/ && l !~ /[|][[:space:]]*crontab([[:space:]]|$)/ { next }
	{
		sub(/^[[:space:](!{]*(echo|printf)([[:space:]]+-[A-Za-z]+)*[[:space:]]+/, "", l)
		sub(/[[:space:]]*[|][[:space:]]*(crontab|tee)([[:space:]].*)?$/, "", l)
		sub(/[[:space:]]*[0-9]*>>?[[:space:]]*[^[:space:]]+[[:space:]]*$/, "", l)
		sub(/[)}[:space:]]+$/, "", l); gsub(/%s|\\n|\005|\|\||&&|;|&/, "\n", l); gsub(/["\047]/, "", l)
		n = split(l, a, "\n")
		# a line that starts with a directory or a word with a colon, as in a note like
		# echo "/etc/config/.gl/ found" or echo "gl-helper: checked", runs nothing
		for (k = 1; k <= n; k++) { sub(/^[[:space:]]*#.*$/, "", a[k]); if (a[k] ~ /[^[:space:]]/ && a[k] !~ /^[[:space:]]*[^[:space:]]*[\/:]([[:space:]]|$)/) print a[k] }
	}'
}
# Does a file of commands (as active_in gives them) run a path of the malware, and which?
runs_ioc() { writes <"$1" | ran | grep -qE "$IOC_RE"; }
ran_ioc() { writes <"$1" | ran | grep -E "$IOC_RE" | sort -u | head -n 3 | tr '\n' ' ' | sed 's/ $//'; }
# The lines of a file that a base file does not have. busybox grep -f with an empty file
# matches every line, GNU grep none; an empty base file has no line, so all lines are new.
not_in() { if [ -s "$1" ]; then grep -vxFf "$1" "$2"; else cat "$2"; fi; }
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
	# A name without a path is the shell's own: some busybox builds run their applets from
	# inside the shell (wget, for one). That is the program this script already runs in.
	case $p in "$TMP"/bin/*) return 0 ;; /*) ;; *) return 0 ;; esac
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
	local p hit d f known
	for d in $MARKER_DIRS $MARKER_DIRS_ALT; do
		exists "$(r "$d")" || { [ -n "$UPPER" ] && exists "$(u "$d")"; } || continue
		for p in $MARKER_FILES; do
			p=$d/$p hit= known=
			[ -n "$UPPER" ] && exists "$(u "$p")" && hit=upper
			exists "$(r "$p")" && hit=${hit:+$hit+}merged
			[ -n "$hit" ] || continue
			f=$(src "$p"); exists "$f" || f=$(r "$p")
			[ -f "$f" ] && printf '%s\n' "$GLH_SHAS" | grep -qxF "$(sha256sum "$f" 2>/dev/null | cut -c1-64)" &&
				known=', the same file as posted in GL.iNet'"'"'s forum'
			add IOC marker "/$p" "present ($hit$known)"
		done
	done
	for d in $MARKER_DIRS $MARKER_DIRS_ALT; do
		if exists "$(src "$d")" && ! grep -q "${TAB}/$d/" "$FIND" && { [ -z "$LOWER" ] || ! exists "$(l "$d")"; }; then
			add REVIEW hidden-dir "/$d" "hidden directory not in base image, no known marker inside"
		fi
	done
	# gl-helper or its downloader under another name: a file in the overlay that carries the
	# packer's own name for itself. Only a program or the packer's own format counts (first
	# bytes ELF or NPK!), so a text that quotes the name (this script, a note) does not.
	# The name stands behind NUL bytes, which busybox grep does not look past: files are
	# picked by their first bytes, and only those are read through strs (issue 24).
	[ -n "$UPPER" ] || return 0
	find "$UPPER" -xdev -type f -size +1k -size -8192k -exec grep -lE '^(.ELF|NPK!)' {} + 2>/dev/null | while IFS= read -r f; do
		case $(head -c 4 "$f" 2>/dev/null) in "$(printf '\177')ELF" | 'NPK!') ;; *) continue ;; esac
		strs "$f" | grep -qF "$GLH_PACKER" || continue
		p=${f#"${UPPER%/}"/}
		grep -q "${TAB}/$p${TAB}" "$FIND" && continue
		# a package explains only a file the base image does not have (issue 4)
		same_as_lower "$p" && continue
		[ -n "$(pkg_new "/$p")" ] && continue
		known=
		printf '%s\n' "$GLH_SHAS" | grep -qxF "$(sha256sum "$f" 2>/dev/null | cut -c1-64)" && known=', the same file as posted in GL.iNet'"'"'s forum'
		add IOC marker "/$p" "wrapped in the packer of the malware's gl-helper and its downloader$known (sha256 $(sha256sum "$f" 2>/dev/null | cut -c1-64))"
	done
	return 0
}

# Does a script on stdin start the older backdoor, not only name it? A command that runs
# monitord, ulogd or ujaild, that hands the loader to lua or monitord, or that copies the
# loader or lua to monitord, as the changed urandom_seed does. Comments, kill, killall,
# rm and lines that block its names do not count.
bd_runs_in() {
	local c
	active_in | writes >"$TMP/bdrun"
	ran <"$TMP/bdrun" | grep -qE '(^|/)(monitord|ulogd|ujaild)$' && return 0
	# the command decides, as ran finds it behind setsid, env, procd's "command" and the
	# like: "lua /bin/ulogd" starts the loader, "rm -f /usr/bin/monitord /bin/ulogd" names
	# both and starts nothing. Only the few lines that name the loader are looked at.
	grep -E 'ulogd|monitord' "$TMP/bdrun" >"$TMP/bdnm"
	while IFS= read -r c; do
		printf '%s\n' "$c" | ran >"$TMP/bdprog"
		grep -qE '(^|/)(lua[0-9.]*|monitord)$' "$TMP/bdprog" && printf '%s\n' "$c" | grep -qE 'ulogd|monitord\.pid' && return 0
		grep -qE '(^|/)cp$' "$TMP/bdprog" && printf '%s\n' "$c" | grep -qE '[^[:space:]]*(ulogd|bin/lua)[[:space:]]+[^[:space:]]*monitord' && return 0
	done <"$TMP/bdnm"
	return 1
}
# Is there anything else that could start the loader: a file in the places that start
# programs at boot or later that names it? Comments count here, so that the script never
# claims more than it saw.
bd_started_elsewhere() {
	local d
	for d in etc/rc.local etc/crontabs etc/init.d etc/hotplug.d etc/udhcpc.user.d etc/profile etc/profile.d etc/gl_crontabs; do
		exists "$(r "$d")" || continue
		find "$(r "$d")" -xdev -type f -exec grep -lE '(^|[^[:alnum:]_.-])/bin/ulogd|monitord' {} + 2>/dev/null | grep -q . && return 0
	done
	return 1
}

# What a line that names a server of the older backdoor and does not fetch from it does
# with it: url (a URL of it, something may fetch that), dns (a hosts or dnsmasq answer
# with an outside address), block (an answer with a local address, a sinkhole, or an
# entry of a block list such as adblock's), or name (review of 2.54)
bd_answer() {
	BDRE=$BD_HOST_RE awk '{ ip = ""; re = ENVIRON["BDRE"]
		if ($0 ~ ("://[^/[:space:]]*(" re ")")) { print "url"; next }
		if ($0 ~ /^[[:space:]]*list[[:space:]]+[A-Za-z_]*(block|black|deny|bl_)[A-Za-z_]*[[:space:]]/) { print "block"; next }
		if (match($0, /^[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F]+:[0-9a-fA-F:.]*|::[0-9a-fA-F:.]*)[[:space:]]/)) { ip = substr($0, RSTART, RLENGTH); gsub(/[[:space:]]/, "", ip) }
		else if (match($0, /(address|server|local)[= ][^\/]*\/[^[:space:]]*\/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F]+:[0-9a-fA-F:.]*|::[0-9a-fA-F:.]*)/)) { ip = substr($0, RSTART, RLENGTH); sub(/.*\//, "", ip) }
		if (ip == "") print "name"
		else if (ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|0\.0\.0\.0$|::1?$|[fF][cCdD][0-9a-fA-F]*:|[fF][eE]80:)/) print "block"
		else print "dns" }'
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
			sha=
			if [ "$(sha256sum "$f" 2>/dev/null | cut -c1-64)" = "$BD_INIT_SHA" ]; then
				sha=", the same file as on other reported devices"
			# only lines the base image's version does not have count, and only lines that
			# start the backdoor: an owner's script that blocks its names or ends its
			# processes names them too (review of 2.54)
			elif [ -n "$LOWER" ] && [ -f "$(l "$p")" ]; then
				not_in "$(l "$p")" "$f" 2>/dev/null | bd_runs_in || continue
			else
				strs "$f" | bd_runs_in || continue
			fi
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
		# GL.iNet's security update puts the start script back but leaves the loader, and the
		# backdoor's own keep-list line carries it through the update (RemoteToHome, test of
		# 23 November 2026). Then it is a remnant: no longer started at boot, but the device
		# had the backdoor, and what was done with it cannot be listed.
		if vendor_cleanup && ! has_ioc backdoor-init && ! bd_started_elsewhere; then
			owner="$owner; GL.iNet's security update put its start script back and nothing else here names it, so it is likely no longer started at boot, but this device had the older backdoor"
		fi
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
	# 2b. /etc/config/wireguard_server was written 9 to 12 seconds after the loader was
	#     dropped on 27 of 30 routers RemoteToHome dated, and three owners report the same.
	#     What changed in it is not known, so the distance in time is noted. Times only, the
	#     file is not read.
	f=$(r bin/ulogd)
	if [ -f "$f" ] && [ -f "$(r etc/config/wireguard_server)" ]; then
		p=$(( $(date -u -r "$(r etc/config/wireguard_server)" +%s 2>/dev/null || echo 0) - $(date -u -r "$f" +%s 2>/dev/null || echo 0) ))
		[ "$p" -ge -120 ] && [ "$p" -le 120 ] &&
			add REVIEW backdoor-wg /etc/config/wireguard_server "written $p s after the older backdoor's loader /bin/ulogd; seen on most devices with this backdoor"
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
		# active lines only: a line commented out after a clean-up keeps nothing
		active "$f" | grep -qE "$BD_KEEP_RE" || continue
		same_as_lower "$p" && continue
		[ -n "$(pkg_new "/$p")" ] && continue
		if [ -n "$LOWER" ] && [ -f "$(l "$p")" ]; then
			not_in "$(l "$p")" "$f" 2>/dev/null | active_in 1 | grep -qE "$BD_KEEP_RE" || continue
		fi
		add IOC backdoor-keep "/$p" "older backdoor: keeps its files across firmware updates"
	done
	# 5. its servers. The backdoor is not known to write them into the configuration: there
	#    a line that fetches from one, a URL of one (something may fetch it) or an answer
	#    with an outside address is the indicator; a name that nothing in the file fetches
	#    from is for review (review of 2.54). In AdGuard Home's query log it means that
	#    some device in this network asked for the name, this one or another, so that is
	#    for a human to judge.
	for p in $BD_HOST_PATHS; do
		exists "$(r "$p")" || continue
		find "$(r "$p")" -xdev -type f -exec grep -lE "$BD_HOST_RE" {} + 2>/dev/null | head -n 20 | while IFS= read -r f; do
			p=${f#"${ROOT%/}"/}
			grep -q "${TAB}/$p${TAB}" "$FIND" && continue
			n=$(grep -oE "[a-z0-9.-]*($BD_HOST_RE)" "$f" | sort -u | head -n 4 | tr '\n' ' ' | sed 's/ $//')
			# active lines only: not a comment, not the name of a firewall rule (review of 2.53)
			active "$f" | grep -E "$BD_HOST_RE" | grep -vE "^[[:space:]]*option[[:space:]]+(name|label)[[:space:]]" >"$TMP/bdhost"
			# A block is the advice, not the backdoor: a hosts or dnsmasq entry, a firewall
			# command that drops or rejects, a route that leads nowhere, a line of a UCI
			# firewall rule whose target is DROP or REJECT. A script that writes such an entry
			# (echo "address=/name/0.0.0.0" >file) blocks too: what echo or printf writes is
			# compared, not the command (review of 2.54).
			uci_block_lines "$f" | active_in >"$TMP/bdblk"
			not_in "$TMP/bdblk" "$TMP/bdhost" | awk '{ l = $0
				if (l ~ /^[[:space:]]*(echo|printf)[[:space:]]/) {
					sub(/^[[:space:]]*(echo|printf)([[:space:]]+-[A-Za-z]+)*[[:space:]]+/, "", l); gsub(/["\047]/, "", l)
					sub(/[[:space:]]*>>?[[:space:]]*[^[:space:]]+[[:space:]]*$/, "", l) }
				print l }' >"$TMP/bdrest"
			# a command that takes such a block away (iptables -D before -I, as scripts that run
			# at every ifup do) is not the backdoor either
			grep -vE "$SRV_BLOCK_RE" "$TMP/bdrest" | while IFS= read -r c; do
				if [ "$(srv_kind "$c")" = fetch ]; then echo fetch; continue; fi
				printf '%s\n' "$c" | bd_answer
			done >"$TMP/bdk"
			if grep -qxE 'fetch|url|dns' "$TMP/bdk"; then
				add IOC backdoor-host "/$p" "older backdoor: names its server ($n)"
			elif grep -qx name "$TMP/bdk" && active "$f" | grep -E "$SRV_FETCH_RE" | while IFS= read -r c; do srv_kind "$c"; done | grep -qx fetch; then
				# the name in a list or a variable, and a fetch elsewhere in the file
				add IOC backdoor-host "/$p" "older backdoor: names its server ($n)"
			elif grep -qx name "$TMP/bdk"; then
				add REVIEW server-ref "/$p" "names a server of the older backdoor ($n), but nothing here fetches from it: look at what it does with it"
			elif [ -s "$TMP/bdhost" ]; then
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

# Does a command that names a server only ask whether it answers? Then it keeps nothing,
# runs nothing and sends nothing: nc -z; wget or uclient-fetch with --spider; curl -I; a
# download by curl, wget or uclient-fetch whose content goes to /dev/null, or to the
# screen, to /dev/null or to grep and its kin. That is an owner's check that a block holds
# (nc -z ... && logger, wget -qO- ... >/dev/null || logger). Not a probe: any other tool
# (nc without -z, ncat, socat, telnet, rtty, ssh, dbclient, ...), a download that wget
# saves under its own name, output to a file, data sent along (curl -d, -F, -T,
# --post-file, $( ) in the command), a pipe into anything else (review of 2.53). A running
# process (SRV_PROC=1) does not show where its output goes, and wget -qO- | sh shows only
# wget -qO-: there content on the screen counts only when the command line itself sends it
# to /dev/null or grep (sh -c '... >/dev/null').
is_probe() {
	printf '%s\n' "$1" | awk -v proc="${SRV_PROC:-0}" 'function unq(s) { gsub(/["\047]/, "", s); return s }
	{
		if ($0 ~ /\$\(|`/) { print 0; exit }
		l = $0; gsub(/\|/, " | ", l); n = split(l, w, " ")
		t = ""; seg = 0; nxt = 0; bad = 0; probe = 0; out = ""; null = 0
		for (i = 1; i <= n; i++) {
			x = unq(w[i]); if (x == "") continue
			if (x == "|") { seg++; nxt = 1; continue }
			if (x ~ /^1?>>?/) { y = x; sub(/^1?>>?/, "", y); if (y == "") y = unq(w[++i]); if (y != "/dev/null") bad = 1; else null = 1; continue }
			if (x ~ /^[0-9]+>/) { if (x ~ /^[0-9]+>>?$/) i++; continue }
			if (x ~ /^[0-9]*</) { if (x ~ /^[0-9]*<$/) i++; continue }
			b = x; sub(/.*\//, "", b)
			if (nxt) { nxt = 0; if (b !~ /^(grep|egrep|fgrep|head|tail|wc|cut|tr|sort|uniq|logger|cat)$/) bad = 1; continue }
			if (seg) continue
			if (t == "") {
				if (b ~ /^(nc|netcat|ncat)$/) t = "nc"
				else if (b ~ /^wget(-[[:alnum:]]+)?$/ || b == "uclient-fetch") { t = "wget"; out = "file" }
				else if (b == "curl") { t = "curl"; out = "-" }
				else if (b ~ /^(tftp|ftpget|ftpput|socat|telnet|rtty|ssh|dbclient|scp|sftp|openssl|rsync)$/) bad = 1
				continue
			}
			if (t == "nc") {
				if (x ~ /^-[[:alnum:]]*[ec]$/ || x ~ /^--(sh-|lua-)?exec/) bad = 1
				else if (x ~ /^-[[:alnum:]]*z/) probe = 1
			} else if (t == "wget") {
				if (x == "--spider") probe = 1
				else if (x ~ /^--(post-data|post-file|body-data|body-file|method)/) bad = 1
				else if (x ~ /^--output-document=/) out = substr(x, 19)
				else if (x == "--output-document") out = unq(w[++i])
				else if (x ~ /^-[[:alnum:]]*O/) { y = x; sub(/^-[[:alnum:]]*O/, "", y); out = (y == "") ? unq(w[++i]) : y }
			} else if (t == "curl") {
				if (x == "--head" || x ~ /^-[[:alpha:]]*I/) probe = 1
				else if (x ~ /^--(data|form|upload-file|json)/ || x ~ /^-[[:alpha:]]*[dFT]/) bad = 1
				else if (x ~ /^--remote-(name|header-name)/ || x ~ /^-[[:alpha:]]*[OJ]/) out = "file"
				else if (x ~ /^--output=/) out = substr(x, 10)
				else if (x == "--output") out = unq(w[++i])
				else if (x ~ /^-[[:alpha:]]*o/) { y = x; sub(/^-[[:alpha:]]*o/, "", y); out = (y == "") ? unq(w[++i]) : y }
			}
		}
		if (t == "" || bad) print 0
		else if (t == "nc") print probe
		else print (probe || out == "/dev/null" || (out == "-" && (!proc || null || seg))) ? 1 : 0
		exit
	}'
}
# What one command does with a server of the malware: fetch, probe, block, unblock (it
# takes a block away) or name (SRV_FETCH_RE and what follows it).
srv_kind() {
	if printf '%s\n' "$1" | grep -qE "$SRV_FETCH_RE"; then
		if ! printf '%s\n' "$1" | grep -qE "$SH_PIPE_RE" && [ "$(is_probe "$1")" = 1 ]; then echo probe; else echo fetch; fi
	elif printf '%s\n' "$1" | ran | grep -qE "$RAM_RE"; then
		echo fetch
	elif printf '%s\n' "$1" | grep -qE "$SRV_BLOCK_RE"; then
		if printf '%s\n' "$1" | grep -qE "$UNBLOCK_RE"; then echo unblock; else echo block; fi
	else
		echo name
	fi
}
# What a file of commands (as active_in gives them) does with the malware's servers:
#   fetch  a command that names a server fetches from it (srv_kind)
#   block  every command that names a server blocks it or takes a block away (a script
#          that deletes a rule before it inserts it again), one at least blocks, and no
#          command fetches anything
#   name   anything else: a probe, a command that only names a server
# Nothing when no command names one.
srv_cmds() {
	grep -E "$KVM_IP_RE" "$1" | while IFS= read -r c; do srv_kind "$c"; done >"$TMP/srvk"
	[ -s "$TMP/srvk" ] || return 0
	if grep -qx fetch "$TMP/srvk"; then
		echo fetch
	elif grep -qx block "$TMP/srvk" && ! grep -qvxE 'block|unblock' "$TMP/srvk" && ! grep -qE "$SRV_FETCH_RE" "$1"; then
		echo block
	else
		echo name
	fi
	return 0
}
# The same for a file, or a command line saved to one (issue 20). A server named only in a
# comment or in a binary is a name.
srv_use() {
	local u
	active "$1" >"$TMP/srv"
	u=$(srv_cmds "$TMP/srv")
	if [ -n "$u" ]; then echo "$u"; else strs "$1" | grep -qE "$KVM_IP_RE" && echo name; fi
	return 0
}
srv_names() { strs "$1" | grep -oE "$KVM_IP_RE" | sort -u | tr '\n' ' ' | sed 's/ $//'; }
# The commands of a crontab, keep list or the firewall's start script that start the
# malware or fetch from its servers: the numbers of their first and last line in the file
# (a command goes on over lines that end in \). What --fix takes out, and nothing else.
bad_lines() {
	local s c nj=0
	linewise "$1" && nj=1
	awk -v nj="$nj" '{ if (l == "") s = NR; l = l $0; c = l; sub(/(^|[[:space:]])#.*$/, "", c) }
		!nj && c ~ /(^|[^\\])(\\\\)*\\$/ { sub(/\\$/, "", l); next }
		{ print s " " NR "\t" l; l = "" }' "$1" 2>/dev/null |
		grep -E "$IOC_RE|$KVM_IP_RE" | while IFS="$TAB" read -r s c; do
			printf '%s\n' "$c" | active_in "$nj" >"$TMP/cronline"
			if runs_ioc "$TMP/cronline" || [ "$(srv_cmds "$TMP/cronline")" = fetch ]; then
				printf '%s\n' "$s"
			fi
		done
	return 0
}
# Those lines as they stand
cron_bad() { bad_lines "$1" | while read -r s e; do sed -n "${s},${e}p" "$1"; done; }
# A file without those lines (with $3 = 1: each command replaced by ":", so that a script
# keeps its if and fi). $2 holds the line numbers from bad_lines.
drop_lines() {
	awk -v rep="${3:-0}" 'FILENAME == ARGV[1] { for (i = $1; i <= $2; i++) d[i] = (i == $1) ? 2 : 1; next }
		!(FNR in d) { print; next }
		rep && d[FNR] == 2 { m = $0; sub(/[^[:space:]].*$/, "", m); print m ": # line of the malware, removed by gl-helper-triage --fix" }' "$2" "$1"
}
# The lines of a UCI file that stand in a section whose target is DROP or REJECT: a
# firewall rule that blocks what it names (review of 2.53)
uci_block_lines() {
	awk 'function flush(  i) { if (blk) for (i = 1; i <= n; i++) print sec[i]; n = 0; blk = 0 }
		/^[[:space:]]*config[[:space:]]/ { flush() }
		{ sec[++n] = $0 }
		/^[[:space:]]*option[[:space:]]+target[[:space:]]/ && toupper($0) ~ /(DROP|REJECT)/ { blk = 1 }
		END { flush() }' "$1" 2>/dev/null
}

check_persist() {
	local p f u
	for p in $PERSIST; do
		f=$(src "$p")
		exists "$f" || continue
		same_as_lower "$p" && continue
		# deleted in the overlay: the owner's doing, and nothing in it can start anything
		if whiteout "$f"; then
			add INFO deleted "/$p" "deleted on this device (the firmware image has it)"
			continue
		fi
		if ! safe "$f"; then
			add REVIEW odd-file "/$p" "not a regular file ($(ls -ld "$f" 2>/dev/null | cut -c1-10)), not read"
			continue
		fi
		u=$(srv_use "$f")
		active "$f" >"$TMP/cmds"
		if runs_ioc "$TMP/cmds"; then
			add IOC persist-ref "/$p" "starts the malware ($(ran_ioc "$TMP/cmds"))"
		elif [ "$u" = fetch ]; then
			add IOC persist-ref "/$p" "fetches from a server of the malware ($(srv_names "$f"))"
		elif [ "$p" = etc/rc.local ] && ! { if [ -n "$LOWER" ] && [ -f "$(l "$p")" ]; then not_in "$(l "$p")" "$f"; else cat "$f"; fi 2>/dev/null |
			sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -vE '^(#.*)?$' | grep -qvxF -e 'exit 0' -e '. /lib/functions/gl_util.sh' -e 'remount_ubifs'; }; then
			# GL.iNet's firmware writes these lines into rc.local itself on some models; a
			# file that differs from the base image by nothing else is not a change of yours
			add INFO firmware-lines "/$p" "differs from the base image only by lines the firmware writes itself (gl_util.sh, remount_ubifs)"
		else
			case $u in
			block) u="; blocks a server of the malware ($(srv_names "$f"))" ;;
			name) u="; names a server of the malware ($(srv_names "$f")), but does not fetch from it" ;;
			esac
			grep -qE "$IOC_RE" "$TMP/cmds" && u="$u; names a path of the malware, but does not run it"
			add PERSIST persistence "/$p" "present in overlay ($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null) active lines)$u"
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
	local p e base u seen
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
				# a finding of the older backdoor (a block of its names too) does not hide what
				# else the file does: the gl-helper checks still run, only the REVIEW lines are
				# left out (review of 2.54)
				grep "^[A-Z]*${TAB}[a-z-]*${TAB}/$rel${TAB}" "$FIND" | cut -f2 | grep -qvE '^(backdoor-[a-z]+|server-ref)$' && continue
				seen=; grep -v "^INFO${TAB}backdoor-block${TAB}" "$FIND" | grep -q "^[A-Z]*${TAB}[a-z-]*${TAB}/$rel${TAB}" && seen=1
				[ -n "$(pkg_new "/$rel")" ] && continue
				case $rel in etc/rc.d/*) known_service_link "$f" && continue ;; esac
				u=
				if [ -f "$f" ] && [ ! -L "$f" ]; then
					# any autostart/config file that starts the implant is persistence too; a
					# keep list starts nothing, but the path it keeps stands first on its line
					active "$f" >"$TMP/cmds"
					if runs_ioc "$TMP/cmds"; then
						case $rel in
						etc/sysupgrade.conf | lib/upgrade/keep.d/*)
							add IOC keep-ref "/$rel" "keeps files of the malware across firmware updates ($(ran_ioc "$TMP/cmds"))" ;;
						*) add IOC persist-ref "/$rel" "starts the malware ($(ran_ioc "$TMP/cmds"))" ;;
						esac
						continue
					fi
					u=$(srv_use "$f")
				fi
				# a server of the malware: only what fetches from it starts the malware, and
				# only that is removed. A block is the owner's, and the file is listed for
				# review like any other; a name alone is for review.
				case $u in fetch) add IOC persist-ref "/$rel" "fetches from a server of the malware ($(srv_names "$f"))"; continue ;; esac
				[ -n "$seen" ] && continue
				case $u in
				block) add INFO server-block "/$rel" "blocks a server of the malware ($(srv_names "$f")): a block, not the malware" ;;
				name) add REVIEW server-ref "/$rel" "names a server of the malware ($(srv_names "$f")), but does not fetch from it"; continue ;;
				esac
				# a path of the malware that a command only names (rm, pgrep, [ -e ]): the owner's
				# guard or a note, not the malware (review of 2.53)
				if [ -f "$f" ] && [ ! -L "$f" ] && grep -qE "$IOC_RE" "$TMP/cmds"; then
					add REVIEW path-ref "/$rel" "names a path of the malware, but does not run it"
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

# The start tick of a process, field 22 of /proc/<pid>/stat (behind the name, which can
# hold spaces and brackets). With the number it tells a process from a later one that
# gets the same number.
proc_tick() { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'; }
# An IOC process, and its start tick for --fix: that stops a number only while it is
# still the process that was found (review of 2.53)
ioc_proc() { add IOC process "$1" "$2"; printf '%s %s\n' "$1" "$(proc_tick "$1")" >>"$TMP/pidtick"; }
# When a process started, in UTC, from its start tick in /proc/<pid>/stat and the boot
# time. The reported shells all started at about the same time (21:40 UTC, 2026-11-20).
proc_start() {
	local bt tk
	bt=$(awk '/^btime /{print $2}' /proc/stat 2>/dev/null)
	tk=$(proc_tick "$1")
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
	: >"$TMP/pidtick"
	local d f pid exe comm cmd sha known prog u named
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
		# this script and its own subshells, known by the file they run, when that file is a
		# copy of this script. A name on a command line hides nothing (review of 2.53).
		case $cmd in *gl-helper-triage*)
			prog=$(printf '%s\n' "$cmd" | active_in 0 1 | head -n 1 | ran | grep -vE '(^|/)-?(sh|ash|bash|dash|busybox)$' | head -n 1)
			case ${prog##*/} in gl-helper-triage*)
				case $prog in /*) f=$prog ;; *) f=$d/cwd/$prog ;; esac
				self_copy "$f" && continue ;;
			esac ;;
		esac
		# The malware is a process that runs one of its files: as the program, under its
		# name, as the script a shell runs, in sh -c or in a loop (ran). A command that only
		# names such a path, as less or tail on a log does, is for review and is not stopped
		# (issue 20).
		: >"$TMP/pran"
		named=0
		if printf '%s\n' "$cmd" | grep -qE "$IOC_RE"; then
			named=1
			printf '%s\n' "$cmd" | active_in 0 1 | ran >"$TMP/pran"
		fi
		if printf '%s\n%s\n' "$exe" "$comm" | cat - "$TMP/pran" | grep -qE "$IOC_RE"; then
			ioc_proc "$pid" "comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		[ "$named" = 1 ] &&
			add REVIEW process "$pid" "names a path of the malware, but does not run it: started $(proc_start "$pid") comm=$comm cmd=$cmd"
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
			ioc_proc "$pid" "GL.iNet's quick check (crond -i /tmp/.log, the name gl-helper gives itself): started $(proc_start "$pid") comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$SHELL_RE"; then
			if printf '%s\n' "$cmd" | active_in 0 1 | grep -E "$SHELL_RE" | grep -qE "$SHELL_USE_RE"; then
				ioc_proc "$pid" "remote shell reported by users (GL.iNet staff: treat the router as compromised): started $(proc_start "$pid") comm=$comm cmd=$cmd"
				continue
			fi
			add REVIEW process "$pid" "names the address or the pipe of the reported remote shell, but is not made like it: started $(proc_start "$pid") comm=$comm cmd=$cmd"
		fi
		if printf '%s\n' "$cmd" | grep -qE "$KVM_IP_RE"; then
			printf '%s\n' "$cmd" >"$TMP/srvcmd"
			u=$(SRV_PROC=1; srv_use "$TMP/srvcmd")
			# a program from a RAM disk that is given a server: the payload (review of 2.53)
			printf '%s\n' "$exe" | grep -qE "$RAM_RE" && u=fetch
			case $u in
			fetch)
				ioc_proc "$pid" "fetches from a server of the malware: started $(proc_start "$pid") comm=$comm exe=$exe cmd=$cmd"
				continue ;;
			block) add INFO process "$pid" "blocks a server of the malware: comm=$comm cmd=$cmd" ;;
			*) add REVIEW process "$pid" "names a server of the malware, but does not fetch from it: started $(proc_start "$pid") comm=$comm cmd=$cmd" ;;
			esac
		fi
		if printf '%s\n' "$cmd" | grep -qE "$TOOL_RE"; then
			add REVIEW process "$pid" "tool that remote shells use (GL.iNet staff's process check): started $(proc_start "$pid") comm=$comm cmd=$cmd"
		fi
		if [ -n "$exe" ] && grep -q "^IOC${TAB}applet-hijack${TAB}${exe}${TAB}" "$FIND"; then
			ioc_proc "$pid" "runs replaced applet: comm=$comm exe=$exe cmd=$cmd"
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

# Was a state file written at the SD-WAN module's start: within two minutes of its other
# state files (issue 19)? Not known: whether the handler rewrites those files too when it
# runs a message; if it does, a message right after the module's start is not told apart.
mp_module_start() {
	local t o g
	t=$(date -u -r "$1" +%s 2>/dev/null) || return 1
	for o in etc/mp_connection_info etc/mphosts; do
		safe "$(r "$o")" || continue
		g=$(date -u -r "$(r "$o")" +%s 2>/dev/null) || continue
		[ $((t - g)) -le 120 ] && [ $((g - t)) -le 120 ] && return 0
	done
	return 1
}

check_tmp() {
	local f
	exists "$(r tmp/.log)" && add REVIEW tmp-file /tmp/.log "path from GL.iNet's quick check (crond -i /tmp/.log) exists"
	f=$(r tmp/f)
	[ -p "$f" ] && add IOC pipe /tmp/f "named pipe of the reported remote shell: the shell ran since the last boot, last data $(shown_time "$(file_time "$f")")"
	exists "$(r tmp/.dg)" && add REVIEW tmp-file /tmp/.dg "the malware's installer leaves a file of this name after its first report following a restart"
	# A command the attacker sent on 20 November 2026 tried to end a program of this name
	# along with the remote shell; none has been seen on a device so far (RemoteToHome).
	exists "$(r tmp/.lp)" && add REVIEW tmp-file /tmp/.lp "a name the attacker's commands of 20 November tried to end along with the remote shell; not seen on any device so far"
	# the live crontab of GL.iNet's firmware; the installer adds its watchdog there too
	f=$(r tmp/gl_crontabs/root)
	safe "$f" && [ -n "$(cron_bad "$f" | head -n 1)" ] &&
		add IOC cron-ref /tmp/gl_crontabs/root "the running crontab starts the malware: $(cron_bad "$f" | head -n 2 | tr '\n' ' ' | cut -c1-160)"
	# The firmware keeps crontab files of its own in /etc/gl_crontabs/crontabs.d, and they
	# survive a restart. GL.iNet's cleanup (its security firmware) removes the malware's lines
	# there too, so they are looked for here as well; --fix drops those lines and no others.
	for f in "$(r etc/gl_crontabs/crontabs.d)"/*; do
		safe "$f" && [ -n "$(cron_bad "$f" | head -n 1)" ] &&
			add IOC cron-ref "/etc/gl_crontabs/crontabs.d/${f##*/}" "a crontab file of the firmware starts the malware: $(cron_bad "$f" | head -n 2 | tr '\n' ' ' | cut -c1-160)"
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
		# firmware was built, and the module's start by those files: written within two
		# minutes of one of them. A file written after the build day but on its own may be the
		# attack on the old firmware before the upgrade, with settings kept (review of 2.54).
		# A file that tells the first start, /etc/board.json, is no help: it is written before
		# the clock is set and carries a date in 1970 on real devices.
		if [ "$n" = 0 ] && [ "$aw" = off ] && vendor_cleanup && a=$(built_epoch) &&
			[ "$(date -u -r "$f" +%s 2>/dev/null || echo 0)" -ge "$a" ] && mp_module_start "$f"; then
			add REVIEW state-file /etc/mp_ip_mapping_info "$w, empty: written after this firmware was built, together with the SD-WAN module's other state files. This firmware has the fix and refuses the attack's command; its SD-WAN module writes the file at its own start. Not counted as a trace"
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
				# The firewall runs /etc/firewall.user (fw3) and what lies in /etc/firewall.d as
				# shell scripts at every start: there the malware's commands count as in an
				# autostart file. --fix drops only those lines (review of 2.53).
				case $rel in etc/firewall.user | etc/firewall.d/*)
					[ ! -L "$f" ] && active "$f" >"$TMP/cmds"
					if [ ! -L "$f" ] && runs_ioc "$TMP/cmds"; then
						add IOC persist-ref "/$rel" "the firewall runs this at every start, and it starts the malware ($(ran_ioc "$TMP/cmds"))"
					elif [ ! -L "$f" ] && [ "$(srv_use "$f")" = fetch ]; then
						add IOC persist-ref "/$rel" "the firewall runs this at every start, and it fetches from a server of the malware ($(srv_names "$f"))"
					fi ;;
				esac
				if [ -n "$LOWER" ] && [ -f "$(l "$rel")" ]; then
					not_in "$(l "$rel")" "$f" 2>/dev/null | grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' >"$TMP/fw-lines"
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
has_ioc() { grep -q "^IOC${TAB}$1${TAB}" "$FIND"; }
# /etc/rtty_conf is counted for the verdict but --fix does not change it: the script cannot
# tell what belongs there. Whatever --fix did, this finding is still there (issue 22).
rtty_note() {
	has_ioc rtty-server || return 0
	say "   ${YEL}/etc/rtty_conf still names the attacker's server. --fix does not change it: the script${N}"
	say "   ${YEL}cannot tell what belongs there. A factory reset or reflash puts it right.${N}"
}

# Under a clean verdict on a running device: when it last started. The remote shell, its
# pipe and the firewall rule live in memory only, and a KVM firmware update can remove
# the malware's files, so a device started since the attacks began is clean now, which
# says nothing about before (issue 5; GL.iNet staff say the same of their quick check).
RESTART_FROM='2026-11-19 00:00:00 UTC'
# GL.iNet's security firmware for routers (builds of 22 and 23 November 2026: 4.7.14 to
# 4.11.1, depending on the model) brings the package gl-sdk4-system-check. Its
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

# How old this version is, by the device's clock, in hours. Nothing where the clock or the
# date cannot be read, or the clock stands before the release.
version_age() {
	local r n
	r=$(date -u -d "${RELEASED% UTC}" +%s 2>/dev/null); n=$(date -u +%s 2>/dev/null)
	case "$r" in '' | *[!0-9]*) return 1 ;; esac
	case "$n" in '' | *[!0-9]*) return 1 ;; esac
	[ "$n" -ge "$r" ] || return 1
	echo $(((n - r) / 3600))
}
report_head() {
	local age
	say "${B}== gl-helper triage $VERSION${N}  ${D}(CSA-2026-01)${N}"
	# The script changes often and does not look for a newer version by itself. So every
	# run says how old this one is and how to get the current one.
	if age=$(version_age); then
		if [ "$age" -ge 48 ]; then kv Released "$RELEASED, ${YEL}$((age / 24)) days ago${N}"
		elif [ "$age" -ge 2 ]; then kv Released "$RELEASED, $age hours ago"
		else kv Released "$RELEASED"; fi
	else
		kv Released "$RELEASED"
	fi
	# started as "sh -s" through ssh or triage-remote.sh there is no file to replace
	if [ ! -f "$0" ]; then kv Update "${D}runs from a pipe, not a file: fetch the script again for the current version${N}"
	elif [ "${age:-0}" -ge 24 ]; then kv Update "${YEL}a newer version is likely.${N} Get it with: sh $0 --update"
	else kv Update "sh $0 --update  ${D}(gets the current version and checks its signature)${N}"; fi
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
	[ "$(count_hard)" -gt "$(count "IOC${TAB}rtty-server")" ] && say "   ${RED}IOC${N}      a known trace of the malware or of a remote shell. --fix removes it."
	has_ioc rtty-server && say "   ${RED}IOC${N}      rtty-server: --fix does NOT change /etc/rtty_conf. A factory reset or reflash does."
	[ "$(count_cmd)" -gt 0 ] && say "   ${RED}IOC${N}      cloud-command, fw-rule, installer-trace: the attack reached this device."
	[ "$(count_bd)" -gt 0 ] && say "   ${RED}IOC${N}      backdoor-*: a trace of the older backdoor. --fix does NOT remove it, see below."
	[ "$(count PERSIST)" -gt 0 ] && say "   ${YEL}PERSIST${N}  a changed rc.local or root crontab. --fix resets it only when the malware itself was found."
	if [ "$(count REVIEW)" -gt 0 ]; then
		say "   ${CYA}REVIEW${N}   an unusual change, not proof of an infection. Check whether it is yours. Never modified."
		grep -qE "^IOC${TAB}persist-ref${TAB}/etc/firewall\.(user|d/)" "$FIND" &&
			say "            Except the malware's own lines in the firewall's start script (IOC above): --fix takes those out."
	fi
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
		say "   ${D}Not proof that nothing happened: not every step of the attack leaves a trace on the${N}"
		say "   ${D}device.${N}"
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
	# Without an archive the run still ends with its result (and --fix changes nothing):
	# the findings are what the owner needs most, also on a router whose /tmp is full.
	mkdir -p "$OUTDIR" || { archive_failed "cannot create $OUTDIR"; return 1; }
	ARCHIVE=$OUTDIR/gl-triage-$HOST-$STAMP.tar.gz
	tar -C "$TMP" -czf "$ARCHIVE" evidence || { rm -f "$ARCHIVE"; archive_failed "writing $ARCHIVE failed"; return 1; }
	tar -tzf "$ARCHIVE" >/dev/null 2>&1 || { archive_failed "archive verification failed: $ARCHIVE"; return 1; }
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
# Take the malware's commands out of a file and keep the rest. In a script each becomes
# ":", so that an if or a loop around it still closes; if the script would not read as a
# script after that, it is left for the owner (review of 2.53). In a crontab or a keep
# list the line goes. For the firewall's start script, and wherever no base image is known
# to put a file back from: there a file may be the firmware's own, such as /etc/rc.local
# or /etc/init.d/rcS, and deleting it would take it away (review of 2.54).
fix_lines() {
	local p="$1" f rep=1
	f=$(r "$p")
	safe "$f" || return 0
	linewise "$f" && rep=0
	bad_lines "$f" >"$TMP/fl.bad"
	drop_lines "$f" "$TMP/fl.bad" "$rep" >"$TMP/fl.new"
	if [ ! -s "$TMP/fl.bad" ]; then
		say "   ${YEL}left /$p: the malware's command there could not be told apart line by line; take it out yourself${N}"
		return 1
	elif [ "$rep" = 1 ] && ! sh -n "$TMP/fl.new" 2>/dev/null && sh -n "$f" 2>/dev/null; then
		say "   ${YEL}left /$p: without the malware's lines it would no longer run as a script; take them out yourself${N}"
		return 1
	elif cat "$TMP/fl.new" >"$f"; then
		if [ "$rep" = 1 ]; then
			act "replaced the malware's lines in /$p by \":\" (your own lines there stay; previous version: files/merged/$p in the archive)"
		else
			act "removed the malware's lines from /$p (your own lines there stay; previous version: files/merged/$p in the archive)"
		fi
	else
		return 1
	fi
}

fix() {
	local pid p f t failed=0
	if [ "$LIVE" = 1 ] && [ "$(id -u)" != 0 ]; then die "--fix needs root"; fi
	if [ "$(count_gl)" = 0 ]; then
		say ""
		if [ "$(count IOC)" = 0 ]; then
			say "   No IOC found, nothing to remediate. REVIEW items were not touched."
			return 0
		fi
		# what is left are IOCs that --fix does not remove: one line for each kind
		say "   Nothing was changed."
		[ "$(count_bd)" -gt 0 ] && say "   ${YEL}--fix does not remove the older backdoor: reflash the firmware.${N}"
		rtty_note
		if has_ioc cloud-command; then
			say "   Nothing to remove for cloud-command: the state file only shows that the command ran."
			say "   It was left in place."
		fi
		if has_ioc installer-trace; then
			say "   Nothing to remove for installer-trace: the link to busybox only shows that the"
			say "   installer was at work. It was left in place."
		fi
		return 0
	fi
	section "Remediation"
	# 1. processes: freeze all first so they cannot restart each other, then kill
	#    Only a process that is still the one that was found, known by its start tick: its
	#    number can have gone to another process since the check (review of 2.53).
	awk -F '\t' '$1=="IOC" && $2=="process" {print $3}' "$FIND" | sort -u >"$TMP/pids.found"
	: >"$TMP/pids"
	while read -r pid; do
		t=$(proc_tick "$pid")
		[ -n "$t" ] || continue
		if ! grep -qxF "$pid $t" "$TMP/pidtick" 2>/dev/null; then
			say "   left pid $pid: another process has that number now"
			continue
		fi
		echo "$pid" >>"$TMP/pids"
	done <"$TMP/pids.found"
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
	# a program of the malware elsewhere, known by its packer: that file only, and where
	# the base image has a file of that name, the base image's file is put back
	awk -F '\t' '$1=="IOC" && $2=="marker" {print substr($3,2)}' "$FIND" | sort -u | while IFS= read -r p; do
		f=$(r "$p")
		[ -f "$f" ] && [ ! -L "$f" ] || continue
		restore_from_lower "$p" || echo fail >>"$TMP/fixfail"
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
			whiteout "$(src "$p")" && continue
			if [ -z "$LOWER" ]; then
				# no base image here to put back (a KVM, or --root without --lower): only the
				# malware's lines go
				if [ -n "$(bad_lines "$(r "$p")" | head -n 1)" ]; then
					fix_lines "$p" || failed=1
				else
					say "   left /$p: there is no base image here to put back, and no line of the malware is in it."
				fi
				continue
			fi
			restore_from_lower "$p" || failed=1
			say "     ${D}(previous version: files/merged/$p in the archive)${N}"
		done
	else
		for p in $PERSIST; do
			exists "$(src "$p")" || continue
			same_as_lower "$p" && continue
			whiteout "$(src "$p")" && continue
			say "   left /$p as it is: only traces of the remote shell were found, and the shell is not"
			say "   known to write there. Read the file yourself (files/merged/$p in the archive)."
		done
	fi
	# 4. other files that start the implant (init scripts, hotplug, profile, ...)
	#    and replaced applets: put the base image version back or remove them
	awk -F '\t' '$1=="IOC" && ($2=="persist-ref" || $2=="applet-hijack") {print $2 "\t" substr($3,2)}' "$FIND" |
		while IFS="$TAB" read -r t p; do
			case " $PERSIST " in *" $p "*) continue ;; esac
			exists "$(r "$p")" || continue
			# The firewall's start script: the owner's rules stay (review of 2.53). It is
			# listed for review as well: this is the one such path that --fix changes, and
			# only in these lines. Without a base image the same holds for every file that
			# starts the malware (review of 2.54).
			case $p in etc/firewall.user | etc/firewall.d/*) t=lines ;; esac
			[ -z "$LOWER" ] && [ "$t" = persist-ref ] && t=lines
			if [ "$t" = lines ]; then
				fix_lines "$p" || echo fail >>"$TMP/fixfail"
				continue
			fi
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
		if [ "$pid" = ssh-key ]; then
			grep -v 'gl-agent' "$f" >"$TMP/keep.new"
		else
			bad_lines "$f" >"$TMP/cron.bad"
			drop_lines "$f" "$TMP/cron.bad" >"$TMP/keep.new"
		fi
		cat "$TMP/keep.new" >"$f" && act "removed the malware's lines from /$p" || echo fail >>"$TMP/fixfail"
	done
	awk -F '\t' '$1=="IOC" && $2=="keep-ref" {print substr($3,2)}' "$FIND" | while IFS= read -r p; do
		f=$(r "$p")
		safe "$f" || continue
		bad_lines "$f" >"$TMP/keep.bad"
		drop_lines "$f" "$TMP/keep.bad" >"$TMP/keep.new"
		cat "$TMP/keep.new" >"$f" && act "removed the malware's paths from /$p" || echo fail >>"$TMP/fixfail"
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
	# not after an archive that failed: there is none to copy (review of 2.53)
	if [ -n "$ARCHIVE" ]; then
		say "   - Copy the evidence archive off the device and keep it."
	elif [ "$MODE" = check ]; then
		say "   - Keep the evidence: run the script with --archive and copy the archive off the device."
	fi
	if [ "$(count_cmd)" -gt 0 ] && [ "$(count_hard)" = 0 ]; then
		say "   - A command from the attacker ran here as root. It could read every key and password on"
		say "     the device, so the steps below apply even though nothing was installed."
	fi
	if [ "$(count_bd)" -gt 0 ]; then
		say "   ${B}- The older backdoor: reinstall the firmware with \"keep settings\" OFF, from a file you${N}"
		say "   ${B}  downloaded yourself. Where it added itself to the keep list it survives an update${N}"
		say "   ${B}  that keeps settings, GL.iNet's security update included. Do not restore a backup${N}"
		say "   ${B}  taken from this device.${N}"
		say "   - Its second stage runs in memory only. Until the reinstall, take the device off the"
		say "     internet. Known server names, to block in your network: adguardns.com, adguardns.org,"
		say "     adsanalypro.com, lede-openproject.org, adxinsight.com, openwrt-project.org. Other"
		say "     variants may use others."
		say "   - It may have been there for months: treat every password and key on it as copied."
	fi
	case $PLATFORM in
	openwrt)
		say "   - Reinstall the firmware WITHOUT keeping settings, from a file you downloaded yourself."
		say "     An update that keeps settings keeps /etc/config, where the implant hides, and what"
		say "     else was added to rc.local, cron, the accounts or the SSH keys."
		say "   - Prefer a reinstall to a factory reset: a reset keeps the installed firmware image,"
		say "     and on at least one model root can write to that image."
		say "   - Check every client that used this router as gateway or DNS." ;;
	glkvm-*)
		say "   - Install GL.iNet's security firmware (1.10.3 or later, 1.8.7 or later for the RMQ1) with"
		say "     \"Save current configuration\" OFF, or reset the KVM afterwards. A kept configuration"
		say "     keeps the password, the SSH keys and /etc/kvmd/user, boot scripts there included. The"
		say "     update removes the known files and keeps no copy: keep the evidence archive."
		say "   - Check the computer connected to the KVM (unknown software, accounts, autostart)." ;;
	*)
		say "   - Reinstall the firmware without keeping settings, from a file you downloaded yourself:"
		say "     this script's cleanup only removes known IOCs." ;;
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
					cron_bad "$(r "${f#/}")"
				elif [ "$kind" = backdoor-keep ]; then
					grep -E "$BD_KEEP_RE" "$(r "${f#/}")"
				elif [ "$f" = /etc/rc.local ]; then
					# the whole file: what stands around the attacker's line matters too
					n=60; cat "$(r "${f#/}")"
				elif [ -n "$LOWER" ] && [ -f "$(l "${f#/}")" ]; then
					not_in "$(l "${f#/}")" "$(r "${f#/}")"
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
	local answer n ioc extra note nl nr na acc
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
	# Lines and names of the owner's that the report carries as they are: said in bold, so
	# that nobody sends them unawares. They stay in the report because they can be what
	# the attacker left (Aaron, 2026-11-23).
	if [ "$nl" -gt 0 ]; then
		ysay "${B}Also $nl lines of your own autostart files and firewall, word for word.${N}"
		# the attacker's addresses, 127.x (the attack's own rule) and 0.0.0.0 are taken out of
		# each line before it is counted, so that a line with both still counts (review of 2.53)
		na=$(R="(^|[^0-9.])($KVM_IP_RE|170\\.39\\.226\\.[0-9]+|127\\.[0-9.]+|0\\.0\\.0\\.0)" awk '{ gsub(ENVIRON["R"], " "); print }' "$TMP/rlines" |
			grep -cE '(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)')
		[ "${na:-0}" -gt 0 ] && ysay "${B}$na of them hold IP addresses that are not the attacker's, for example of your own network.${N}"
		ysay "They can also hold names, passwords or tokens. Look at them with v first, and answer n"
		ysay "if you would not post one of them in a public forum."
	fi
	# every account name that goes with the report
	grep -E '^(new-account|uid0-account)  ' "$TMP/revlines" 2>/dev/null | sed -n 's/.* name=\([^ ]*\).*/\1/p' | sort -u >"$TMP/accs"
	n=$(wc -l <"$TMP/accs" | tr -d ' ')
	acc=$(head -n 8 "$TMP/accs" | tr '\n' ' ' | sed 's/ $//')
	[ "$n" -gt 8 ] && acc="$acc and $((n - 8)) more (v shows them)"
	[ -n "$acc" ] && ysay "${B}Also the name of each account the firmware does not have: $acc${N}"
	# the note leaves the device: show it as the report holds it, after jstr's filter
	note=$(sed -n 's/^"note": "\(.*\)",$/\1/p' "$TMP/report.json")
	if [ -n "$note" ]; then
		ysay "And your note, as it will be sent:"
		printf '        %s\n' "$note" >&3
	fi
	ysay "Not sent: host name, the device's keys and its password, other files. What stands in the"
	ysay "lines and paths above goes as it is, addresses, names and tokens included (v shows them)."
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
		ysay "- for an account the firmware does not have: its name, number and shell, never a password"
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
		ysay "Not sent: host name, the device's keys and its password, the content of any other file."
		ysay "What stands in the lines and paths above goes as it is, addresses, names and tokens included."
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
		say "   ${D}kept switched it back on, with its remote SSH and web access and AstroWarp.${N}"
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
	say "   ${D}kept switched it back on, with its remote SSH and web access and AstroWarp.${N}"
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

# ---------------------------------------------------------------- update
# --update replaces this script by the version that is served now. The new file is used
# only when its signature fits one of the keys below, so that nobody between this device
# and the download can pass something else off as the script: not in the network, and not
# at the service that hands the script out. Each version is signed with the other half of
# such a key when it is published. An older version is refused even with a good signature:
# it could be an old one with known gaps, sent on purpose. The signature is checked with
# usign, the tool OpenWrt checks its package lists with, and only when it is the
# firmware's own. Whatever fails, the script that is here stays as it is.
# Not every firmware has usign. Where it is missing the script says so and what that
# means, and replaces itself only when its user agrees: at the question, or with
# --unsigned where nobody can be asked. A signature that is there and does not fit is
# never passed over.
# The keys: the base64 line of each public key file, separated by spaces. The second is a
# spare whose other half is kept offline, to replace the first if it is lost.
UPDATE_URL=${GL_TRIAGE_UPDATE_URL:-https://app.gl-i.net/csa-2026-01-fix}
UPDATE_KEYS='RWT3i36dVR3XndIzvtu600f1No34ytWkFYphv+5p49dLKtEUUy3IfIDx RWTjqtEa0VPVvTR3x0I/d2cCw3rN4ly+mVAnwgaEzL3j36CPwUTGhqn1'
fetch() {
	if tool_ok curl; then curl -fsSL -m 60 -o "$2" "$1" 2>/dev/null
	elif tool_ok wget; then wget -q -T 60 -O "$2" "$1" 2>/dev/null
	else return 2; fi
}
do_update() {
	local self new sig k ok nv check answer
	self=$0 new=$TMP/update.sh sig=$TMP/update.sig
	section "Update"
	say "   This version   $VERSION, released $RELEASED"
	no() { say "   ${RED}Not updated:${N} $1"; say "   ${D}The script here is unchanged. To get the current one by hand:${N}"; say "   ${D}curl -fsSL $UPDATE_URL -o gl-helper-triage.sh${N}"; }
	[ -n "$UPDATE_KEYS" ] || { no "this version carries no key to check an update with."; return 4; }
	{ [ -f "$self" ] && [ ! -L "$self" ]; } || { no "the script was not started from a file of its own ($self)."; return 4; }
	{ [ -w "$self" ] && [ -w "$(dirname "$self")" ]; } || { no "$self cannot be written."; return 4; }
	check=usign
	if ! command -v usign >/dev/null 2>&1; then
		check=none
		say "   ${YEL}This firmware has no usign, the tool that checks the signature of an update.${N}"
		say "   Without that check only the encrypted connection protects the download: whoever"
		say "   controls the connection, or the service that hands the script out, could send another file."
		if [ "$UNSIGNED" = 1 ]; then
			say "   Going on without the check, as --unsigned says."
		elif [ -t 0 ] && [ -t 3 ]; then
			printf '   %sUpdate without checking the signature? [y/N]%s ' "$B" "$N" >&3
			read -r answer || answer=
			case $answer in y | Y | yes | Yes | YES) ;; *) no "not confirmed."; return 4 ;; esac
		else
			no "the signature cannot be checked here. To update all the same, add --unsigned."
			return 4
		fi
	elif ! tool_ok usign; then
		no "usign on this device is not the firmware's own, so its answer would prove nothing."
		return 4
	fi
	fetch "$UPDATE_URL" "$new"
	case $? in 0) ;; 2) no "neither curl nor wget of the firmware is here to download with."; return 4 ;; *) no "the download failed."; return 4 ;; esac
	if [ "$check" = usign ]; then
		fetch "$UPDATE_URL.sig" "$sig" || { no "no signature is served for the current version yet. Try again in a few minutes."; return 4; }
		ok=0
		for k in $UPDATE_KEYS; do
			printf 'untrusted comment: update key\n%s\n' "$k" >"$TMP/update.pub"
			usign -V -q -m "$new" -p "$TMP/update.pub" -x "$sig" >/dev/null 2>&1 && { ok=1; break; }
		done
		[ "$ok" = 1 ] || { no "the signature does not fit the download. The file was not used."; return 4; }
	fi
	nv=$(sed -n 's/^VERSION=\([0-9][0-9]*\.[0-9][0-9]*\)$/\1/p' "$new" | head -n 1)
	case $(awk -v a="$nv" -v b="$VERSION" 'BEGIN { split(a, x, "."); split(b, y, "."); if (a == "") print "bad"; else if (x[1] + 0 > y[1] + 0 || (x[1] + 0 == y[1] + 0 && x[2] + 0 > y[2] + 0)) print "newer"; else if (x[1] + 0 == y[1] + 0 && x[2] + 0 == y[2] + 0) print "same"; else print "older" }') in
	newer) ;;
	same) say "   ${GRN}This is the current version.${N} Nothing to do."; return 0 ;;
	older) no "the download is version $nv, older than this one. An old version is not taken, even with a good signature."; return 4 ;;
	*) no "the download names no version."; return 4 ;;
	esac
	sh -n "$new" 2>/dev/null || { no "the download does not read as a script."; return 4; }
	cp "$self" "$self.old" 2>/dev/null
	if cat "$new" >"$self.new" 2>/dev/null && mv -f "$self.new" "$self" 2>/dev/null; then
		if [ "$check" = usign ]; then say "   ${GRN}${B}Updated to version $nv.${N} Its signature was checked."
		else say "   ${GRN}${B}Updated to version $nv.${N} ${YEL}Its signature was NOT checked.${N}"; fi
		say "   The version from before is kept as $self.old"
		say "   Run it now: sh $self"
		return 0
	fi
	no "the new file could not be written to $self."
	return 4
}

# ---------------------------------------------------------------- main
if [ "$MODE" = update ]; then do_update; exit $?; fi
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
	collect || { cloud_advice; result_block; finish 4; }
	cloud_advice
	result_block
	[ "$(count IOC)" -gt 0 ] && finish 1
	finish 0
	;;
fix)
	report_body
	collect
	if [ -z "$ARCHIVE" ] || [ ! -s "$ARCHIVE" ]; then
		say "   ${RED}No verified archive, so nothing was changed.${N} Free some space or choose another directory with -o."
		cloud_advice
		result_block
		[ "$(count IOC)" -gt 0 ] && recommend
		finish 4
	fi
	if [ "$(count_gl)" = 0 ]; then
		fix
		cloud_advice
		result_block
		# IOCs that --fix leaves (older backdoor, rtty_conf, traces of a command): exit 1, as --check
		[ "$(count IOC)" -gt 0 ] && { recommend; finish 1; }
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
		rtty_note
		result_link 3
		recommend
		finish 3
	fi
	if [ "$(count_bd)" -gt 0 ]; then
		grep -E "^IOC${TAB}(backdoor-|rtty-server${TAB})" "$FIND" | awk -F '\t' '{printf "   still present: %s %s %s\n", $2, $3, $4}' >&3
		say "   ${RED}Verdict: gl-helper indicators removed, the older backdoor is STILL THERE${N}"
		rtty_note
		result_link 3
		recommend
		finish 3
	fi
	# rtty_conf still naming the attacker's server: not done, whatever else --fix removed
	if has_ioc rtty-server; then
		grep "^IOC${TAB}rtty-server${TAB}" "$FIND" | awk -F '\t' '{printf "   still present: %s %s %s\n", $2, $3, $4}' >&3
		say "   ${RED}Verdict: remediation INCOMPLETE - the other gl-helper indicators were removed${N}"
		rtty_note
		[ "$FIXRC" != 0 ] && say "   ${YEL}Some steps also reported errors, see above.${N}"
		result_link 3
		recommend
		finish 3
	fi
	if [ "$FIXRC" != 0 ]; then say "   ${YEL}Verdict: IOCs gone, but some steps reported errors${N}"; result_link 3; recommend; finish 3; fi
	say "   ${GRN}${B}Verdict: no gl-helper indicators left${N}"
	has_ioc cloud-command && say "   ${D}The state file /etc/mp_ip_mapping_info was left in place: it only shows that the command ran.${N}"
	has_ioc installer-trace && say "   ${D}The installer's link to busybox was left in place: it only shows that the installer was at work.${N}"
	result_link 2
	recommend
	finish 2
	;;
esac
