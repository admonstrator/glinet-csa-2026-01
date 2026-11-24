#!/usr/bin/env bash
# triage-remote.sh - run gl-helper-triage.sh on a GL.iNet KVM or OpenWrt router over SSH
#
#   ./triage-remote.sh [--fix] [-p PORT] [-i KEY] [-o DIR] root@DEVICE [root@DEVICE2 ...]
#
# Per device:
#   1. check     read-only detection, report printed here
#   2. archive   evidence tar.gz streamed to this machine, verified, sha256 written
#   3. fix       only with --fix, only if IOCs were found, only after step 2 succeeded;
#                the device keeps its own copy of the archive in /tmp as well, and the
#                fix ends with a check of its own (its verdict is the device's result)
#
# Exit code: highest of the device results (0 clean, 1 infected, 2 fixed,
# 3 fix incomplete, 4 error).

set -uo pipefail
# the evidence can hold keys and passwords (--with-secrets): for this user only
umask 077

here=$(cd "$(dirname "$0")" && pwd)
script=$here/gl-helper-triage.sh
fix=0 outdir=./evidence ssh_opts=()

usage() { sed -n '2,15s/^# \{0,1\}//p' "$0"; }

while [[ $# -gt 0 ]]; do
	case $1 in
	--fix) fix=1 ;;
	-p | -i | -o)
		[[ $# -ge 2 && -n $2 ]] || { echo "$1 needs a value" >&2; exit 4; }
		case $1 in -p) ssh_opts+=(-p "$2") ;; -i) ssh_opts+=(-i "$2") ;; -o) outdir=$2 ;; esac
		shift ;;
	-h | --help) usage; exit 0 ;;
	-*) echo "unknown option: $1" >&2; exit 4 ;;
	*) break ;;
	esac
	shift
done
[[ $# -ge 1 ]] || { usage; exit 4; }
# a target that starts with - would be read by ssh as one of its options
for target in "$@"; do
	[[ $target != -* ]] || { echo "not a device: $target" >&2; exit 4; }
done
[[ -r $script ]] || { echo "missing $script" >&2; exit 4; }
mkdir -p "$outdir"

# The device has no terminal on its side, so tell it when ours can show colours.
color=
[[ -t 1 && -z ${NO_COLOR:-} ]] && color=--color

# short, so that the control socket's path stays under the 104 bytes macOS allows;
# mktemp -d alone gives a long path in /var/folders there
ctl=$(mktemp -d /tmp/glt.XXXXXX) || exit 4
# shellcheck disable=SC2154 # $s is the loop variable inside the trap string
trap 'for s in "$ctl"/cm-*; do [[ -S $s ]] && ssh -o ControlPath="$s" -O exit x 2>/dev/null; done; rm -rf "$ctl"' EXIT

worst=0
note() { (( $1 > worst )) && worst=$1; }

for target in "$@"; do
	echo
	echo "################ $target"
	cm=(-o ControlMaster=auto -o "ControlPath=$ctl/cm-%C" -o ControlPersist=120 -o ConnectTimeout=10)
	# each word quoted for the remote shell
	# shellcheck disable=SC2029 # the options are meant to reach the remote sh
	run() { ssh ${ssh_opts[@]+"${ssh_opts[@]}"} "${cm[@]}" "$target" "sh -s --$(printf ' %q' "$@")" <"$script"; }

	run --check $color
	rc=$?
	if (( rc >= 4 || rc == 255 )); then
		echo "!! $target: check failed (exit $rc)"; note 4; continue
	fi

	ts=$(date -u +%Y%m%dT%H%M%SZ)
	name=$outdir/gl-triage-${target#*@}-$ts.tar.gz
	echo
	echo "-- pulling evidence to $name"
	run --archive --stdout >"$name" 2>"$name.log"
	arc=$?
	if (( arc >= 4 )) || ! gzip -t "$name" 2>/dev/null || ! tar -tzf "$name" >/dev/null 2>&1; then
		echo "!! $target: evidence archive missing or corrupt (exit $arc, see $name.log)"
		note 4
		continue
	fi
	# sha256sum on Linux, shasum on macOS; the same line either way
	if command -v sha256sum >/dev/null 2>&1; then
		(cd "$outdir" && sha256sum "${name##*/}" >"${name##*/}.sha256")
	else
		(cd "$outdir" && shasum -a 256 "${name##*/}" >"${name##*/}.sha256")
	fi
	[[ -s $name.sha256 ]] || { echo "!! $target: could not compute the archive's sha256"; note 4; continue; }
	echo "   $(cut -d ' ' -f1 "$name.sha256")  $(du -h "$name" | cut -f1)"

	if (( rc == 0 )); then note 0; continue; fi
	if (( fix == 0 )); then
		echo "!! $target: IOCs found. Evidence saved. Re-run with --fix to remediate."
		note 1
		continue
	fi

	echo
	echo "-- remediating $target"
	run --fix $color
	frc=$?
	note "$frc"
	case $frc in
	2) echo "== $target: remediated, no IOC left" ;;
	3) echo "!! $target: remediation incomplete, see output above" ;;
	*) echo "!! $target: fix exited with $frc" ;;
	esac
done

exit "$worst"
