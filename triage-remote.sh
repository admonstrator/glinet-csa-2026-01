#!/usr/bin/env bash
# triage-remote.sh - run gl-helper-triage.sh on a GL.iNet KVM or OpenWrt router over SSH
#
#   ./triage-remote.sh [--fix] [--lookup | --no-lookup] [-p PORT] [-i KEY] [-o DIR] root@DEVICE [root@DEVICE2 ...]
#
# The device has no terminal here, so it never asks. --lookup lets steps 1 and 2 ask the
# community list about the files listed for review (fingerprints only, docs/lookup.md;
# each device asks twice); --no-lookup leaves even the hint about it out. --fix does not
# remove a file the list knows as malware: such a device ends as "remediation incomplete".
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
fix=0 outdir=./evidence ssh_opts=() lookup=()

usage() { sed -n '2,20s/^# \{0,1\}//p' "$0"; }

while [[ $# -gt 0 ]]; do
	case $1 in
	--fix) fix=1 ;;
	--lookup | --no-lookup) lookup=("$1") ;;
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

# The device has no terminal on its side, so tell it when ours can show colors.
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

	# kept, to see whether the fingerprint check found known malware: --fix does not know it
	run --check $color ${lookup[@]+"${lookup[@]}"} | tee "$ctl/check.txt"
	rc=${PIPESTATUS[0]}
	lb=0
	grep -q 'lookup-bad: a file listed for review' "$ctl/check.txt" && lb=1
	lbmsg="!! $target: --fix does not remove the file the community list knows as malware: reinstall the firmware without keeping settings."
	if (( rc >= 4 || rc == 255 )); then
		echo "!! $target: check failed (exit $rc)"; note 4; continue
	fi

	ts=$(date -u +%Y%m%dT%H%M%SZ)
	name=$outdir/gl-triage-${target#*@}-$ts.tar.gz
	echo
	echo "-- pulling evidence to $name"
	run --archive --stdout ${lookup[@]+"${lookup[@]}"} >"$name" 2>"$name.log"
	arc=$?
	# with --lookup step 2 asks again: known malware it finds counts as well, even when step 1
	# had no answer (review of 2.60)
	grep -q 'lookup-bad: a file listed for review' "$name.log" 2>/dev/null && lb=1
	(( arc == 1 && rc == 0 )) && rc=1
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
		(( lb )) && echo "$lbmsg"
		note 1
		continue
	fi

	echo
	echo "-- remediating $target"
	run --fix $color
	frc=$?
	# no connection: an error like any other, within the exit codes above
	(( frc == 255 )) && frc=4
	# --fix does not know the file the list knows as malware: never "remediated" then
	if (( lb )); then echo "$lbmsg"; (( frc < 3 )) && frc=3; fi
	note "$frc"
	case $frc in
	2) echo "== $target: remediated, no IOC left" ;;
	3) echo "!! $target: remediation incomplete, see output above" ;;
	*) echo "!! $target: fix exited with $frc" ;;
	esac
done

exit "$worst"
