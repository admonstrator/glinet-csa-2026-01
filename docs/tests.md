# Tests

Part of the [gl-helper triage script](../README.md).

The tests mount real overlay filesystems in an unprivileged user namespace, plant an
infection and run check, archive and fix:

```sh
unshare -rm bash tests/run-tests.sh
KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
```

On a device the script runs under busybox, whose tools differ in details from those of a
desktop Linux. The tests can give the script its own shell and tools while they keep
the machine's:

```sh
mkdir bb && for a in $(busybox --list); do ln -s "$(command -v busybox)" bb/$a; done
TRIAGE_SH="busybox sh" TRIAGE_PATH="$PWD/bb" unshare -rm bash tests/run-tests.sh
```

GitHub runs the tests on every push, once with the machine's tools and once with busybox
only, together with the tests of the worker and dashboard
([workflow](../.github/workflows/tests.yml)).

Without `KVM_LOWER` only the OpenWrt scenarios run (synthetic base image). The script
was also run in check and archive mode on a GL.iNet router with firmware 4.11
(OpenWrt 25.12).

The tests of the [fingerprint check](lookup.md) run the script as on a device, in a
chroot that holds only a static busybox, and answer it from a small `python3` server on
`127.0.0.1`: with each of the three words, with an error, and with answers broken on
purpose (another random number, a hash that was not asked, a wrong word, a line missing,
added or out of order, control characters, escape sequences, bytes above 0x7e, more than
8192 bytes, several megabytes, `\r\n`, no line break at the end, an answer that trickles
in for a minute). They compare the request byte for byte with one built from the report's
own `review_items`, check that accounts are never asked, that busybox's own `wget` is
never used over HTTPS, and that known malware next to a trace of the attack still reads
`INFECTED`. The question on a terminal is tested through `script` where that gives one,
and Ctrl-C at the question through a terminal `python3` opens. Without `python3` or a
static busybox these tests are skipped.

The tests point the script at a local address with `GL_TRIAGE_REPORT_URL`,
`GL_TRIAGE_RESULT_URL`, `GL_TRIAGE_UPDATE_URL` and `GL_TRIAGE_LOOKUP_URL` (since 2.60).
Since 2.55 the script takes these only when they are an address on this machine,
`http://127.0.0.1/...` or `http://127.0.0.1:PORT/...`, made of letters, digits and
`:/._?=&%-` alone (so that
`http://127.0.0.1:1@host/` names no other host), and `GL_TRIAGE_ATTACK_UNTIL` only
when it moves the end of the attack's window later (a year from 2100 on): a value set on
a device can neither send the report somewhere else nor make a trace count less.
