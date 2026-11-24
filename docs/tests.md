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

The tests point the script at a local address with `GL_TRIAGE_REPORT_URL`,
`GL_TRIAGE_RESULT_URL` and `GL_TRIAGE_UPDATE_URL`. Since 2.55 the script takes these
only when they name this machine (`http://127.0.0.1`), and `GL_TRIAGE_ATTACK_UNTIL` only
when it moves the end of the attack's window later (a year from 2100 on): a value set on
a device can neither send the report somewhere else nor make a trace count less.
