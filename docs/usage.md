# Options and Report

Part of the [gl-helper triage script](../README.md).

| Option | Effect |
|---|---|
| `--check` (default) | Read-only detection and report |
| `--archive [-o DIR]` | Report plus evidence archive in `DIR` (default `/tmp`) |
| `--archive --stdout` | Evidence archive to stdout, log to stderr |
| `--fix [-o DIR]` | Archive first (changes nothing and exits 4 if that fails), then remediate and re-check |
| `--changes` | List every file that differs from the base image, without checking anything. See [List of changes](#list-of-changes). |
| `--report`, `--no-report`, `--show-report` | Send the anonymous report without asking, never offer it, or print it without sending. See [Anonymous report](anonymous-report.md). |
| `--no-device-id` | Leave the device ID out of the report. |
| `--note TEXT` | Add a note of your own to the report, for example where it comes from or whether the device was checked before or after a cleanup. At most 120 characters; only letters, digits, spaces and `._:/+@=,()-` are kept. |
| `--with-secrets` | Keep the private keys and passwords that the script would otherwise take out of the evidence archive. |
| `--color`, `--no-color` | Force or disable colored output. By default colors are used only on a terminal; `NO_COLOR=1` also turns them off. |

Exit codes: `0` clean, `1` indicators found, `2` fixed and clean, `3` fix incomplete,
`4` error.

Every run ends with a section on GoodCloud: when it is on, or cannot be read, the script
says to switch GoodCloud and AstroWarp off and gives the command. The attack came in
through GoodCloud, and according to reports of November 22 devices are still being hit.

The head of the report appears at once. It includes whether GoodCloud is switched on
now, with the version of its client; that is the setting at the time of the check, not
during the attack. While the checks run, a line shows which of the
ten steps is in progress. The report groups its findings by label and ends with a summary and a verdict. Under a
clean verdict on a running device the script says when the device last started. If that
was on or after November 19, 2026, it adds that the result says little about the time
before: a remote shell and what it left in memory are gone after a restart, and on a KVM
a firmware update can have removed the malware's files. The copy
in the evidence archive is always plain text.

Findings are labeled:

- `IOC`: a known indicator. `--fix` removes it.
- `PERSIST`: `rc.local` or root crontab in the overlay without an implant reference.
  `--fix` resets it only when the malware itself was found (its files, autostart entries,
  processes, connections to its servers or the `gl-agent` key), like the vendor cleanup. With nothing but traces of the remote shell
  (its process, pipe, connection, the firewall rule) both files stay as they are.
- `REVIEW`: unusual change. Archived and reported, never modified. The one exception is
  the malware's own lines in `/etc/firewall.user` and `/etc/firewall.d` (see [Firewall](indicators.md#firewall)).
- `INFO`: context, for example files installed by a package.

Below the findings the report lists, under "Credentials on this device", the keys and VPN
profiles stored on the device: root's SSH client keys with their fingerprint, WireGuard
and AmneziaWG private keys of the GL.iNet client and server, OpenVPN client profiles,
the ZeroTier identity and the Tailscale state. It shows names
and counts, never the content. These are not findings: they are listed with or without
indicators and are never part of the anonymous report. Other passwords and tokens in the
configuration are not listed.

## List of changes

`--changes` lists every file in the overlay that differs from the firmware's base image
(`/rom`), so you can see what has been written to the device since the firmware was
installed:

```sh
sh gl-helper-triage.sh --changes > /tmp/changes.txt
```

Each line gives the kind of change, the time the file was last written (UTC) and its
path; a link also shows where it points:

```
new      2026-11-20 21:03:11  /etc/config/.gl/watch.sh
changed  2026-11-20 21:03:14  /etc/rc.local
removed  2026-11-21 08:12:40  /etc/init.d/old-service
changed  2026-11-20 21:03:15  /usr/bin/netstat -> /tmp/n
```

- `new`: not in the base image. `changed`: differs from it. `removed`: deleted from it.
- `written`: there is an overlay but no base image to compare with, so new and changed
  files cannot be told apart.
- `odd-name`: a name with a line break in it, shown with `?` in its place. For a directory
  with such a name the directory is listed, not the files in it.

Copies of the base image's files that the overlay holds unchanged are left out. On a
device in use the list runs to hundreds or thousands of lines: settings, installed
packages, logs. It is not a finding and not a verdict: the script judges nothing here,
writes no archive and sends no report. Anyone with root can set a file's time, and a
year before 2020 means the clock was not set yet. Control characters in names are shown
as `?`, so a file name cannot change your terminal. A directory the overlay hides as a
whole (an opaque directory) does not show the base image's files in it as removed.

Without an overlay but with a base image, the running system is compared with the base
image. With neither, the script says that there is nothing to compare with and exits
with `4`.
