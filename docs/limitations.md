# Limitations

Part of the [gl-helper triage script](../README.md).

- Only known indicators are remediated. A different implant variant, or other changes
  an attacker made, may remain. Read the `REVIEW` items.
- Without a base image (`/rom`) the results are less precise and the tools come
  from `$PATH`. Without an overlay as well, autostart places and the firewall's start
  scripts are read only for commands that start the malware or fetch from its servers;
  other changes to the firmware cannot be listed (since 2.55).
- A copy of the script saved on the device names every indicator it searches for. Since
  2.38 such a copy is not counted as a trace: in `/etc/config` or an autostart directory
  it is listed as `REVIEW script-copy`, in a directory of programs such as `/usr/bin` as
  `REVIEW new-binary` (since 2.55; before, a copy there was taken for a replaced
  `netstat`). Earlier versions called a device infected for a copy in `/etc/config` or an
  autostart directory. A copy saved under the name of a busybox tool replaces that tool
  and counts as `IOC applet-hijack` like any other file there.
  Since 2.55 a copy is known by its whole shape, and a file that starts the malware, keeps
  its files, holds its crontab line or fetches from a server of the older backdoor counts
  as a trace whatever lines it carries ([#25](https://github.com/admonstrator/glinet-csa-2026-01/issues/25)).
  The shape of a copy, or of compiled Lua, no longer keeps a file from being read for a
  start of the malware.
- The script reads shell the way `sh` would in the common cases, not in every case. A
  command that is put together while it runs (from pieces, from another file, from text
  that `eval` builds) is not seen. A variable counts only where the same file sets it.
  Text in single quotes that runs over more than 2,000 lines or 64 KB, and a file that
  is still over 1 MB without its comments and repeated empty lines, are read line by line: there
  a start that only the lines around it make one can go unseen, and a line that only
  looks like a start can count as one (since 2.55, so that such a file does not hold the
  check up for minutes).
- The script only reads regular files. A named pipe or a link into `/proc` in a place it
  scans is not opened, because reading one could block the run for good; where such a
  thing stands in for `rc.local` or the root crontab it is listed as `REVIEW`.
- `--changes` compares file by file, and only what the files hold. Where the overlay
  replaced a whole directory, the base image's files in it are not listed as removed. A
  file whose mode or owner changed but not its content is not listed (`chmod 4755
  /bin/busybox` does not show).
- The script cannot see anything outside the device, such as changes on an attached
  computer or on the cloud account.
- The [fingerprint check](lookup.md) (since 2.60) knows only what the community list
  knows. A file it does not know, or has as probably safe, is still yours to judge, and a
  file that differs in a single byte from a known one is not known. It asks only about
  files listed for review that the script could read in full, up to 64 MiB each.
