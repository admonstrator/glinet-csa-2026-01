# Limitations

Part of the [gl-helper triage script](../README.md).

- Only known indicators are remediated. A different implant variant, or other changes
  an attacker made, may remain. Read the `REVIEW` items.
- Without a base image (`/rom`) the results are less precise and the tools come
  from `$PATH`. Without an overlay as well, autostart places and the firewall's start
  scripts are read only for commands that start the malware or fetch from its servers;
  other changes to the firmware cannot be listed (since 2.55).
- A copy of the script saved on the device names every indicator it searches for. Since
  2.38 such a copy is listed as `REVIEW script-copy` and not counted as a trace; earlier
  versions called a device infected for a copy in `/etc/config` or an autostart directory.
  Since 2.55 a copy is known by its whole shape, and a file that starts the malware, keeps
  its files, holds its crontab line or fetches from a server of the older backdoor counts
  as a trace whatever lines it carries ([#25](https://github.com/admonstrator/glinet-csa-2026-01/issues/25)).
- The script only reads regular files. A named pipe or a link into `/proc` in a place it
  scans is not opened, because reading one could block the run for good; where such a
  thing stands in for `rc.local` or the root crontab it is listed as `REVIEW`.
- The script cannot see anything outside the device, such as changes on an attached
  computer or on the cloud account.
