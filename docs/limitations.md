# Limitations

Part of the [gl-helper triage script](../README.md).

- Only known indicators are remediated. A different implant variant, or other changes
  an attacker made, may remain. Read the `REVIEW` items.
- Without a base image (`/rom`) the results are less precise and the tools come
  from `$PATH`.
- A copy of the script saved on the device names every indicator it searches for. Since
  2.38 such a copy is listed as `REVIEW script-copy` and not counted as a trace; earlier
  versions called a device infected for a copy in `/etc/config` or an autostart directory.
- The script only reads regular files. A named pipe or a link into `/proc` in a place it
  scans is not opened, because reading one could block the run for good; where such a
  thing stands in for `rc.local` or the root crontab it is listed as `REVIEW`.
- The script cannot see anything outside the device, such as changes on an attached
  computer or on the cloud account.
