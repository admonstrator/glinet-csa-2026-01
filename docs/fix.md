# What `--fix` Does

Part of the [gl-helper triage script](../README.md).

1. Writes and verifies the evidence archive. No archive, no changes.
2. Stops implant processes (SIGSTOP all, then SIGKILL), each only while its number still
   belongs to the process that was found (same start time).
3. Removes `/etc/glinet/.cache/` and `/etc/config/.gl/`, and a fallback directory of the
   installer when one of the malware's files was found in it.
4. Resets `rc.local` and the root crontab to the base image version, or removes them
   if the base image has none, but only when the malware itself was found (its files,
   autostart entries, processes, connections to its servers or the `gl-agent` key). The
   previous versions are in the archive.
5. Restores replaced applets from the base image and removes other autostart files that
   start the implant, including OpenWrt `rc.d` links to removed init scripts.

   Where there is no base image to compare with (a KVM, which has no `/rom`, or `--root`
   without `--lower`), steps 4 and 5 take out only the malware's lines, as in the
   firewall's start script, and leave a file without such a line as it is: the file may
   be the firmware's own, such as `/etc/init.d/rcS` (since 2.54).
6. Removes only the implant's lines (and lines that fetch from its servers) from sysupgrade
   keep lists, from the running crontab `/tmp/gl_crontabs/root`, from the firmware's
   crontab files in `/etc/gl_crontabs/crontabs.d`, and, for a key named `gl-agent`, from
   `authorized_keys`. In `/etc/firewall.user` and `/etc/firewall.d` it replaces them with
   `:` (see [Firewall](indicators.md#firewall)).
   `/etc/rtty_conf` is not changed: the script cannot tell what belongs there. When it names
   the attacker's server, `--fix` says so and exits 1 if that was the only finding, or 3
   after removing the others. A factory reset or reflash fixes the file.
7. Deletes the firewall rule that the command of the user-reported remote shell left
   behind. Other firewall rules and the firewall configuration are not changed.
8. Restarts cron and checks again.

Changes go through the merged root filesystem, so the overlay stays consistent while it
is mounted. `REVIEW` items are never touched (apart from the malware's lines in the
firewall's start script, see step 6), and neither is the
[older backdoor](indicators.md#the-older-backdoor-urandom_seed--ulogd): with only that on the device
`--fix` changes nothing and exits 1, with both it removes the gl-helper indicators and
exits 3.
