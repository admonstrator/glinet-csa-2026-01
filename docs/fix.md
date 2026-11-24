# What `--fix` Does

Part of the [gl-helper triage script](../README.md).

1. Writes and verifies the evidence archive. No archive, no changes. A file already
   there under the archive's name is never written over; a second run in the same
   second gets a number in its name (since 2.55).
2. Holds every `crond` until step 8, so that cron cannot start the malware again while
   its files go (since 2.55). Stops implant processes (SIGSTOP all, then SIGKILL), each
   only while its number still belongs to the process that was found (same start time).
3. Removes `/etc/glinet/.cache/` and `/etc/config/.gl/`, and a fallback directory of the
   installer when one of the malware's files was found in it.
4. Resets `rc.local` and the root crontab to the base image version, or removes them
   if the base image has none, but only when the malware itself was found (its files,
   autostart entries, processes, connections to its servers or the `gl-agent` key). The
   previous versions are in the archive. An `rc.local` that differs from the base image
   only by lines the firmware writes itself (`gl_util.sh`, `remount_ubifs`) is left as it
   is (since 2.55).
5. Restores replaced applets from the base image and removes other autostart files that
   start the implant, including OpenWrt `rc.d` links to removed init scripts.

   Where there is no base image to compare with (a KVM, which has no `/rom`, or `--root`
   without `--lower`), steps 4 and 5 take out only the malware's lines, as in the
   firewall's start script, and leave a file without such a line as it is: the file may
   be the firmware's own, such as `/etc/init.d/rcS` (since 2.54). A replaced applet is
   removed and, where busybox has that applet, put back as a link to busybox (since
   2.55): the overlay hid the firmware's own link as well.

   A file in an autostart place with a line break in its name that starts the malware is
   removed; other files with such names are left (since 2.55). A file of the same name
   without the line break, the owner's, stays as it is.
6. Removes only the implant's lines (and lines that fetch from its servers) from sysupgrade
   keep lists, from the running crontabs `/tmp/gl_crontabs/root` and
   `/var/spool/cron/crontabs/root`, from the firmware's
   crontab files in `/etc/gl_crontabs/crontabs.d`, and, for a key named `gl-agent`, from
   `authorized_keys`. In `/etc/firewall.user` and `/etc/firewall.d` it replaces them with
   `:` (see [Firewall](indicators.md#firewall)).
   `/etc/rtty_conf` is not changed: the script cannot tell what belongs there. When it names
   the attacker's server, `--fix` says so and exits 1 if that was the only finding, or 3
   after removing the others. A factory reset or reflash fixes the file.
7. Deletes the firewall rule that the command of the user-reported remote shell left
   behind. Other firewall rules and the firewall configuration are not changed.
8. Lets cron go on, tells each crontab directory that root's crontab changed
   (`cron.update`, which busybox crond reads within a minute, GL.iNet's own crond for
   `/tmp/gl_crontabs` too), restarts cron and checks again.

Changes go through the merged root filesystem, so the overlay stays consistent while it
is mounted. With `--root`, a path is left alone when a directory on its way is a link
that leads out of the root (an image's `etc/glinet -> ../../victim`): `--fix` says so and
exits 3, and the archive names it in `files/NOT-COPIED.txt` instead of copying what lies
outside (since 2.55). `REVIEW` items are never touched (apart from the malware's lines in the
firewall's start script, see step 6), and neither is the
[older backdoor](indicators.md#the-older-backdoor-urandom_seed--ulogd): with only that on the device
`--fix` changes nothing and exits 1, with both it removes the gl-helper indicators and
exits 3.
