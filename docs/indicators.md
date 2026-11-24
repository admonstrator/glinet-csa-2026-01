# What the Script Looks For

Part of the [gl-helper triage script](../README.md).

The indicators come from the cleanup GL.iNet shipped in RM1PE firmware **1.10.2**
(`/etc/init.d/S08overlayfs`, built 2026-11-21). At boot it scrubs the writable overlay
layer when one of these marker files exists:

| Marker files (any one triggers) | Persistence removed together with them |
|---|---|
| `/etc/glinet/.cache/gl-helper` | `/etc/glinet/.cache/` |
| `/etc/glinet/.cache/gb` | `/etc/config/.gl/` |
| `/etc/config/.gl/gl-helper` | `/etc/rc.local` |
| `/etc/config/.gl/gb` | `/etc/crontabs/root` |
| | `/usr/bin/netstat` (a replaced, trojanized netstat) |

The vendor cleanup only runs when a marker file is present and only touches this set.
This script also detects:

- what the malware's installer leaves besides the files above. A forum user read the
  installer itself ([post 90](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056/90)
  of the notice's thread, an analysis made with an AI tool; the names and addresses in
  it decode as stated, we have not verified the rest):
  - the directories it falls back to when it cannot write to the first one:
    `/etc/gl_nas/.cache`, `/userdata/.gl`, `/overlay/.gl`, `/tmp/.gl`,
  - its other files in any of these directories: `watch.sh`, `run.sh`, `wake.sh`,
    `boot.sh`, `rtty_keep.sh`, `eco`, `eco.tmp`, `node`, `.u`, `.wc`, `install.log`, and
    since 2.55 `.rk1` (a loop that watches `/etc/rtty_conf`), `gl-helper.dl` (a download
    in progress) and `rn`, `wv` (older builds), as a reader of version 63 of the installer
    describes them ([#25](https://github.com/admonstrator/glinet-csa-2026-01/issues/25)).
    A command that starts one of them counts like a start of `gl-helper`, and a keep list
    entry for one of the directories counts with or without a trailing slash,
  - its watchdog line in the running crontab `/tmp/gl_crontabs/root` and, since 2.55, in
    busybox crond's own `/var/spool/cron/crontabs/root` (`cron-ref`),
  - `/etc/rtty_conf` set to the attacker's server (`rtty-server`). Set to another server,
    where the file is not the firmware image's, it is `REVIEW` (`rtty-conf`, since 2.55):
    the installer can be told to use any server,
  - a key named `gl-agent` in `authorized_keys` (`ssh-key`),
  - a fetch from its servers `65.20.71.131`, `66.245.219.252` or `gl-inet.top`: a command
    in an autostart file, in `rc.local`, in a crontab or in a running process that names
    one of them together with a tool that fetches or talks to a server (`wget`, `curl`,
    `nc`, `ssh`, `rtty` and the like) or with a pipe into a shell, or a program on a RAM
    disk (`/tmp`, `/var`, `/run`, `/dev/shm`) that gets one of them as an argument. One
    user's network logs and the installer name the same servers,
  - a process that runs one of the malware's files: as the program, under its name, as
    the script a shell runs, in `sh -c` or in a loop,
  - the replaced `netstat`: a two-line script that calls the real one and hides the
    connections to its server,
  - the malware's program or its downloader under any name: both are wrapped in a packer
    that names itself in clear text, "Node hardened executable packer"
    ([post 94](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056/94)).
    A file in the overlay that holds this text and starts like a program is a `marker`,
    unless a package installed it; `--fix` removes that file. Since 2.55 the malware's
    own directories are searched the same way, also those outside the overlay's upper
    layer (`/overlay/.gl`, `/userdata/.gl`, `/tmp/.gl`), and a running program counts
    as well: one that runs from such a file, or from a deleted file or a RAM disk and
    holds this text or a posted hash, is an `IOC` process that `--fix` stops,
  - a marker file whose sha256 is one that forum users posted for `gl-helper`, `gb`, the
    downloader or `ni.sh` ([post 101](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056/101),
    [post 153](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056/153))
    is noted as such. A different hash clears nothing: the operator can rebuild at any time.

  Naming is not running. Since 2.53 the script counts a server or a path of the malware
  only where a command uses it ([#20](https://github.com/admonstrator/glinet-csa-2026-01/issues/20)):

  - a command that only checks whether the server answers and keeps nothing (`nc -z`,
    `wget --spider`, `curl -I`, output to `/dev/null`) is not a fetch,
  - an autostart file that only blocks the server (`-j DROP`, `-j REJECT`, a route to
    nowhere, a hosts entry to a null address) is `INFO` (`server-block`) and stays,
  - any other file that names the server is `REVIEW` (`server-ref`) and stays,
  - a command that only names a path of the malware, such as `rm -rf /etc/config/.gl`,
    `pgrep -f gl-helper` or `less` on its log, is `REVIEW` (`path-ref`) and is not stopped,
  - comments never count, and `gl-helper` counts only as a whole word: a cron job that
    starts `gl-helper-triage.sh` is not a trace,
  - in `rc.local` and the root crontab such a line counts as your own change (`PERSIST`,
    see the labels in the [README](../README.md)).

  The script reads commands roughly as `sh` does: quotes, line continuations, `;`, `&&`
  and `|`. Where a line can be read two ways, it checks both. What `echo` or `printf`
  writes into a crontab or `rc.local` is read as a command too (since 2.54). Since 2.55
  it also reads quotes that go on over several lines, here-documents that a shell or
  crontab reads, what `$( )` runs anywhere on a line, the program behind `xargs`,
  `flock`, `trap`, `su -c` and `find -exec`, a program or server held in a variable that
  the same file sets, a command string run by `sh -c "$CMD"` or `eval`, and a file that
  the same lines write and then run, `( ...; prog ) &` and `( ...; prog ) > /dev/null`,
  `sh<<EOF` without a blank,
  here-documents with a quoted end word (`<< "E O F"`) and `{ crontab -l; echo ...; } |
  crontab -`. Host names count in any case (`GL-INET.TOP`), and `//` or `/./` in a path
  changes nothing. Quoted text that is only data does not make a command: the comment of
  a firewall rule and what `logger` writes to the log, so `--comment "block nc shell"`
  next to the attacker's address is a block, not a download, unless the same file makes
  `logger` or `comment` a function or an alias of its own. What `echo` or `printf`
  write still counts, because a group or a loop around them can send it to `sh` or into
  a file. The patterns of a `case` on one line are no commands either. The exact rules
  are in the script and its tests.

  `crond -i /tmp/.log`, the process GL.iNet's check looks for, is the name the malware
  gives its own process.
- a `netstat` link to busybox that was made between November 19 and 21 (`installer-trace`;
  before 2.55 from November 20: a forum user recorded a KVM taken over on November 19).
  The anonymous reports show it on KVMs, always made on the evening of the attack, on
  some next to the malware's files and on others with nothing else left. With only this,
  the verdict is `ATTACKED`: the installer was at work, its files are gone. A link made
  later is an owner's repair as often as not and is listed as `REVIEW` (since 2.55),
- a link in a tool directory that the firmware does not have, for example a new
  `/usr/bin/netstat` (`REVIEW`),
- scripts in `/etc/udhcpc.user.d`, which the router runs on every DHCP event (`REVIEW`),
- a file `/tmp/.lp` (`REVIEW`): a command the attacker sent on November 20 tried to end a
  program of that name along with the remote shell. None has been seen on a device so far
  ([RemoteToHome](https://github.com/RemoteToHome-io/gl-security-incident-2026)),
- files `/tmp/rc.local.bak`, `/tmp/.bt`, `/tmp/.wl`, `/tmp/.p` and `/tmp/.r` (`REVIEW`,
  since 2.55): names the installer and its scripts use in `/tmp`, by the same reader of
  the installer. They are short enough to be something else, and gone after a restart,
- the name `gl-inet.top` in `/etc/rtty_conf`, and a fetch from it as above. It is in the
  malware's helper as a fallback server (`gl-inet.top:8899`), so it counts like the two
  addresses,
- connections to the attacker's server that are attempted but not answered: the server
  was suspended on November 21, so a shell loop that still runs never gets through,
- Tailscale from the [community Tailscale updater](https://github.com/Admonstrator/glinet-tailscale-updater)
  is not counted as a change (`INFO updater-file`). The script recognizes it without
  running it: the uncompressed build by its version string (`tiny.by.admon`), the
  compressed one when the updater's own traces are on the device. Otherwise a replaced
  `tailscaled` is `REVIEW`, and `tailscaled --version` tells you whose it is,
- busybox/coreutils applets in the overlay that were replaced by a foreign regular file
  (for example `netstat`), unless a package (apk/opkg) installed the file,
- running processes started from implant paths or from a replaced applet,
- autostart and config files that reference implant paths: crontabs, `rc.local`, init
  scripts, hotplug, profile, and **sysupgrade keep lists** (an entry there makes the
  implant survive a firmware update with "keep settings"),
- implant persistence even when the marker files were deleted,
- a link in an autostart place that leads to a file of the malware, such as
  `/etc/rc.d/S98x -> /etc/config/.gl/boot.sh` (`persist-ref`, since 2.55),
- a file in an autostart place with a line break in its name (since 2.55). Such a name
  is shown with `?` for the line break. The file is read: when it starts the malware it
  is `IOC persist-ref` and `--fix` removes it, otherwise it is `REVIEW odd-name`,
- a tool in place of a busybox applet that is neither a program nor a script, although
  the list of packages names a package for it (`REVIEW applet-replaced`, since 2.55):
  the list lies in the overlay as well and can be written like any other file,
- on a running device, an overlay whose layer of changes cannot be seen because
  something is mounted over it (`REVIEW overlay-hidden`, since 2.55). The check then
  reads the running system as it does without an overlay.

## Running processes

On 2026-11-21 GL.iNet posted a [quick check for routers](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070):
a router is under attack when `ps | grep tmp` shows a process `crond -i /tmp/.log`. The
script runs the same check and reports the process as `IOC`.

There are three reports of a remote root shell on GL-AXT1800 routers (firmware 4.8.3):
two from forum users (kosrkosr and TakashiSasaki) and one from
[RemoteToHome Consulting](https://github.com/RemoteToHome-io/gl-security-incident-2026), found on one of its own routers. It is a loop around a
pipe at `/tmp/f` that connects `/bin/sh -i` through `nc` to `170.39.226.219`, on a
different port each time. Where it was measured, the shell started at about 21:40 UTC on
2026-11-20. GL.iNet's indicator process was not running on RemoteToHome's router.

RemoteToHome read the code of the GoodCloud client taken from that router
(`gl-sdk4-cloud`): a cloud command for SD-WAN IP mapping puts an address into an
`iptables` command without checking it. It reports that this runs whether or not
AstroWarp is enabled, and that the same code is in the 4.8.4 beta for the GL-AXT1800 and
in GL-MT3000 4.11.0. GL.iNet has not confirmed this analysis. See
[RemoteToHome's write-up](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/router-reverse-shell.md). GL.iNet staff [recommends checking for it](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070/32)
and says to treat a router with such a shell as compromised. The script reports as `IOC`:

- these processes, with the time they started. A process that names the address or
  `/tmp/f` counts only when it is built like the reported shell: `nc`, `netcat` or
  `socat`, `mkfifo`, `sh -i`, or `cat /tmp/f`. An owner's `tcpdump` or `grep` for the
  address is `REVIEW` and is not stopped (since 2.53, [#7](https://github.com/admonstrator/glinet-csa-2026-01/issues/7)),
- open connections to `170.39.226.0/24`,
- the pipe `/tmp/f`. It stays after the shell was stopped and only goes away at a
  restart, so it shows that the shell ran since the last boot. Its time is when data
  last went through it. `--fix` removes it after the archive is written.

`/etc/mp_ip_mapping_info` is the state file that the cloud handler writes at the end of
each run. The attack's message leaves it empty, and the file stays after a restart while
the firewall rule does not. So the script reports as `IOC` (`cloud-command`) a state
file that is empty, was written on or after November 19, 2026 (before 2.55: November 20;
a forum user recorded a KVM taken over on November 19), and sits on a device where
AstroWarp is switched off. In every other case the file is `REVIEW` with its time and
size, because it is normal on a router that uses AstroWarp. Firmware with GL.iNet's fix
writes the file empty at its own start, together with its other state files; the script
recognizes that and reports `REVIEW` too ([#19](https://github.com/admonstrator/glinet-csa-2026-01/issues/19), since 2.54).
Since 2.55 this holds on firmware without the fix as well: there the module writes the
file when AstroWarp is switched on, and switched off again before the check, such a file
looked like the attack ([#25](https://github.com/admonstrator/glinet-csa-2026-01/issues/25)).
A command from the cloud within the same two minutes would look the same.

Where the file's filesystem is mounted `noatime`, as the overlay is on the routers
surveyed, the report also gives the handler's first and last call (since 2.35, in the
report as `state_file_first`).

GL.iNet travel routers have no battery clock and show a wrong date until they sync the
time. A file time before 2020 is therefore shown with "clock was not set, not a real
date".

This trace and the firewall rule only show that a crafted command ran. With nothing
else found, the verdict is `ATTACKED`, not `INFECTED`: a forum user recovered one such
message from the memory of the cloud client on a GL-BE9300, and it only listed the
malware's folders and sent the listing to the attacker's server. Other devices got a
remote shell through the same handler. What ran on a given device cannot be determined
afterward, so the advice on keys and passwords is the same. `--fix` has nothing to
remove for it and leaves the file in place.

The same post adds two wider checks, which the script runs as well and reports as
`REVIEW`: processes that look like `nc`, `netcat`, `socat`, `/bin/sh -i` or `mkfifo`, and
established connections held by a shell or by such a tool. The post uses `netstat -tnp`
for the connections. The script reads the kernel's lists in `/proc/net/tcp` and `/proc/net/tcp6` instead,
because the implant is known to replace `netstat`.

The script also looks at where every running program comes from. A program started
from a RAM disk (`/tmp`, `/var`, `/run`) is in neither the base image nor the overlay, so
the file checks cannot see it. Such programs, and programs that are not in the base image
or differ from it, are listed as `REVIEW` (`INFO` when a package installed them). A script
that a shell from the base image runs, like the remote shell above, is not caught this
way; only the patterns above find it.

## The older backdoor (urandom_seed / ulogd)

Users of GL.iNet's forum found a second backdoor that is not part of GL.iNet's notice and
that GL.iNet's quick check does not see
([ehidle's report](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097),
and posts 26, 63 and 65 of the [notice's thread](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056)).
At least five devices are described so far: two GL-AX1800 (4.8.3), a GL-X2000 (4.7.13),
a GL-MT3000 (4.11.0) and one whose model was not given, with files dated from October 2025 to March 2026; one user says since
September 2025. A second GL-AX1800 with the same firmware, also on GoodCloud, was clean.
How it got onto the devices is not known. RemoteToHome found it on 49 routers it manages
(GL-MT2500, GL-MT3000, GL-MT6000, GL-AX1800, GL-AXT1800), installed from September 2025 to
May 2026, and took apart all 49 loaders and both builds of the second stage
([its repository](https://github.com/RemoteToHome-io/gl-security-incident-2026), November 23, 2026).

The changed `urandom_seed` is the same file on three of them (sha256 `3265f27f…fc19`).
`/bin/ulogd` differs from device to device (each copy holds an id of its own; RemoteToHome
found 49 hashes on 49 routers), so its hash is no use as an indicator. The server names are not readable in it: acs
[decoded them](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097/2) from one variant, and nick2's
[write-up](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097/6) compares an infected router with a clean one of the same kind.

It starts at every boot from a changed `/etc/init.d/urandom_seed`, reports the device to
a server whose name imitates AdGuard or OpenWrt and gets a second program back that runs in memory
only. The script reports as `IOC`, with a kind that starts with `backdoor-`:

- an init script from outside a package that starts `monitord`, `/bin/ulogd` or `ujaild`
  and differs from the base image (`backdoor-init`). Since 2.54 a script that only names
  them, to end their processes, delete their files or block their servers, is not counted,
- `/bin/ulogd` that no package installed, and `/usr/bin/monitord` when it is a copy of
  `/usr/bin/lua` (`backdoor-file`),
- a changed list of files that a firmware update keeps, when it names those files
  (`backdoor-keep`): the backdoor appends `/bin/ulogd` and `/etc/init.d/urandom_seed` to
  `/lib/upgrade/keep.d/netifd`. Not always: on 9 of RemoteToHome's 49 routers that file
  was untouched, so a missing `backdoor-keep` does not show that the backdoor is absent,
- one of the known server names in the configuration (`backdoor-host`): `adguardns.com`,
  `adguardns.org`, `adsanalypro.com`, `lede-openproject.org`, `adxinsight.com`,
  `openwrt-project.org`. A line counts where it fetches from such a server, contains one
  of its URLs or resolves the name to an outside address. A name that nothing fetches
  from is `REVIEW` (`server-ref`). A line that blocks the name is `INFO`
  (`backdoor-block`): a hosts or dnsmasq entry to a null or local address, a block list,
  a firewall rule that drops it,
- a running `monitord` or `ujaild` (`backdoor-proc`). The second stage `ujaild` runs from
  a deleted file, so the script fingerprints the copy the kernel holds: on RemoteToHome's
  49 routers of five models it was one of two programs, and a match is noted as the known
  second stage.
  A different fingerprint does not clear the process,
- compiled Lua anywhere in the overlay that no package installed: with the loader's
  function names in it, it is the loader under another name (`backdoor-file`), otherwise
  `REVIEW lua-bytecode`. The firmware keeps its own compiled Lua in the read-only image,
- `/etc/config/wireguard_server` written within two minutes of `/bin/ulogd` (`REVIEW
  backdoor-wg`, with the distance in seconds). RemoteToHome found it written 9 to 12
  seconds after the loader on 27 of 30 routers with a dated install, and three owners
  report the same. What changes in it is not known; one owner's backups show the content
  unchanged.

A request for one of those names in AdGuard Home's query log is `REVIEW`: it shows that
some device in the network asked, not which one.

The verdict names the backdoor separately from the gl-helper indicators. `--fix` does not
remove it: the second stage runs in memory only, runs any command, writes any file and
opens a proxy for its server (RemoteToHome), so what was done with it cannot be listed.
Install the firmware again with "keep settings" off, from a file you downloaded yourself,
and do not restore a backup taken from that device.

GL.iNet's security firmware for routers (November 22 and 23, 2026) puts `urandom_seed`
back at its first start but leaves `/bin/ulogd`, and the backdoor's own keep-list line
carries the loader through an update that keeps settings (RemoteToHome's test of November
23). The script then still reports `/bin/ulogd` as `IOC`; where no other start-up file names
the loader, the finding says that it is likely no longer started at boot (since 2.54). The
device had the backdoor.

## Firewall

The running firewall rules are generated from configuration when the firewall starts, so
no single rule "comes from the firmware". What the script compares with the firmware
image is that configuration (`/etc/config/firewall`, `/etc/firewall.user`,
`/etc/nftables.d/` and similar): every file that differs is a `REVIEW` finding, and the
lines that are not in the image are printed under "Firewall". Your own port forwards and
rules show up there too.

`/etc/firewall.user` and the files in `/etc/firewall.d` are run as shell scripts when the
firewall starts (fw3). A line there that starts the malware or fetches from its servers is
an `IOC` (`persist-ref`) as in any autostart file (since 2.53). `--fix` replaces that line
with `:`, so that an `if` or a loop around it still closes, and changes no other line. This
is the one place where `--fix` changes a file that is also listed for review. If the
script would no longer read as a script after that (`sh -n`), for example because the
malware's command is the condition of an `if`, the file is left as it is and `--fix` ends
with exit 3.

From the running rules the report prints the ones that redirect traffic (`DNAT`,
`REDIRECT` and the chain `SDWAN_IP_MAPPING`). The complete rule set (`iptables-save`,
`nft list ruleset`) goes into the evidence archive. A rule in `SDWAN_IP_MAPPING` that
redirects `127.0.0.1` to `127.0.0.1` is what the command of the user-reported remote
shell leaves behind; the script reports it as `IOC` and `--fix` deletes it.

The process and rule checks show what is running **right now**. `/tmp` is RAM: after a restart these
traces are gone, and a clean result does not show that a device was never compromised.
`--fix` stops the processes. It cannot tell what started them.

It also lists other overlay changes as `REVIEW` for a human to judge: new or modified
binaries, new init scripts, `authorized_keys`, extra uid 0 accounts, hidden files and
processes running from deleted binaries.

Since 2.60 the [fingerprint check](lookup.md) can ask the community list about the files
listed for review. A file it knows as malware becomes `IOC lookup-bad`: the verdict is
`INFECTED`, and `--fix` does not remove it. The finding comes from the list, not from the
device, so it is shown with its own line and verdict, never as a gl-helper indicator.

> ⚠️ **Do not run `netstat` on a device you suspect.** It may be the implant's replacement,
> and GL.iNet staff [says](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070/41)
> that running the replacement starts the malware. The script never calls it and uses the
> busybox from the base image (`/rom`) for its own tools.

What "trusted tools" rests on (since 2.37):

- The busybox of the base image is linked dynamically on GL.iNet's routers. It loads its
  loader and its libraries (`libc.so`, `libgcc_s.so.1`) from `/lib` of the running system,
  where the overlay can put other files in their place. The script reads their names from
  the busybox and compares each with the base image, and with musl also looks for a file
  `/etc/ld-musl-ARCH.path` that would send the loader elsewhere. If one differs it is
  listed as `REVIEW changed-lib`, the head of the report says `Trusted tools  no`, and the
  tools come from `$PATH`. Where the names cannot be read, nothing is claimed about the
  libraries; the run goes on in every case.
- Tools that are not busybox applets come from `$PATH`: `iptables-save`, `ip6tables-save`,
  `nft`, `logread`, `curl` or `wget`, and `iptables` and the cron init script in `--fix`.
  On a running device each is used only when it is the base image's own file. One that is
  not is not run and is listed as `INFO tool-skipped`, because a replaced tool would run as
  root; what it would have shown is then missing from the check. For a firewall tool that
  means the rule the attack leaves cannot be seen.
- The base image is what everything is compared with. The script does not check that
  nobody wrote to it. No such case is known.
