<div align="center">

<img src="images/logo.svg" width="300" alt="A seal resting on a patched-up router">

## gl-helper Triage for GL.iNet Routers and KVMs

**Check a device for the malware from GL.iNet's security notice of 20 November 2026, save the evidence, then clean up.**

[![Advisory CSA-2026-01](https://img.shields.io/badge/Advisory-CSA--2026--01-b3261e?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/) [![Guide](https://img.shields.io/badge/Guide-gl--i.net-16774c?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/fix/) [![License](https://img.shields.io/github/license/admonstrator/glinet-csa-2026-01?style=for-the-badge)](LICENSE) [![Last Commit](https://img.shields.io/github/last-commit/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/commits) [![Issues](https://img.shields.io/github/issues/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/issues) [![Stars](https://img.shields.io/github/stars/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/stargazers)

</div>

---

> [!WARNING]
> **Community work, not an official GL.iNet tool.** GL.iNet has not reviewed or endorsed it.
> It finds and removes only the indicators we know of, and it **does not replace the factory
> reset** GL.iNet recommends. Use it at your own risk.

---

## 📖 About

On 20 November 2026 GL.iNet published a [security notice](https://www.gl-inet.com/blogs/blog/glinet-security-notice-2026-11-20):
its cloud remote management service had been abused to install malware on a subset of
GL.iNet routers and KVM devices. The community advisory is
[CSA-2026-01](https://gl-i.net/security/csa-2026-01/).

This repository contains a triage script for the implant known as "gl-helper". It runs on
GL.iNet KVMs (RM1 family, buildroot based) and on GL.iNet / OpenWrt routers.

By [Admon](https://forum.gl-inet.com/u/admon/) and the community: [RemoteToHome Consulting](https://remotetohome.io)
and users of GL.iNet's forum contributed findings and checks. See [Credits](#-credits).

> 🎖️ **Community Maintained** – Part of the [GL.iNet Toolbox](https://github.com/Admonstrator/glinet-toolbox) project  
> ⚠️ **Independent Project** – Not affiliated with GL.iNet

---

## ✨ Features

- 🔎 **Check** – Read-only detection of the known indicators of the implant
- 📦 **Archive** – Saves evidence before anything is changed. No archive, no changes.
- 🧹 **Fix** – Removes the known implant files and their persistence on request
- 🛡️ **Trusted tools** – Uses the busybox from the base image, not the tools an attacker may have replaced, and checks that the libraries it loads are the base image's too
- 👀 **Review list** – Reports other unusual changes for a human to judge and never touches them
- 🖥️ **Routers and KVMs** – GL.iNet / OpenWrt routers and GL.iNet KVMs (RM1 family)

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| **Device** | GL.iNet KVM (RM1 family) or GL.iNet / OpenWrt router, with root SSH access |
| **On the device** | busybox `sh`/`ash` or bash, nothing to install |
| **On your computer** | Only for `triage-remote.sh`: Linux with bash, ssh, tar and sha256sum |

---

## 🔎 Indicators

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
  it decode as stated, the rest is not verified by us):
  - the directories it falls back to when it cannot write to the first one:
    `/etc/gl_nas/.cache`, `/userdata/.gl`, `/overlay/.gl`, `/tmp/.gl`,
  - its other files in any of these directories: `watch.sh`, `run.sh`, `wake.sh`,
    `boot.sh`, `rtty_keep.sh`, `eco`, `node`, `.u`, `.wc`, `install.log`,
  - its watchdog line in the running crontab `/tmp/gl_crontabs/root` (`cron-ref`),
  - `/etc/rtty_conf` set to the attacker's server (`rtty-server`),
  - a key named `gl-agent` in `authorized_keys` (`ssh-key`),
  - its servers `65.20.71.131` and `66.245.219.252` on a command line, in an autostart
    file or as a connection. One user's network logs and the installer name the same
    two, so they count as indicators now,
  - the replaced `netstat`: a two-line script that calls the real one and hides the
    connections to its server.

  `crond -i /tmp/.log`, the process GL.iNet's check looks for, is the name the malware
  gives its own process.
- a `netstat` link to busybox that was made on or after 20 November (`installer-trace`).
  The anonymous reports show it on KVMs, always made on the evening of the attack, on
  some next to the malware's files and on others with nothing else left. With only this,
  the verdict is `ATTACKED`: the installer was at work, its files are gone.
- a link in a tool directory that the firmware does not have, for example a new
  `/usr/bin/netstat` (`REVIEW`),
- scripts in `/etc/udhcpc.user.d`, which the router runs on every DHCP event (`REVIEW`),
- the name `gl-inet.top` on a command line, in an autostart file or in `/etc/rtty_conf`.
  It is in the malware's helper as a fallback server (`gl-inet.top:8899`), so it counts
  as an indicator like the two addresses,
- connections to the attacker's server that are attempted but not answered: the server
  was suspended on 21 November, so a shell loop that still runs never gets through,
- Tailscale from the [community Tailscale updater](https://github.com/Admonstrator/glinet-tailscale-updater)
  is not counted as a change (`INFO updater-file`). The script recognises it without
  running it: the uncompressed build by its version string (`tiny.by.admon`), the
  compressed one when the updater's own traces are on the device. Otherwise a replaced
  `tailscaled` is `REVIEW`, and `tailscaled --version` tells you whose it is,
- busybox/coreutils applets in the overlay that were replaced by a foreign regular file
  (for example `netstat`), unless a package (apk/opkg) installed the file,
- running processes started from implant paths or from a replaced applet,
- autostart and config files that reference implant paths: crontabs, `rc.local`, init
  scripts, hotplug, profile, and **sysupgrade keep lists** (an entry there makes the
  implant survive a firmware update with "keep settings"),
- implant persistence even when the marker files were deleted.

### Running processes

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

- these processes, with the time they started,
- open connections to `170.39.226.0/24`,
- the pipe `/tmp/f`. It stays after the shell was stopped and only goes away at a
  restart, so it shows that the shell ran since the last boot. Its time is the last data
  that went through it. `--fix` removes it after the archive is written.

`/etc/mp_ip_mapping_info` is the state file that the cloud handler writes at the end of
each run, one line per entry that has a MAC address. The attack's message has none, so
it leaves the file empty. The firewall rule is gone after a restart or when the cloud
client stops; the file stays. So the script reports as `IOC` (`cloud-command`) a state
file that is empty, was written on or after 20 November 2026 and sits on a device where
AstroWarp is switched off. In every other case the file is `REVIEW` with its time and
size, because it is normal on a router that uses AstroWarp.

Where the filesystem holding the file is mounted `noatime`, as the overlay is on the
routers surveyed, the script also gives its access time as the handler's first call and
the time written as its last (since 2.35, also in the report as `state_file_first`). That
is the time the file was created, so the first call since the file last did not exist.

GL.iNet travel routers have no battery clock and have a wrong date until they sync the
time. A file time before 2020 is therefore shown with "clock was not set, not a real
date"; the report keeps the time as it is.

This trace and the firewall rule only show that a crafted command ran. With nothing
else found, the verdict is `ATTACKED`, not `INFECTED`: a forum user recovered one such
message from the memory of the cloud client on a GL-BE9300, and it only listed the
malware's folders and sent the listing to the attacker's server. Other devices got a
remote shell through the same handler. What ran on a given device cannot be told
afterwards, so the advice on keys and passwords is the same. `--fix` has nothing to
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

### The older backdoor (urandom_seed / ulogd)

Users of GL.iNet's forum found a second backdoor that is not part of GL.iNet's notice and
that GL.iNet's quick check does not see
([ehidle's report](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097),
and posts 26, 63 and 65 of the [notice's thread](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056)).
At least five devices are described so far: two GL-AX1800 (4.8.3), a GL-X2000 (4.7.13),
a GL-MT3000 (4.11.0) and one whose model was not given, with files dated from October 2025 to March 2026; one user says since
September 2025. A second GL-AX1800 with the same firmware, also on GoodCloud, was clean.
How it got onto the devices is not known.

The changed `urandom_seed` is the same file on three of them (sha256 `3265f27f…fc19`).
`/bin/ulogd` differs from device to device, four hashes on four devices, so its hash is
no use as an indicator. The server names are not readable in it: acs
[decoded them](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097/2) from one variant, and nick2's
[write-up](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097/6) compares an infected router with a clean one of the same kind.

It starts at every boot from a changed `/etc/init.d/urandom_seed`, reports the device to
a server whose name imitates AdGuard or OpenWrt and gets a second program back that runs in memory
only. The script reports as `IOC`, with a kind that starts with `backdoor-`:

- an init script from outside a package that names `monitord`, `/bin/ulogd` or `ujaild`
  and differs from the base image (`backdoor-init`),
- `/bin/ulogd` that no package installed, and `/usr/bin/monitord` when it is a copy of
  `/usr/bin/lua` (`backdoor-file`),
- a changed list of files that a firmware update keeps, when it names those files
  (`backdoor-keep`): the backdoor appends `/bin/ulogd` and `/etc/init.d/urandom_seed` to
  `/lib/upgrade/keep.d/netifd`. Not always: on 8 of 28 surveyed routers with the backdoor
  that file was the firmware's own, with the start-up script, the loader and both processes
  present, so a missing `backdoor-keep` says nothing about whether the backdoor is there,
- one of the known server names in the configuration (`backdoor-host`): `adguardns.com`,
  `adguardns.org`, `lede-openproject.org`, `adxinsight.com`, `openwrt-project.org`.
  A line that blocks such a name is no indicator (`backdoor-block`, `INFO`): a hosts
  entry to `0.0.0.0`, `127.0.0.1`, `::` or `::1`, or dnsmasq's `address=/name/`,
  `server=/name/` and `local=/name/` without a real address,
- a running `monitord` or `ujaild` (`backdoor-proc`). The second stage `ujaild` runs from
  a deleted file, so the script fingerprints the copy the kernel holds: on 30 routers of
  four models it was one of two programs, and a match is noted as the known second stage.
  Another fingerprint does not clear the process,
- compiled Lua anywhere in the overlay that no package installed: with the loader's
  function names in it, it is the loader under another name (`backdoor-file`), otherwise
  `REVIEW lua-bytecode`. The firmware keeps its own compiled Lua in the read-only image,
- `/etc/config/wireguard_server` written within two minutes of `/bin/ulogd` (`REVIEW
  backdoor-wg`, with the distance in seconds). Two owners found it written eleven seconds
  after the loader; if more devices show it, it points to how the backdoor got in.

A request for one of those names in AdGuard Home's query log is `REVIEW`: it shows that
some device in the network asked, not which one.

The verdict names the backdoor apart from the gl-helper indicators. `--fix` does not
remove it: the second stage leaves no file, and nobody has taken it apart yet. Reflash the
firmware with "keep settings" off and do not restore a backup taken from that device.

### Firewall

The running firewall rules are generated from configuration when the firewall starts, so
no single rule "comes from the firmware". What the script compares with the firmware
image is that configuration (`/etc/config/firewall`, `/etc/firewall.user`,
`/etc/nftables.d/` and similar): every file that differs is a `REVIEW` finding, and the
lines that are not in the image are printed under "Firewall". Your own port forwards and
rules show up there too.

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

---

## 🚀 Quick Start

Run the check on the device (SSH as root), without cloning the repository:

```bash
curl -fsSL https://app.gl-i.net/csa-2026-01-fix -o gl-helper-triage.sh ; sh gl-helper-triage.sh
```

This only reads. It changes nothing and prints a report.

> ⚠️ **Read the script before you run it.** It runs as root on a device you suspect is compromised.

If the report shows indicators, save the evidence and then clean up:

```bash
sh gl-helper-triage.sh --archive
```

```bash
sh gl-helper-triage.sh --fix
```

`--fix` writes the evidence archive first and aborts if that fails. On the device `/tmp`
is RAM: copy the archive to your computer before you reboot.

### From Your Computer

`triage-remote.sh` runs the check over SSH, streams the evidence archive to `./evidence/`
on your computer, verifies it and only then runs `--fix`. It needs Linux with bash, ssh,
tar and sha256sum. Several devices can be given at once.

```bash
git clone https://github.com/admonstrator/glinet-csa-2026-01.git
cd glinet-csa-2026-01
./triage-remote.sh root@192.168.8.1          # check + pull the evidence archive
./triage-remote.sh --fix root@192.168.8.1    # also remediate if indicators are found
```

Or pipe the script through SSH yourself, so nothing is stored on the device:

```bash
ssh root@DEVICE 'sh -s -- --check' < gl-helper-triage.sh
ssh root@DEVICE 'sh -s -- --archive --stdout' < gl-helper-triage.sh > evidence.tar.gz
ssh root@DEVICE 'sh -s -- --fix' < gl-helper-triage.sh
```

---

## 🗣️ The Result in Plain Words

The output is written for people who know these devices. For everyone else the script
prints an address directly under the verdict:

```
   Verdict: ATTACKED - a command sent through GoodCloud ran on this device

    >>> This result in plain words, with what to do (English, German, Chinese):
   >>> https://csa.gl-i.net/#AA006011D
```

On a terminal the first of these lines is a green bar and the address is underlined, so
that it is the thing a reader sees. The bar uses reverse video, so its text has the
terminal's own background colour and stays readable in dark and light themes.

The page behind it explains what was found, what that means and what to do, in English,
German and Chinese. Over ssh the address often cannot be clicked, so it is short enough to
type: nine characters, capitals or not. They hold the script's version, router or KVM, the
kinds of findings, whether GoodCloud is on, whether the device was restarted since the
attacks began, what `--fix` did and whether other changes are listed for review. The ninth
character is a check, so a mistyped code is refused instead of explaining another result.

Where the script knows the model and its firmware version, five more characters follow
after a dash (`csa.gl-i.net/#AA006011D-2PJ2W`, since 2.45). With them the page says whether
newer firmware exists for the device, from the list of
[firmware.gl-i.net](https://firmware.gl-i.net/). The first nine work without them.

No path, no name, no serial number, no ID: nothing in the code tells this device from
another of its kind. It stands after `#`, a part of an address that a browser does not
send: opening it sends nothing about the device, and it can be posted in a forum as it is.
The page does not check anything; it explains the code it is given. With `--fix` the
address is printed under the verdict after the clean-up, and then also says what the
clean-up did.

Since 2.39; under the verdict since 2.40; nine characters since 2.41; model and firmware
since 2.45. The longer addresses
of 2.39 and 2.40 still work.

## 🎛️ Modes

| Option | Effect |
|---|---|
| `--check` (default) | Read-only detection and report |
| `--archive [-o DIR]` | Report plus evidence archive in `DIR` (default `/tmp`) |
| `--archive --stdout` | Evidence archive to stdout, log to stderr |
| `--fix [-o DIR]` | Archive first (aborts if that fails), then remediate and re-check |
| `--report`, `--no-report`, `--show-report` | Send the anonymous report without asking, never offer it, or print it without sending. See below. |
| `--no-device-id` | Leave the device ID out of the report. |
| `--note TEXT` | Add a note of your own to the report, for example where it comes from or whether the device was checked before or after a clean-up. At most 120 characters; only letters, digits, spaces and `._:/+@=,()-` are kept. |
| `--with-secrets` | Keep the private keys and passwords that the script would otherwise take out of the evidence archive. |
| `--color`, `--no-color` | Force or disable coloured output. By default colours are used only on a terminal; `NO_COLOR=1` also turns them off. |

Exit codes: `0` clean, `1` indicators found, `2` fixed and clean, `3` fix incomplete,
`4` error.

Every run ends with a section on GoodCloud: when it is on, or cannot be read, the script
says to switch GoodCloud and AstroWarp off and gives the command. The attack came in
through GoodCloud, and by reports of 22 November devices are still being hit.

The head of the report appears at once. It includes whether GoodCloud is switched on
now, with the version of its client; that is the setting at the time of the check, not
during the attack. While the checks run, a line shows which of the
nine steps is in progress. The report groups its findings by label and ends with a summary and a verdict. Under a
clean verdict on a running device the script says when the device last started. If that
was on or after 19 November 2026 it adds that the result says little about the time
before: a remote shell and what it left in memory are gone after a restart, and on a KVM
a firmware update can have removed the malware's files. The copy
in the evidence archive is always plain text.

Findings are labeled:

- `IOC`: a known indicator. `--fix` removes it.
- `PERSIST`: `rc.local` or root crontab in the overlay without an implant reference.
  `--fix` resets it only when the malware itself was found (its files, autostart entries
  or processes), like the vendor cleanup. With nothing but traces of the remote shell
  (its process, pipe, connection, the firewall rule) both files stay as they are.
- `REVIEW`: unusual change. Archived and reported, never modified.
- `INFO`: context, for example files installed by a package.

Below the findings the report lists, under "Credentials on this device", the keys and VPN
profiles stored on the device: root's SSH client keys with their fingerprint, WireGuard
and AmneziaWG private keys of the GL.iNet client and server, OpenVPN client profiles,
the ZeroTier identity and the Tailscale state. It shows names
and counts, never the content. These are not findings: they are listed with or without
indicators and are never part of the anonymous report. Other passwords and tokens in the
configuration are not listed.

---

## 🔄 Updating the Script

The script changes several times a day while the community learns more. `--update` replaces
it by the version that is served now:

```sh
sh gl-helper-triage.sh --update
```

It checks nothing on the device and changes nothing but its own file. It never runs by
itself.

- **Only with a good signature.** Each version is signed when it is published. The script
  carries the public keys and takes a download only when the signature fits, checked with
  `usign`, the tool OpenWrt checks its package lists with. So neither someone in the
  network nor the service that hands the script out can pass on another file.
- **Never an older version.** A version older than the one that runs is refused, even with
  a good signature: it could be an old one with known gaps, sent on purpose.
- **Where there is no `usign`** the script says so and what that means, and asks whether to
  update all the same. Then only the encrypted connection protects the download. Where
  nobody can be asked, add `--unsigned`.
- **Whatever fails, the script that is there stays.** The version from before is kept next
  to it as `gl-helper-triage.sh.old`.

What it does not protect against: an attacker who is root on the device, or who controls
the repository the script comes from. The first download is protected by the encrypted
connection alone, as before.

## 📮 Anonymous Report

At the end of a run the script offers to send a short report to the community, so that
we can see which models and firmware versions were hit and when. It offers this on a
device without indicators too: those reports show which devices were not hit. At the end of its
run it says in a few lines what the report contains and sends it only after you answer
`y`; `v` first shows everything that would be sent: each part explained, your own lines
word for word, and the complete report. Without a terminal (for example through
`ssh ... 'sh -s'`) it never sends on its own; add `--report` to send. `--show-report`
prints the complete report and sends nothing, `--no-report` switches the offer off.

The report contains: script version, platform, model, firmware version, time of the
check, uptime, the number of findings per label, the kind and path of each `IOC` and
`PERSIST` finding, whether GL.iNet's quick check hit, and for the reported remote shell
its start time, the remote port and the time of its pipe. For the implant's own files and
for replaced system tools it adds the SHA-256, size and two times of the file: when it
was last written (mtime) and when the kernel last changed its entry (ctime). The first
can come with the file, from an archive or a copy, or be set back with `touch`; the second
cannot, so the two together show when the file really arrived. It also gives the time
and size of the cloud handler's state file, and whether GoodCloud and AstroWarp are
switched on, with the version of the cloud client. Since 2.28 also whether the device is
bound to a GoodCloud account and whether remote SSH and the remote web interface
through the cloud are on: yes, no or unknown each, never the account's name or address.
People ask whether a device that was only bound, with remote access off, was at risk;
these three answers let the reports say. The two remote access answers are the stored
settings, and "on" is what the firmware sets by itself on many versions. They only matter
while GoodCloud is on, so with GoodCloud off the script shows remote access as not in use
and the dashboard counts it as off.

Since 2.35 it carries the note given with `--note`, empty without one. It is for people
who report many devices, to say where a report comes from, whether the device was
checked before or after a clean-up, or that it is a repeat. The script prints the note
as it will be sent before it asks.

Since 2.23 it also carries what the script listed for `REVIEW`: for each finding its kind
and path, at most 40, and for a file its SHA-256 and its two times (written, and
changed on the device; since 2.24). A program that runs from a deleted file is
fingerprinted from the copy the kernel still holds. Not the description, which can hold
addresses, command lines and account names: a process is sent as its kind alone, a
connection as the name of the program that holds it. An account that the firmware does
not have is sent with its name, number and shell and whether its password field is empty
(since 2.25), never a password or hash. These are not known traces. They
are sent so that a pattern across devices can be seen early: the older backdoor stood in
people's `REVIEW` lists for a day before anyone named it. The paths are shown before the
question, because a path of your own can say something about you. Their combination is
also fairly particular to a device, so two reports from it can be told to belong together
even with `--no-device-id`.

When indicators were found, it also contains what the attacker left, as text:

- `/etc/rc.local` in full when it was changed (up to 60 lines), because what stands around
  the attacker's line matters too. From the other changed autostart files (the root
  crontab, init scripts that start the implant) the lines that are not in the firmware
  image, up to 20 per file. From the lists of files a firmware update keeps, only the
  lines that name the implant.
- the rules of the firewall chain `SDWAN_IP_MAPPING`, which the reported attack writes to,
- the command lines of the implant's and the remote shell's processes.

**Your own lines in those files are part of this**, for example a line you added to
`rc.local` or the crontab. Before it asks, the script says how many such lines the report
holds; `v` prints them word for word, with the rest of the report. Read them, and answer
`n` if one of them is a password or token. (Up to 2.41 the lines were always printed in
full, which on some devices ran over several screens and pushed the result out of sight.)

The report carries a **device ID**, so that several reports from one device count once.
It is a hash of the hardware address of the first network interface; the address itself
never leaves the device. A plain hash of such an address could be reversed by trying all
addresses, so the server does not store it either: it hashes it again with a secret that
only the server has, and keeps a short form of that. `--no-device-id` leaves the ID out.
The ID makes the report pseudonymous rather than fully anonymous: two reports from the
same device can be linked to each other, but not to you.

To be exact about that hash: GL.iNet uses few address ranges, so whoever receives the ID
as the script sends it could find the hardware address behind it by trying them all. The
server could do that before it applies its own secret; it does not, and it does not keep
the value it received. If that is not good enough for you, use `--no-device-id`.

It does not contain the host name, IP or MAC addresses, or any other file. `REVIEW` findings are only counted.
The receiving [worker](worker/) stores no IP address.

---

## 🧹 What `--fix` Does

1. Writes and verifies the evidence archive. No archive, no changes.
2. Stops implant processes (SIGSTOP all, then SIGKILL).
3. Removes `/etc/glinet/.cache/` and `/etc/config/.gl/`, and a fallback directory of the
   installer when one of the malware's files was found in it.
4. Resets `rc.local` and the root crontab to the base image version, or removes them
   if the base image has none. The previous versions are in the archive.
5. Restores replaced applets from the base image and removes other autostart files that
   start the implant, including OpenWrt `rc.d` links to removed init scripts.
6. Removes only the implant lines from sysupgrade keep lists, from the running crontab
   `/tmp/gl_crontabs/root` and, for a key named `gl-agent`, from `authorized_keys`.
   `/etc/rtty_conf` is not changed: the script cannot tell what belongs there. When it names
   the attacker's server, `--fix` says so and exits 1 if that was the only finding, or 3
   after removing the others. A factory reset or reflash puts the file right.
7. Deletes the firewall rule that the command of the user-reported remote shell left
   behind. Other firewall rules and the firewall configuration are not changed.
8. Restarts cron and checks again.

Changes go through the merged root filesystem, so the overlay stays consistent while it
is mounted. `REVIEW` items are never touched, and neither is the
[older backdoor](#the-older-backdoor-urandom_seed--ulogd): with only that on the device
`--fix` changes nothing and exits 1, with both it removes the gl-helper indicators and
exits 3.

---

## 📦 Evidence Archive

`gl-triage-<host>-<time>.tar.gz` contains the report, the findings, a listing and
SHA-256 hashes of the whole overlay upper layer, a full copy of the upper layer (up to
64 MiB), copies of all finding paths, process list with socket owners, decoded TCP
connections, the firewall rules and configuration, `/proc/<pid>/` data and the binary of implant processes, kernel and system
logs, and a `MANIFEST.sha256`.

> ⚠️ **The archive can hold passwords, tokens and password hashes.** It is a copy of the
> device's configuration. Hand it only to someone you would give the device's passwords
> to, and never post it publicly or attach it to an issue.

The script takes out what it knows about, as a best effort and not as a guarantee:

- `/etc/shadow` is not included. `etc/shadow-summary.txt` only records whether a hash is
  set and whether it differs from the base image.
- Private keys and VPN profiles are left out: root's SSH client keys, the dropbear host
  keys, OpenVPN profiles, the Tailscale state, the ZeroTier identity, `*.pem` and `*.key`
  files, PPP secrets. `authorized_keys` and public keys stay, because a key someone added
  is evidence.
- In `/etc/config` the value of every option whose name ends in `key`, `password`,
  `passphrase`, `secret`, `token` or `psk` is replaced by `REDACTED`. The rest stays, so
  an added VPN peer is still visible.
- `REDACTED.txt` in the archive lists what was taken out. Hashes of the original files
  are in `overlay/upper-sha256.txt`.

What it does not catch: files in other formats are copied as they are. That includes the
settings of AdGuard Home with its password hash, files below `/etc/glinet` and
`/etc/kvmd/user` (on a KVM the web password file and the two-factor secret live there),
and the shell history, which is kept on purpose because it can show what an attacker
typed.

`--with-secrets` keeps everything except `/etc/shadow`, for an archive that stays with
you. The device itself is never changed by this.

On the device `/tmp` is RAM. Copy the archive off the device before rebooting.

---

## ✅ After Triage

- Keep the evidence archive. Run the triage **before** you restart, reset or update:
  some traces live only in memory, and the RM1PE 1.10.2 cleanup deletes the implant's
  files at boot without keeping a copy.
- KVM: install GL.iNet's security firmware. Only RM1PE 1.10.2 runs the vendor cleanup;
  the builds for RM1 and RM1V2 do not. On an RM1, an update that keeps settings carries
  over the password file, the SSH keys and everything under `/etc/kvmd/user`
  (found by RemoteToHome): change them and look for keys and scripts you did not add.
- Router: update **without keeping settings**. OpenWrt keeps `/etc/config` across a
  sysupgrade, and the implant hides in `/etc/config/.gl`.
- A factory reset wipes the whole overlay and is the safe option on both.
- Check the computer attached to a KVM, and the clients behind a router.
- Change the device password, the GL.iNet cloud account password and SSH keys.
- If the device was hit, everything it held a key for is exposed as well. Remove the
  router's VPN profile on the server or with the VPN provider and create a new one,
  and remove the router's SSH keys from every machine that trusts them.
  The report lists the keys and profiles it found under "Credentials on this device".
  [RemoteToHome's recovery steps](https://github.com/RemoteToHome-io/gl-security-incident-2026#if-you-find-something) go through each kind of VPN.
- Until GL.iNet's security firmware is installed, consider switching GoodCloud off on
  the device. [RemoteToHome](https://github.com/RemoteToHome-io/gl-security-incident-2026#reducing-exposure-until-fixed-firmware-is-installed)
  shows how and what it costs you.

---

## 🧬 Firmware Notes

From the firmware images we compared (1.10.1 vs 1.10.2; both 1.10.2 builds are from 2026-11-21):

- **RM1PE 1.10.2** contains the boot cleanup in `/etc/init.d/S08overlayfs`.
- **RM1V2 1.10.2** does not contain it. Its `S08overlayfs` is unchanged.
- **RM1 1.10.2** does not contain it either, as [RemoteToHome found](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/kvm-firmware.md).
  Their page also covers what an RM1 update keeps and that it leaves SSH switched off.
- Both 1.10.2 builds change `rtty` (the cloud remote terminal): the `-s`, `-C/--cacert`
  and `-x/--insecure` options are gone, the CA path `/var/run/gl-rtty/ca.crt` is built
  in, and `S99rtty` no longer reads a `tls` setting from the cloud-provided config.

---

## 🧪 Tests

The tests mount real overlay filesystems in an unprivileged user namespace, plant an
infection and run check, archive and fix:

```sh
unshare -rm bash tests/run-tests.sh
KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
```

On a device the script runs under busybox, whose tools differ from those of a desktop
Linux in details. The tests can give the script its own shell and tools while they keep
the machine's:

```sh
mkdir bb && for a in $(busybox --list); do ln -s "$(command -v busybox)" bb/$a; done
TRIAGE_SH="busybox sh" TRIAGE_PATH="$PWD/bb" unshare -rm bash tests/run-tests.sh
```

GitHub runs the tests on every push, once with the machine's tools and once with busybox
only, together with the tests of the worker and dashboard
([workflow](.github/workflows/tests.yml)).

Without `KVM_LOWER` only the OpenWrt scenarios run (synthetic base image). The script
was also run in check and archive mode on a GL.iNet router with firmware 4.11
(OpenWrt 25.12).

---

## 🚧 Limitations

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

---

## 💡 Getting Help

- 📘 [Guide on gl-i.net](https://gl-i.net/security/csa-2026-01/fix/) – The steps on one page
- 🛡️ [Advisory CSA-2026-01 on gl-i.net](https://gl-i.net/security/csa-2026-01/) – What happened and what GL.iNet recommends
- 💬 [GL.iNet's notice in the forum](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056) – Discussion and updates from GL.iNet
- 🔬 [RemoteToHome's findings on the incident](https://github.com/RemoteToHome-io/gl-security-incident-2026) – How the remote shell got in, the KVM firmware, how to recover
- 🐛 [Report issues on GitHub](https://github.com/admonstrator/glinet-csa-2026-01/issues) – Bugs and false positives. Never attach an evidence archive.
- 📧 GL.iNet support (support@gl-inet.com) – If you are not sure whether your device is affected

---

<div align="center">

## 💖 Support the Project

Admon built the script, the report service, the dashboard and the advisory in a few days
and nights of unpaid time, and keeps them up to date as the incident develops. All of it
is free and stays free. If it helped you, you can support his work:

[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsors-EA4AAA?style=for-the-badge&logo=github)](https://github.com/sponsors/admonstrator) [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/admon) [![Ko-fi](https://img.shields.io/badge/Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/admon) [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://link.admon.me/paypal)

</div>

---

## 👥 Credits

This is community work, and not one person's.

- [Admon](https://github.com/Admonstrator) – The script, the report service with its dashboard, and the
  [advisory page](https://gl-i.net/security/csa-2026-01/)
- [RemoteToHome Consulting](https://remotetohome.io) – The [analysis of the remote shell](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/router-reverse-shell.md)
  and its cause in the GoodCloud client, the [KVM firmware findings](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/kvm-firmware.md),
  the [recovery steps](https://github.com/RemoteToHome-io/gl-security-incident-2026#if-you-find-something), the look at the attacker's address,
  and [how to read the real firmware build](https://remotetohome.io/blog/glinet-router-firmware-versions/),
  which the report uses. Their [findings list](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/findings.md) says for
  every item how it was checked.
- kosrkosr and TakashiSasaki – The first two reports of the remote shell in GL.iNet's forum
- ehidle, acs, ikangshen, nick2 and the authors of posts 26, 63 and 65 in the notice's thread – The older backdoor
  in `urandom_seed` and `/bin/ulogd`, with its signs and the hash of the loader
- AdamK – The connection and process checks
- ehidle – The evidence of the attack on a GL-BE9300: that the recovered command only looked for the
  malware, and that the cloud handler's state file is a trace that survives a restart
- Romer – The older backdoor's keep list in full, and that the WireGuard server configuration was
  written seconds after it
- rdizzie – Read the malware's installer and posted what it does and where it puts its files
- [joska252](https://github.com/joska252) – Found that the archive contained password hashes and private keys, and that
  changed files of the base image's own packages were skipped, and that a named pipe could hang the script
  ([#3](https://github.com/admonstrator/glinet-csa-2026-01/issues/3), [#4](https://github.com/admonstrator/glinet-csa-2026-01/issues/4), [#9](https://github.com/admonstrator/glinet-csa-2026-01/issues/9)),
  read the script against the published sources ([#10](https://github.com/admonstrator/glinet-csa-2026-01/issues/10)),
  and found that blocking the older backdoor's servers read as infected, that a clean result said nothing about a
  restart, and that `--fix` reset autostart files it had no reason to touch ([#5](https://github.com/admonstrator/glinet-csa-2026-01/issues/5)),
  and that "trusted tools" claimed more than the script checked ([#8](https://github.com/admonstrator/glinet-csa-2026-01/issues/8))
- [SaadEGI](https://github.com/SaadEGI) – Found that the script reported an attack on a router that had just been updated
  to the security firmware, and showed with the times of the files that the firmware itself wrote the state file
  ([#19](https://github.com/admonstrator/glinet-csa-2026-01/issues/19))
- [infinisec](https://github.com/infinisec) – Found that busybox's grep does not look behind a NUL byte, so that the check of
  the libraries the script's tools load found nothing on a real device
  ([#24](https://github.com/admonstrator/glinet-csa-2026-01/issues/24))
- Everyone who sent an anonymous report or posted their output in the forum

---

## ⚠️ Disclaimer

This script is provided **as-is** without any warranty. Use it at your own risk.

It changes files on your device when you run it with `--fix`. It is a stopgap: it cannot
prove that a device is clean, and a factory reset is still recommended.

In a business network, talk to your cyber insurer or incident response provider before you
change or reset the device.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

<div align="center">

## 🧰 Part of the GL.iNet Toolbox

[![GL.iNet Toolbox](https://img.shields.io/badge/🧰_GL.iNet_Toolbox-Explore_All_Tools-blue?style=for-the-badge)](https://github.com/Admonstrator/glinet-toolbox)

**Made with ❤️ by [Admon](https://github.com/Admonstrator) and the GL.iNet community**

</div>
