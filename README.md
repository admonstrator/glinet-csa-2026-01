<div align="center">

<img src="images/logo.svg" width="300" alt="A seal resting on a patched-up router">

## gl-helper Triage for GL.iNet Routers and KVMs

**Check a device for the malware from GL.iNet's security notice of November 20, 2026, save the evidence, then clean up.**

[![Advisory CSA-2026-01](https://img.shields.io/badge/Advisory-CSA--2026--01-b3261e?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/) [![Guide](https://img.shields.io/badge/Guide-gl--i.net-16774c?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/fix/) [![License](https://img.shields.io/github/license/admonstrator/glinet-csa-2026-01?style=for-the-badge)](LICENSE) [![Last Commit](https://img.shields.io/github/last-commit/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/commits) [![Issues](https://img.shields.io/github/issues/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/issues) [![Stars](https://img.shields.io/github/stars/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/stargazers)

**Only here to check your device? The [guide on gl-i.net](https://gl-i.net/security/csa-2026-01/fix/) tells you what to do, step by step.**
You do not need to read this README for that.

</div>

---

> [!WARNING]
> **Community work, not an official GL.iNet tool.** GL.iNet has not reviewed or endorsed it.
> It finds and removes only the indicators we know of, and it **does not replace the factory
> reset** GL.iNet recommends. Use it at your own risk.

---

## 📖 About

On November 20, 2026, GL.iNet published a [security notice](https://www.gl-inet.com/blogs/blog/glinet-security-notice-2026-11-20):
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

The script looks for three things:

- **The gl-helper malware** from GL.iNet's notice: its files, its autostart entries, its
  processes, the replaced `netstat` and connections to its servers.
- **The remote shell** that users reported on routers, and the traces the cloud command
  behind it leaves.
- **An older backdoor** (`urandom_seed` / `ulogd`) that forum users found while looking
  for the first two. `--fix` does not remove it.

Other unusual changes are listed as `REVIEW` for a human to judge. The process and
firewall checks show what is running right now: after a restart those traces are gone,
and a clean result does not show that a device was never compromised.

> ⚠️ **Do not run `netstat` on a device you suspect.** It may be the implant's replacement,
> and GL.iNet staff [says](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070/41)
> that running the replacement starts the malware. The script never calls it and uses the
> busybox from the base image (`/rom`) for its own tools.

Every indicator, with its source: [What the script looks for](docs/indicators.md).

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

`--fix` writes the evidence archive first. If that fails it changes nothing, still gives
the verdict and ends with exit 4. On the device `/tmp` is RAM: copy the archive to your
computer before you reboot.

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

Under the verdict the script prints a short address such as
`https://csa.gl-i.net/#AA006011D`. The page behind it explains what was found and what
to do, in English, German and Chinese. Nothing in the code tells your device from
another of its kind, so it can be posted in a forum as it is. Details:
[The result in plain words](docs/result-code.md).

---

## 🎛️ Modes

| Option | Effect |
|---|---|
| `--check` (default) | Read-only detection and report |
| `--archive [-o DIR]` | Report plus evidence archive in `DIR` (default `/tmp`) |
| `--archive --stdout` | Evidence archive to stdout, log to stderr |
| `--fix [-o DIR]` | Archive first (changes nothing and exits 4 if that fails), then remediate and re-check |
| `--report`, `--no-report`, `--show-report` | Send the anonymous report without asking, never offer it, or print it without sending. See below. |
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
  the malware's own lines in `/etc/firewall.user` and `/etc/firewall.d` (see [Firewall](docs/indicators.md#firewall)).
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
it with the version that is served now:

```sh
sh gl-helper-triage.sh --update
```

It checks nothing on the device and changes nothing but its own file. It never runs by
itself.

- **Only with a good signature.** Each version is signed when it is published. The script
  carries the public keys and accepts a download only when the signature matches, checked with
  `usign`, the tool OpenWrt checks its package lists with. So neither someone in the
  network nor the service that hands the script out can pass on another file.
- **Never an older version.** A version older than the one that runs is refused, even with
  a good signature: it could be an old one with known flaws, sent on purpose.
- **Where there is no `usign`** the script says so and what that means, and asks whether to
  update anyway. Then only the encrypted connection protects the download. Where
  nobody can be asked, add `--unsigned`.
- **Whatever fails, the existing script stays.** The previous version is kept next
  to it as `gl-helper-triage.sh.old`.

What it does not protect against: an attacker who is root on the device, or who controls
the repository the script comes from. The first download is protected by the encrypted
connection alone, as before.

## 📮 Anonymous Report

At the end of a run the script offers to send a short report to the community, so that
we can see which models and firmware versions were hit and when. It sends only after you
answer `y`; `v` first shows everything that would be sent. `--no-report` switches the
offer off, and without a terminal the script never sends on its own.

When indicators were found, the report can include your own lines from `rc.local` or the
crontab. Read them before you send. Details: [Anonymous report](docs/anonymous-report.md).

---

## 🧹 What `--fix` Does

`--fix` writes and verifies the evidence archive first. No archive, no changes. Then it
stops the implant's processes, removes its files and autostart entries, restores replaced
tools from the base image, deletes the firewall rule the remote shell left behind, and
checks again.

`REVIEW` items are not touched, and neither is the older backdoor: for that, install the
firmware again. The steps in detail: [What `--fix` does](docs/fix.md).

---

## 📦 Evidence Archive

`gl-triage-<host>-<time>.tar.gz` contains the report, the findings, a copy of the changed
files in the overlay, the process list, the connections, the firewall rules and the logs.

> ⚠️ **The archive can hold passwords, tokens and password hashes.** It is a copy of the
> device's configuration. Hand it only to someone you would give the device's passwords
> to, and never post it publicly or attach it to an issue.

The script takes out the private keys and passwords it knows about, as a best effort and
not as a guarantee. On the device `/tmp` is RAM: copy the archive off the device before
rebooting. Details: [Evidence archive](docs/evidence-archive.md).

---

## ✅ After Triage

- Keep the evidence archive. Run the triage **before** you restart, reset or update:
  some traces live only in memory, and the RM1PE 1.10.2 cleanup deletes the implant's
  files at boot without keeping a copy.
- KVM: install GL.iNet's security firmware, 1.10.3 or later (1.8.7 or later for the
  RMQ1), with "Save current configuration" unchecked, or reset the KVM afterward. 1.10.3
  removes the implant at boot on all six models RemoteToHome read, and keeps no copy. An
  update that keeps the configuration carries over the password file, the SSH keys and
  everything under `/etc/kvmd/user`, boot scripts there included (RemoteToHome's test).
- Router: install the firmware again **without keeping settings**, from a file you
  downloaded yourself. An update that keeps settings keeps `/etc/config`, where the
  implant hides, and whatever else was added to `rc.local`, cron, the accounts or the SSH
  keys. Prefer this to a factory reset: a reset keeps the installed firmware image, and on
  at least one model root can write to that image (RemoteToHome, GL-AXT1800).
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

## 📚 Further Reading

| Document | Content |
|---|---|
| [What the script looks for](docs/indicators.md) | Every indicator, with its source and how it is reported |
| [What `--fix` does](docs/fix.md) | The cleanup, step by step |
| [Evidence archive](docs/evidence-archive.md) | What is in it and which secrets are taken out |
| [Anonymous report](docs/anonymous-report.md) | What is sent, what is not, and the device ID |
| [The result in plain words](docs/result-code.md) | How the short address under the verdict works |
| [Firmware notes](docs/firmware-notes.md) | What GL.iNet's KVM firmware 1.10.2 and 1.10.3 change |
| [Tests](docs/tests.md) | How to run the test suite |

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

This is community work, not one person's.

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
- [joska252](https://github.com/joska252) – Many reports that made the script safer and more careful: secrets in the
  evidence archive ([#3](https://github.com/admonstrator/glinet-csa-2026-01/issues/3)), skipped package files ([#4](https://github.com/admonstrator/glinet-csa-2026-01/issues/4)),
  a named pipe that could hang the script ([#9](https://github.com/admonstrator/glinet-csa-2026-01/issues/9)),
  a reading of the script against the published sources ([#10](https://github.com/admonstrator/glinet-csa-2026-01/issues/10)),
  false alarms and a `--fix` that did too much or too little
  ([#5](https://github.com/admonstrator/glinet-csa-2026-01/issues/5), [#7](https://github.com/admonstrator/glinet-csa-2026-01/issues/7), [#20](https://github.com/admonstrator/glinet-csa-2026-01/issues/20), [#22](https://github.com/admonstrator/glinet-csa-2026-01/issues/22)),
  and what "trusted tools" really covers ([#8](https://github.com/admonstrator/glinet-csa-2026-01/issues/8))
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
prove that a device is clean, and installing the firmware again without keeping settings
is still recommended.

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
