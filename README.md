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

This script checks a GL.iNet router or KVM (RM1 family) for that malware, known as
"gl-helper", for the remote shell users reported on routers, and for an older backdoor
(`urandom_seed` / `ulogd`) that forum users found while looking.

By [Admon](https://forum.gl-inet.com/u/admon/), [RemoteToHome Consulting](https://remotetohome.io)
and users of GL.iNet's forum. See [Credits](#-credits).

---

## ✨ Features

- 🔎 **Check** – Read-only detection of the known indicators
- 📦 **Archive** – Saves evidence before anything is changed. No archive, no changes.
- 🧹 **Fix** – Removes the known implant files and their autostart entries on request
- 🛡️ **Trusted tools** – Uses the busybox from the base image, not tools an attacker may have replaced
- 👀 **Review list** – Reports other unusual changes for a human to judge and never touches them

---

## 🚀 Quick Start

On a router you need root SSH access
([GL.iNet's guide to logging in over SSH](https://docs.gl-inet.com/router/en/4/tutorials/ssh_log_in_to_the_router/)).
On a KVM, run it in the web interface under Toolbox, Terminal. Nothing has to be installed.

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

On the device `/tmp` is RAM: copy the archive to your computer before you reboot.

> ⚠️ **Do not run `netstat` on a device you suspect.** It may be the implant's replacement,
> and GL.iNet staff [says](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070/41)
> that running the replacement starts the malware. The script never calls it and uses the
> busybox from the base image (`/rom`) for its own tools.

### From Your Computer

`triage-remote.sh` runs the check over SSH, pulls the evidence archive to `./evidence/`
on your computer and only then runs `--fix`. It needs Linux with bash, ssh, tar and
sha256sum.

```bash
git clone https://github.com/admonstrator/glinet-csa-2026-01.git
cd glinet-csa-2026-01
./triage-remote.sh root@192.168.8.1          # check + pull the evidence archive
./triage-remote.sh --fix root@192.168.8.1    # also remediate if indicators are found
```

---

## 🎛️ Options

| Option | Effect |
|---|---|
| `--check` (default) | Read-only check and report |
| `--archive [-o DIR]` | Report plus evidence archive in `DIR` (default `/tmp`) |
| `--fix [-o DIR]` | Archive first, then clean up and check again |
| `--update` | Replace the script with the current signed version |
| `--report`, `--no-report` | Send the anonymous report without asking, or never offer it |
| `--with-secrets` | Keep private keys and passwords in the evidence archive |

Exit codes: `0` clean, `1` indicators found, `2` fixed and clean, `3` fix incomplete,
`4` error.

| Label | Meaning |
|---|---|
| `IOC` | A known indicator. `--fix` removes it. |
| `PERSIST` | A changed `rc.local` or root crontab. `--fix` resets it only when the malware itself was found. |
| `REVIEW` | An unusual change. Reported, never modified. |
| `INFO` | Context, for example files installed by a package. |

---

## ✅ After Triage

- Run the triage **before** you restart, reset or update, and keep the evidence archive.
- Install GL.iNet's security firmware **without keeping settings**, from a file you
  downloaded yourself.
- Change the device password, the GL.iNet cloud account password and the SSH keys.
- If the device was hit, replace every VPN profile and SSH key it held.
- Check the computer attached to a KVM, and the clients behind a router.
- If you switched SSH on for the check, switch it off again under Security, Admin Access,
  before firmware 4.9 under System, Security
  ([GL.iNet](https://docs.gl-inet.com/router/en/4/interface_guide/admin_access/#ssh)).
  A reinstall without settings switches it back on.

The reasons and the details per device: [After triage](docs/after-triage.md).

---

## 📚 Documentation

| Document | Content |
|---|---|
| [What the script looks for](docs/indicators.md) | Every indicator, with its source and how it is reported |
| [Options and report](docs/usage.md) | All options, and how to read the report |
| [What `--fix` does](docs/fix.md) | The cleanup, step by step |
| [Evidence archive](docs/evidence-archive.md) | What is in it and which secrets are taken out |
| [Anonymous report](docs/anonymous-report.md) | What is sent, what is not, and the device ID |
| [The result in plain words](docs/result-code.md) | How the short address under the verdict works |
| [Updating the script](docs/update.md) | `--update` and its signature check |
| [After triage](docs/after-triage.md) | What to do with a device that was hit |
| [Limitations](docs/limitations.md) | What the script cannot see |
| [Firmware notes](docs/firmware-notes.md) | What GL.iNet's KVM firmware 1.10.2 and 1.10.3 change |
| [Tests](docs/tests.md) | How to run the test suite |

> ⚠️ **The evidence archive can hold passwords, tokens and password hashes.** Never post
> it publicly or attach it to an issue.


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
