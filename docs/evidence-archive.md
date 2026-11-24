# Evidence Archive

Part of the [gl-helper triage script](../README.md).

`gl-triage-<host>-<time>.tar.gz` contains the report, the findings, a listing and
SHA-256 hashes of the whole overlay upper layer, a full copy of the upper layer (up to
64 MiB), copies of all finding paths, process list with socket owners, decoded TCP
connections, the firewall rules and configuration, `/proc/<pid>/` data and the binary of implant processes, kernel and system
logs, and a `MANIFEST.sha256`. When there were files to ask the
[fingerprint check](lookup.md) about (since 2.60), `evidence/lookup.txt` says what came of
it, with the request when it was sent and the answer when it was used.

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
