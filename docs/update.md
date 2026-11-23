# Updating the Script

Part of the [gl-helper triage script](../README.md).

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
