# After Triage

Part of the [gl-helper triage script](../README.md).

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
