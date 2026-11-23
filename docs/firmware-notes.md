# Firmware Notes

Part of the [gl-helper triage script](../README.md).

From the firmware images we compared (1.10.1 vs 1.10.2; both 1.10.2 builds are from 2026-11-21):

- **RM1PE 1.10.2** contains the boot cleanup in `/etc/init.d/S08overlayfs`.
- **RM1V2 1.10.2** does not contain it. Its `S08overlayfs` is unchanged.
- **RM1 1.10.2** does not contain it either, as [RemoteToHome found](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/kvm-firmware.md).
- **1.10.3** (and 1.8.7 for the RMQ1) runs the cleanup on all six models RemoteToHome
  read, without keeping a copy. An update with "Save current configuration" checked carried
  a boot script and an added SSH key into 1.10.3 on their test RM1.
- Both 1.10.2 builds change `rtty` (the cloud remote terminal): the `-s`, `-C/--cacert`
  and `-x/--insecure` options are gone, the CA path `/var/run/gl-rtty/ca.crt` is built
  in, and `S99rtty` no longer reads a `tls` setting from the cloud-provided config.
