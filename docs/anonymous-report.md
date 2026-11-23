# Anonymous Report

Part of the [gl-helper triage script](../README.md).

At the end of a run the script offers to send a short report to the community, so that
we can see which models and firmware versions were hit and when. It offers this on a
device without indicators too: those reports show which devices were not hit. At the end of its
run it says in a few lines what the report contains and sends it only after you answer
`y`; `v` first shows everything that would be sent: each part explained, your own lines
word for word, and the complete report. Without a terminal (for example through
`ssh ... 'sh -s'`) it never sends on its own; add `--report` to send. `--show-report`
prints the complete report and sends nothing, `--no-report` switches the offer off.

The report contains:

- script version, platform, model, firmware version, time of the check and uptime,
- the number of findings per label, and the kind and path of each `IOC` and `PERSIST`
  finding,
- whether GL.iNet's quick check hit, and for the remote shell its start time, the remote
  port and the time of its pipe,
- for the implant's own files and for replaced system tools the SHA-256, the size and two
  times: when the file was last written (mtime) and when its entry last changed on the
  device (ctime). The first can be set back with `touch`, the second cannot, so the two
  together show when the file really arrived,
- the time and size of the cloud handler's state file,
- whether GoodCloud and AstroWarp are switched on, with the version of the cloud client,
- whether the device is bound to a GoodCloud account, and whether remote SSH and the
  remote web interface through the cloud are on (since 2.28): yes, no or unknown each,
  never the account's name or address. With GoodCloud off, remote access is shown as not
  in use.

Since 2.35 it carries the note given with `--note`, empty without one. It is for people
who report many devices, to say where a report comes from, whether the device was
checked before or after a cleanup, or that it is a repeat. The script prints the note
as it will be sent before it asks.

Since 2.23 it also carries what the script listed for `REVIEW`: the kind and path of each
finding, at most 40, and for a file its SHA-256 and its two times. Descriptions are not
sent, because they can hold addresses, command lines and account names. An account that
the firmware does not have is sent with its name, number and shell and whether its
password field is empty, never a password or hash. These are not known traces. They are
sent so that a pattern across devices can be seen early: the older backdoor sat in
people's `REVIEW` lists for a day before anyone named it. The paths are shown before the
question, because a path of your own can say something about you. Together they can also
identify a device, so two reports from it can be recognized as belonging together even
with `--no-device-id`.

When indicators were found, it also contains what the attacker left, as text:

- `/etc/rc.local` in full when it was changed (up to 60 lines), because what surrounds
  the attacker's line matters too. From the other changed autostart files (the root
  crontab, init scripts that start the implant, `/etc/firewall.user` and `/etc/firewall.d`
  when they do) the lines that are not in the firmware image, up to 20 per file. From the lists of files a firmware update keeps, only the
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
never leaves the device. The server hashes the ID again with a secret of its own and
keeps only a short form of that. The ID makes the report pseudonymous rather than fully
anonymous: two reports from the same device can be linked to each other, but not to you.

One caveat: GL.iNet uses few address ranges, so whoever receives the ID as the script
sends it could find the hardware address by trying them all. The server does not do
that and does not keep the value it received. If that is not good enough for you, use
`--no-device-id`.

Apart from the lines and paths described above, the report contains no host name, no
key, no password and no other file. Those lines and paths are sent as they are, including
addresses of your network, names, and a password or token if you wrote one into such a
line. Before it asks, the script says in bold how many lines it sends, how many of them
hold IP addresses that are not the attacker's, and the name of every account it sends.
The receiving [worker](../worker/) stores no IP address.
