# Fingerprint Check

Part of the [gl-helper triage script](../README.md).

From 2.60 the script can ask the community's server whether the files it listed for
review are known: known malware, probably safe, or not known. It asks only when you agree,
and only on the device itself (`--check` and `--archive`, not `--fix`). A file that the
community list knows as malware makes the result `INFECTED`; a file it has as probably
safe keeps its `REVIEW` line and gets a note. The answer can only make the result
worse, never better: a trace the script found itself stays a trace, whatever the server
says.

## What is sent

For each file listed for review that has a fingerprint (the report and the check take at
most 40 findings: programs first, then odd files and files in `/tmp`, then new and changed
files, then hidden ones and the rest; the script says how many it left out):

- the SHA-256 of the line `<kind> <path>`, exactly as the anonymous report would carry kind
  and path (only the characters `A-Za-z0-9 ._:/+@=,()-`, the kind cut to 24 characters,
  the path to 160): the server can recognize a path it already knows and nothing else,
- the SHA-256 of the file.

Accounts listed for review (`new-account`, `uid0-account`) are never asked: their line holds
the account's name, which could be guessed back from a hash, and `/etc/passwd` differs on
every device anyway.

And once: the version of the script and a random number for this run. Nothing else: no
path in clear text, no content of a file, no device ID, no model, no firmware, no host
name. The server stores none of it. A file's fingerprint is the same each time it is asked,
and the same as in the anonymous report: for a file that differs on every device, such as
`/etc/config/firewall`, it tells that device's file from others.

## The exchange

`POST https://app.gl-i.net/csa-2026-01-report/lookup`, body `text/plain`, at most 8192
bytes, lines ending in a single `\n` (no `\r`, no empty lines, one `\n` after the last
line). Only the bytes `0x0a` and `0x20` to `0x7e` may occur.

Request:

```
csa-2026-01-lookup 1
version 2.60
nonce 0123456789abcdef0123456789abcdef
<sha256 of "kind path"> <sha256 of the file>
<sha256 of "kind path"> <sha256 of the file>
```

| Line | Pattern |
| --- | --- |
| 1 | `^csa-2026-01-lookup 1$` |
| 2 | `^version 2\.[0-9]{1,3}$` |
| 3 | `^nonce [0-9a-f]{32}$` |
| 4 and on, 1 to 40 of them | `^[0-9a-f]{64} [0-9a-f]{64}$`, no line twice |

Answer, `200`, `text/plain; charset=utf-8`:

```
csa-2026-01-lookup-answer 1
nonce 0123456789abcdef0123456789abcdef
at 2026-11-24 16:40 UTC
<sha256 of "kind path"> <sha256 of the file> known_bad
<sha256 of "kind path"> <sha256 of the file> known_safe
<sha256 of "kind path"> <sha256 of the file> unknown
```

One line per line asked, in the same order, the two hashes as asked, then one of the
three words. The nonce is the one asked with. `at` is the time of the answer, UTC, to the
minute. Nothing else is in the answer: no reason, no note, no source.

Other answers, each a fixed text and never a part of the request:

| Status | Body | When |
| --- | --- | --- |
| `400` | `bad request` | any line or byte that does not fit the patterns above |
| `404` | `not found` | the check is switched off on the server |
| `405` | `method not allowed` | anything but `POST` |
| `413` | `too large` | more than 8192 bytes, by `content-length` or while reading |
| `503` | `not available` | the server's database failed while reading: no answer rather than one that misses an entry |

Each of these bodies ends in a single `\n`, as the worker's other plain-text answers do.

## How the server decides

For each line, the first that applies:

1. `known_bad`: the file's SHA-256 is in the table `bad_hashes` with `answer = 1`.
2. `known_safe`: a mark "probably safe" set on the dashboard (`labels`, verdict `safe`)
   whose key `<kind> <path>` has the SHA-256 asked and whose fingerprints include the
   file's; or the file's SHA-256 is in `known-hashes.json` (release files of the
   community's Tailscale and AdGuard Home builds, at any path). A mark holds every
   fingerprint that reports sent for its key, made-up reports included: so `known_safe` is
   never more than "probably safe".
3. `unknown`: everything else, including open or declined suggestions, a mark whose
   fingerprints do not include this file, and entries of `bad_hashes` with `answer = 0`.

The first request of a day that names an entry of `bad_hashes`, released or not, adds one
to its `asked` and sets `asked_last` to the day; later requests that day write nothing.
`asked` is the number of days on which the file was asked about, and an entry costs at
most one write a day, however many requests come. The server writes this after the
answer, so an entry that waits does not answer more slowly than a file nobody listed. A
file that is not in the table leaves no trace. Anyone can send requests: `asked` is a
hint, not a count of devices.

The check is on only when the worker has `LOOKUP = "on"` among its `[vars]`.

## What the script does with the answer

It takes an answer only when all of it fits: at most 8192 bytes, only the bytes above,
the first line, the nonce it sent, exactly the lines it asked in the same order, and only
the three words. Anything else and the whole answer is set aside, with one line saying so;
the result is what it would have been without the check. The same when there is no
connection, the certificate does not check out, or no answer came within 25 seconds: the
script cuts the answer at 8193 bytes while it arrives, and after 25 seconds it stops the
tool and gives up, whatever the tool's own limits are. From the line that says it is
asking, Ctrl-C does the same at once: it stops the check, not the run, says so in one line,
and the run goes on to its result.

It asks over HTTPS only and never falls back to plain HTTP or to an unchecked certificate.
`curl` and GNU `wget` follow no redirect (`curl` without `-L`, `wget` with
`--max-redirect=0`), so the request goes to this address only. OpenWrt's `uclient-fetch`
follows one; over HTTPS only the server or its host could send it.
It sends with `curl`, else OpenWrt's `uclient-fetch`, else GNU `wget`. busybox's own `wget`
is never used for it: that one takes any certificate. Without such a tool it sends nothing
and says so. `curl` runs with `-q` and GNU `wget` with `--no-config`, so that no settings
file of the tool changes where or how it sends. The request goes out once (`wget` with
`-t 1`); `--post-data` takes the place of `--post-file` only where the tool does not know
`--post-file`. The script does not depend on the `Content-Type` it can set, and neither
does the server.

| Answer | Effect |
| --- | --- |
| `known_bad` | a finding `IOC lookup-bad <path>`: verdict `INFECTED`, exit code 1, and the field for review in the result code is 2 |
| `known_safe` | the `REVIEW` line stays and is counted as before, with a note that the community list has the file as probably safe |
| `unknown` | nothing changes |

`--fix` does not remove a file found this way: it only removes what it knows. With
`--archive`, the request and the answer go into the archive as `lookup.txt`.

## Options

- `--lookup`: check without asking (what is sent is still shown).
- `--no-lookup`: never ask.
- Without either, the script asks on a terminal, and only when there is something to
  check. Ctrl-C at the question counts as no, and the run goes on to its result. Without
  a terminal it sends nothing and says that `--lookup` would.
- With `--fix` the check does not run; `--lookup` there only prints a line saying so.
