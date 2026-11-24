# Fingerprint Check

Part of the [gl-helper triage script](../README.md).

From 2.60 the script can ask the community's server whether the files it listed for
review are known: known malware, known to be all right, or not known. It asks only when
you agree, and only on the device itself (`--check` and `--archive`, not `--fix`). A file
that the community list knows as malware makes the result `INFECTED`; a file it knows as
all right keeps its `REVIEW` line and gets a note. The answer can only make the result
worse, never better: a trace the script found itself stays a trace, whatever the server
says.

## What is sent

For each file listed for review that has a fingerprint (at most 40):

- the SHA-256 of the line `<kind> <path>`, exactly as the anonymous report would carry kind
  and path (only the characters `A-Za-z0-9 ._:/+@=,()-`, the kind cut to 24 characters,
  the path to 160): the server can recognise a path it already knows and nothing else,
- the SHA-256 of the file.

And once: the version of the script and a random number for this run. Nothing else: no
path in clear text, no content of a file, no device ID, no model, no firmware, no host
name. The server stores none of it.

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

## How the server decides

For each line, the first that applies:

1. `known_bad`: the file's SHA-256 is in the table `bad_hashes` with `answer = 1`.
2. `known_safe`: a mark "probably safe" set on the dashboard (`labels`, verdict `safe`)
   whose key `<kind> <path>` has the SHA-256 asked and whose fingerprints include the
   file's; or the file's SHA-256 is in `known-hashes.json` (release files of the
   community's Tailscale and AdGuard Home builds, at any path).
3. `unknown`: everything else, including open or declined suggestions, a mark whose
   fingerprints do not include this file, and entries of `bad_hashes` with `answer = 0`.

Every line whose file is in `bad_hashes`, released or not, adds one to that entry's
`asked` and sets `asked_last` to the day. A file that is not in the table leaves no trace.

The check is on only when the worker has `LOOKUP = "on"` among its `[vars]`.

## What the script does with the answer

It takes an answer only when all of it fits: at most 8192 bytes, only the bytes above,
the first line, the nonce it sent, exactly the lines it asked in the same order, and only
the three words. Anything else and the whole answer is set aside, with one line saying so;
the result is what it would have been without the check. The same when there is no
connection or the certificate does not check out: the script asks over HTTPS only and
never falls back to plain HTTP or to an unchecked certificate.

| Answer | Effect |
| --- | --- |
| `known_bad` | a finding `IOC lookup-bad <path>`: verdict `INFECTED`, exit code 1, and the field for review in the result code is 2 |
| `known_safe` | the `REVIEW` line stays and is counted as before, with a note that the community list knows the file |
| `unknown` | nothing changes |

`--fix` does not remove a file found this way: it only removes what it knows. With
`--archive`, the request and the answer go into the archive as `lookup.txt`.

## Options

- `--lookup`: check without asking (what is sent is still shown).
- `--no-lookup`: never ask.
- Without either, the script asks on a terminal, and only when there is something to
  check. Without a terminal it sends nothing and says that `--lookup` would.
