# Report worker

A Cloudflare Worker that receives the short, anonymous reports `gl-helper-triage.sh`
sends when its user agrees, and stores them in a KV namespace.

It stores the fields listed in `src/index.js` and the time of receipt. It does not store
the sender's IP address, country or any header, and its logs are switched off. Cloudflare
itself still sees the connection, as with every website behind it.

## Set up

Needs a Cloudflare account and Node.js. All commands run in this folder.

```bash
cp wrangler.example.toml wrangler.toml
```

`wrangler.toml` holds your own settings and is not in git, so `git pull` never collides
with it. To update the worker later: `git pull`, then `npx wrangler deploy`.

```bash
npx wrangler login
```

```bash
npx wrangler kv namespace create REPORTS
```

Copy the `id` it prints into `wrangler.toml` (replace `REPLACE_WITH_KV_NAMESPACE_ID`).
Older wrangler versions spell the command `kv:namespace create`.

```bash
npx wrangler deploy
```

With `workers_dev = false`, as in the template, the worker has no address yet; it gets
one in the next section.

```bash
npx wrangler secret put EXPORT_TOKEN
```

Enter a long random value. It protects the export; without it the export does not exist.

## Give it its address

The script sends to `https://app.gl-i.net/csa-2026-01-report`. A redirect to the
`workers.dev` address does not work: `curl` and `wget` turn a redirected POST into a GET.
The worker has to answer on that address itself. With `gl-i.net` as a zone in the same
Cloudflare account and `app.gl-i.net` proxied (orange cloud), add this to `wrangler.toml`
and deploy again:

```toml
routes = [{ pattern = "app.gl-i.net/csa-2026-01-report*", zone_name = "gl-i.net" }]
```

If `app.gl-i.net` is not behind Cloudflare, set `workers_dev = true`, use the
`workers.dev` address and change `REPORT_URL` in `gl-helper-triage.sh`. The rules of the
zone (see "Protect it") do not apply to that address.

## Check it

```bash
curl https://app.gl-i.net/csa-2026-01-report
```

```bash
curl -H "Authorization: Bearer <EXPORT_TOKEN>" https://app.gl-i.net/csa-2026-01-report/export
```

With `?all=1` the export returns every report in one answer (from D1). Without it, the
export returns a page of reports as JSON lines (500 from D1, 40 from KV). When there are more, the response
header `x-next-cursor` has the value for `?cursor=`.

To test a full round, run the script on a device with `--report`. It sends a report even
when nothing was found.

## Moving the reports to D1

KV on the free plan allows 1,000 writes and listings a day, which is a few hundred
reports. D1, Cloudflare's database, allows 100,000 written rows a day, and the dashboard
gets all reports with a few queries instead of one read per report. The worker uses D1
as soon as a database is bound as `DB`, and KV until then. The KV namespace stays: the
script download keeps its copy there.

The free plan also allows 100,000 KV reads and 100,000 calls of the worker a day. The
script, the firmware list and the reported table are therefore read through the memory
of the worker, each key at most once a minute. When KV refuses reads anyway, the script
download sends the client to GitHub, `reported.json` answers 503 and the result page
goes without the firmware list. Against the limit on calls only the paid plan helps.

1. Create the database. The command prints a `database_id`.

   ```bash
   npx wrangler d1 create csa-2026-01
   ```

2. Create the table.

   ```bash
   npx wrangler d1 execute csa-2026-01 --remote --file=schema.sql
   ```

3. Add the database to `wrangler.toml`, as a section of its own at the end, and deploy.

   ```toml
   [[d1_databases]]
   binding = "DB"
   database_name = "csa-2026-01"
   database_id = "the id from step 1"
   ```

   ```bash
   npx wrangler deploy
   ```

   From now on new reports go to D1. The dashboard shows only those until step 4 is done.

4. Copy the reports that are in KV. Each call copies 40 and says how to go on; repeat it
   with the `cursor` it returns until `cursor` is empty. Calling it again does no harm:
   a report that is already in the table is skipped. KV is not changed.

   ```bash
   curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" "https://app.gl-i.net/csa-2026-01-report/migrate"
   ```

   ```bash
   curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" "https://app.gl-i.net/csa-2026-01-report/migrate?cursor=<cursor from the answer>"
   ```

   The answer looks like `{"copied":40,"in_database":40,"cursor":"..."}`.

5. Check: the dashboard shows the same number of reports as before, and

   ```bash
   npx wrangler d1 execute csa-2026-01 --remote --command "SELECT count(*) FROM reports"
   ```

   gives the same number.

To go back, remove the `[[d1_databases]]` block and deploy: the worker uses KV again.
Reports that arrived in D1 in the meantime are then not shown.

## Marking findings

The dashboard lists what the scripts sent for review. Everyone who may open the dashboard
may mark such a finding, with a short note, in the block "Unusual changes seen on several
devices" or inside a single report:

- "Probably safe": hidden for everyone unless they ask to see it.
- "Probably not safe": stays listed, with the mark. Only the team sees it.
- "Known malware": stays listed, with the mark, and the fingerprint check answers
  `known_bad` for it: a device that sends such a file turns `INFECTED` on its next check.
  Before saving, the dashboard says how many devices in the loaded reports carry the
  finding and how many of them show no traces.

Each mark records who set it (the address Cloudflare Access signed in) and when.

A mark belongs to a kind and a path and remembers the fingerprints known for that path at
the time. A file with another fingerprint at the same path brings the finding back, as "new
file at a path marked safe": a replaced file is exactly what should not stay hidden. Where
every device has its own file at a path (`/etc/sysupgrade.conf`, or a loader that differs
from device to device), a mark can hold for every file at its path, also new ones. For
"probably safe" that only hides them on the dashboard: the check still calls only the
fingerprints the mark holds probably safe. For "known malware" the check answers
`known_bad` for any file at that path.

A mark holds at most 60 fingerprints, and never those of known release files: the check
calls a release file probably safe whatever a mark says, so a mark "known malware" for one
odd file at `/usr/sbin/tailscaled` does not hit the devices with the release. For more
than 60 files at a path, "known malware" needs "every file at this path". A mark "known
malware" for an account changes nothing for the check: the script never asks about
accounts. Without D1 there is no malware list, and the dashboard offers none.

A single file can also go on the community list as malware, at any path: the button in
the "Fingerprints" table of a finding or in "Malware files". It is then an entry of
`bad_hashes` with `answer = 1`, as if it had been loaded as SQL; an entry that waited
(`answer = 0`) keeps its counter. A copy of a system program has that program's
fingerprint (the older backdoor's `monitord` is a copy of `lua`): such a file must not go
on the list.

A click on a finding opens it in the side panel: the devices that sent it, the
fingerprints behind its path with the number of devices for each, the models and
firmware, and when the entry changed on the devices. That is what to look at before
marking something.

The "Review" page of the dashboard lists every mark with its comment, who set it and
when, and the files on the community list, and from there a mark or a file can be removed.

The marks are kept in the D1 table `labels`, which the worker creates on first use (and
to which it adds the column `every`), or in one KV entry when there is no database. They
can be read at `<worker>/dashboard/labels` with the dashboard's login, together with the
entries of `bad_hashes`; the dashboard changes the list at `<worker>/dashboard/bad-hashes`
(POST, `{ "sha256", "verdict": "malware" or "", "note" }`), which needs D1. From script
2.60 the fingerprint check asks for them (see "Fingerprint check" below).

### Suggestions

A suggestion is a mark that waits for a yes: a finding that an analysis of the reports
takes for probably safe, with its reason and the fingerprints it covers. It hides nothing.
The "Review" page lists open suggestions above the marks. "Confirm safe" turns one into a
mark in your name, for exactly its fingerprints and with its reason; "Decline" keeps it
on the server with your name, so that the same suggestion loaded again does not come
back. The finding then stays listed as before.

Suggestions come in as SQL and need D1. The list itself stays outside the repository,
because its paths and fingerprints come from the reports:

```bash
node tools/suggestions-sql.mjs suggestions.json > suggestions.sql
npx wrangler d1 execute csa-2026-01 --remote --file=suggestions.sql
```

`suggestions.json` is `[{ "key": "kind path", "note": "why", "hashes": [...] }, ...]`, each
entry checked as the dashboard checks a mark. A key that is already there, as a suggestion
or as a declined one, is left as it is. They are kept in the D1 table `suggestions`.

## Fingerprint check

From script 2.60 the script can ask the worker whether the files it listed for review are
known: known malware, known as probably safe, or not known. It asks only after its user
agreed (or with `--lookup`), only on the device itself, and only for files with a
fingerprint, at most 40. For each file it sends two SHA-256 values: of the line
`<kind> <path>` exactly as the report would carry them, and of the file. Once per request
it sends the script's version and a random nonce. No path in clear text, no device ID, no
model. The exchange is fixed in [`../docs/lookup.md`](../docs/lookup.md), and the worker
does exactly what it says.

The script posts to `https://app.gl-i.net/csa-2026-01-report/lookup`; the route for
`app.gl-i.net/csa-2026-01-report*` already covers it. The answer has one line per line
asked, in the same order, each with one word:

- `known_bad`: the file is in the table `bad_hashes` with `answer = 1`; or a mark "known
  malware" whose key `<kind> <path>` has the SHA-256 asked holds for every file at its path
  or for this file's fingerprint.
- `known_safe`: a mark "probably safe" whose key `<kind> <path>` has the SHA-256 asked and
  whose fingerprints include the file's (also when the mark holds for every file at its
  path); or the file is a known release file (`src/known-hashes.json`), at any path.
- `unknown`: everything else, also marks "probably not safe", open or declined suggestions
  and entries of `bad_hashes` with `answer = 0`.

The answer can only make the script's result worse: `known_bad` makes it `INFECTED`,
`known_safe` only adds a note to a `REVIEW` line. A mark holds every fingerprint that
reports sent for its key, made-up reports included, so the script shows `known_safe` as
"probably safe" and keeps the file listed for review.

The worker takes every request for an attack. It refuses a body over 8192 bytes, by its
`content-length` and while reading it, so a missing or false length does not help. Before
anything is decoded it checks every byte: only `0x0a` and `0x20` to `0x7e` may occur. Then
every line must fit its fixed pattern. Anything else gets a fixed text (`400 bad request`,
`413 too large`), never a part of the request; when D1 or KV fails while reading, the answer
is `503 not available` rather than one that misses an entry. **Nothing of a request is
stored or logged**; the only write is the counter of a `bad_hashes` entry that was asked
for, at most once a day per entry, made after the answer, so the answer takes no longer for
an entry that waits than for a file nobody listed. Made-up requests can therefore not run
up D1 writes: with the 14 entries of the first fill there are at most 14 a day. Each
worker instance reads the marks at most once a minute, so a mark set or removed on the
dashboard counts a minute later at the latest (at once in the instance that saved it).

### Switch it on

The check is off until this line stands in the `[vars]` block of `wrangler.toml` (the block
that holds `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`; a file may have only one) and the worker
is deployed again:

```toml
[vars]
LOOKUP = "on"
```

Without it, the address answers `404 not found` to every method, and the script goes on
without the check. Removing the line and deploying switches the check off at once, for
example if someone who should not could set marks on the dashboard.

Add a rate limiting rule for it, see "Protect it".

### Known malware: the table bad_hashes

The D1 table `bad_hashes` lists files known as malware, by SHA-256. It is in `schema.sql`,
and the worker creates it on first use. Without D1 there is no such table, and the check
answers only `known_safe` and `unknown`.

| Column | Meaning |
| --- | --- |
| `sha256` | of the file, 64 lowercase hex characters |
| `note` | what it is, for the maintainers; never sent |
| `answer` | `1` released: the check answers `known_bad`. `0` waiting: it counts as not known |
| `by`, `at` | who added or last changed the entry, and when |
| `asked` | on how many days a check asked for the file (one a day, however many requests), released or not. Anyone can send requests: a hint, not a count of devices |
| `asked_last` | the last of those days, `YYYY-MM-DD` |

The first fill takes the fingerprints the script itself carries in public (`GLH_SHAS`,
`BD_INIT_SHA`, `BD_ULOGD_SHAS`), each released:

```bash
node tools/bad-hashes-sql.mjs --script ../gl-helper-triage.sh > bad-hashes.sql
npx wrangler d1 execute csa-2026-01 --remote --file=bad-hashes.sql
```

Further entries come from a list that stays outside the repository:

```bash
node tools/bad-hashes-sql.mjs bad-hashes.json > bad-hashes.sql
npx wrangler d1 execute csa-2026-01 --remote --file=bad-hashes.sql
```

`bad-hashes.json` is `[{ "sha256": "...", "note": "what it is", "answer": 0 }, ...]`,
optionally with `"by"` and `"at"` (ISO time). The tool checks every entry (64 lowercase hex
characters, a note of 1 to 200 printable ASCII characters, an answer of 0 or 1) and stops
at the first that does not fit.

To release an entry, load it again with `"answer": 1`; with `"answer": 0` it is withdrawn.
Loading an entry again changes its note, answer, `by` and `at`, never its counter. An entry
with `answer = 0` changes no answer but is counted, so a file that comes up on many devices
shows before anyone vouches for it.

The counters:

```bash
npx wrangler d1 execute csa-2026-01 --remote --command "SELECT sha256, answer, asked, asked_last, note FROM bad_hashes ORDER BY asked_last DESC, asked DESC"
```

## Telling devices apart

From script 2.9 a report carries a device id, so that ten reports from one device are not
read as ten devices. The script sends a hash of a hardware address. Such a hash can be
reversed by trying all addresses of a manufacturer, so the worker does not store it: it
stores an HMAC of it with a secret, shortened to 12 characters. Set the secret once:

```bash
npx wrangler secret put DEVICE_SALT
```

Enter a long random value and keep it: with a new value the same device gets a new id,
and reports before and after no longer match. Without the secret the worker drops the id
and every report counts on its own, as before.

In the dashboard "One row per device" folds repeated reports into one. The report with
the most known traces stands for the device, so a device that was hit and later cleaned
still counts as hit.

## Serving the script

The worker also serves the script itself at `https://app.gl-i.net/csa-2026-01-fix`, so a
change is available at once. (A redirect to `raw.githubusercontent.com` shows the old
file for up to five minutes after a push.)

The worker takes the script only from the `main` branch of this repository. It asks
GitHub which commit `main` points to (the way `git` does, not through the API with its
limit on anonymous calls), fetches `gl-helper-triage.sh` by that commit and
keeps it in KV. The response header `x-script-commit` says which commit is served.

- `.github/workflows/publish-script.yml` calls `POST /csa-2026-01-fix/refresh` after every
  push that changes the script. The call needs no secret: it can only bring the copy in
  line with `main`, and the worker answers it at most every 30 seconds.
- Without that call the worker checks by itself when its copy is older than 10 minutes.
- If GitHub cannot be reached, the stored copy keeps being served.

To switch over, add a second route in `wrangler.toml` and deploy:

```toml
routes = [
  { pattern = "app.gl-i.net/csa-2026-01-report*", zone_name = "gl-i.net" },
  { pattern = "app.gl-i.net/csa-2026-01-fix*", zone_name = "gl-i.net" },
]
```

Then remove the redirect rule that sends `/csa-2026-01-fix` to GitHub. As long as it
exists, Cloudflare answers with the redirect and the worker is never asked.

```bash
curl -sI https://app.gl-i.net/csa-2026-01-fix
```

shows `x-script-commit` when the worker answers, and `location:` when the redirect is
still in place.

## The script's signature

`sh gl-helper-triage.sh --update` takes a new version only with a signature that fits a
key built into the script. The pieces:

- **The key.** Made once with `signify -G -n -p csa-update.pub -s csa-update.sec`. The two
  lines of the `.sec` file are the secret `UPDATE_SIGNING_KEY` of the repository. The
  base64 line of the `.pub` file stands in `UPDATE_KEYS` in the script and in
  `UPDATE_KEYS` in `src/index.js`; a test compares the two. A second key is the spare:
  its `.sec` file is kept offline, its public line stands next to the first.
- **Signing.** The workflow "Publish script" signs the script after every push to `main`
  that changes it and posts the signature to `/csa-2026-01-fix.sig`.
- **The worker.** It checks the signature itself, against the script it serves and the
  public keys, and keeps it with the fingerprint of that script. It hands it out at
  `https://app.gl-i.net/csa-2026-01-fix.sig` only while that script is served; otherwise it
  answers 404 and `--update` leaves the device's script alone. Posting needs no secret:
  nothing but a real signature is taken.

To replace a lost or stolen key: make a new pair, sign one release by hand with the spare
key so that devices take it, and put the new public line into the script and the worker
with that release.

## Dashboard for the team

`https://app.gl-i.net/csa-2026-01-report/dashboard` shows what the reports add up to:
how many devices have traces and of which kind, when it started, which models and
firmware builds, the malware's files by fingerprint, and the commands, autostart lines
and firewall rules the attacker left, with identical ones grouped.

It has six pages: Overview (the counts, when it started, whether it is still going on,
how an attack ran), Devices & firmware, Attack (evidence, malware files, ports, what the
attacker left), Older backdoor, Review (unusual changes, what was marked as probably
safe, known release files) and Reports, a sortable, paged table. A row opens the report
in a panel beside the table, with arrows to step through the rows; a finding from the
review list opens there too, and so does the glossary. On a wide window the panel stands
beside the page, which makes room for it; drag its left edge to change its width (kept per
browser, a double-click on the edge goes back to the usual width); the arrows in its title
show it over the whole window, with the details in two columns, and Esc goes back. Long lists in it, such
as many findings of one kind, show their first lines and the rest on request. What a card shows and how to
read it is behind the i next to its title. The arrows at the right of a title show the card over
the whole page. Table headings stay in view while the rows scroll.

Beyond the counts it shows how an attack ran (the middle value of each time in the
reports, with how long the attacker was active and how long it took to find), the ports
of the remote shells and whether they were handed out in order, and a grid of models by
firmware versions with the share of devices that had traces. "Copy as advisory YAML"
turns that grid into the `reported` block of the advisory on gl-i.net. A report that
carries something no other device has (a file fingerprint, a command, an autostart line)
is marked "Unusual". Firmware is shown as the version, with beta or rc where there is
one; the build number and date are in each report.

The filters, the page, an open report or finding and a card shown over the whole page
are kept in the address, so a link shows someone else the same view. Links from before
the pages (`view=safe`, `view=item`) still work. The page offers the reports that are
new since your last visit.

"Edit layout" arranges the cards: on a grid of twelve columns, each card spans a number
of columns and rows. Drag the dots before a title to move a card, drag its corner to
resize it (a double click on the corner gives it the template's size), move it to
another page or hide it. Cards are placed in their order, and a card that fits goes
into a gap left above it. Three templates (Standard, Compact, Large) give every card its
page and size; "Back to the template" undoes what was changed by hand. The layout is
kept in the browser (localStorage), not on the server, so each person has their own.
The layout of before (order, hidden cards, widths) is taken over once. On a phone the
cards stand in one column, and the layout cannot be edited there.

Everything can be filtered: by device, firmware and kind of evidence (lists with counts),
by result, device type, time received and whether the device was restarted since the
attack, and by free text; the last two and the view switches are under "More filters".
Bars and chart columns set a filter when clicked, and the large numbers lead to the
reports behind them. "Export CSV" downloads the reports that match. All times are UTC,
to the minute.

The page keeps itself up to date: every 20 seconds it asks for the time of the newest
report and fetches new reports only when that has moved. New rows are highlighted, an
open report stays open, and "Live: off" stops it. Only the page in view is drawn again.
Polling pauses while the tab is in the background.

The page loads all reports into the browser: 500 per request from D1, 40 from KV (the
free Workers plan allows 50 subrequests per request, and every KV read is one). With KV
a new report can take up to a minute to appear and costs two writes.

The page is `src/dashboard.html`. The worker imports `src/dashboard.js`, which
`node build.mjs` generates from it; run that after every change to the page.
It is for the team only. Cloudflare Access sits in front of it, and the worker checks the
signature Access adds to every request. Until both settings below are present, the
dashboard answers "not found" for everyone.

1. In the Cloudflare dashboard open **Zero Trust → Access → Applications** and add a
   **self-hosted** application:
   - domain `app.gl-i.net`, path `csa-2026-01-report/dashboard`
   - a policy with action **Allow** that lists the e-mail addresses of the team

   Only this path. The address the script posts to must stay open, or routers cannot
   send reports.
2. Note two values: the **Application Audience (AUD) tag** of the application, and your
   **team domain** (Zero Trust → Settings, it looks like `yourteam.cloudflareaccess.com`).
3. Add them to `wrangler.toml`, above the first `[section]`, and deploy:

   ```toml
   [vars]
   ACCESS_TEAM_DOMAIN = "yourteam.cloudflareaccess.com"
   ACCESS_AUD = "the AUD tag"
   ```

   A `[vars]` block is a section of its own: put it after `routes = ...` and before or
   after the other sections, not inside `[[kv_namespaces]]`.

   ```bash
   npx wrangler deploy
   ```

Team members open the address, sign in with the one-time code Access mails them, and see
the table. The names of the menus in the Cloudflare dashboard change now and then.

## Protect it

Anyone can send made-up reports; the worker only checks their shape and size (48 KiB).
The spending limit for Workers ends every call once it is reached, and with it every KV
and D1 access, but it does not count KV and D1 themselves. Two settings keep made-up
calls from costing anything:

- A rate limiting rule in the `gl-i.net` zone (Security, WAF, Rate limiting rules),
  counted per IP address, for the paths where every call reaches KV or D1:
  `/csa-2026-01-report`, `/csa-2026-01-report/lookup` (the fingerprint check, which the
  script asks once per run), `/csa-2026-01-fix.sig` and `/csa-2026-01-fix/refresh`. On the
  Free plan of the zone a rule can match only the path, counts over 10 seconds and
  blocks for 10 seconds; 3 requests per 10 seconds leave room for the script and for the
  publish workflow, which calls every 35 seconds. The worker takes reports only at
  `/csa-2026-01-report`, and the fingerprint check only at `/csa-2026-01-report/lookup`;
  a POST to any other address neither stores a report nor answers a check, so these
  paths cover them all.
- `workers_dev = false` and `preview_urls = false` in `wrangler.toml`: the rules of the
  zone apply only to its own addresses, and the `workers.dev` address would skip them.

## Schema validation in front of the worker

`openapi.json` describes the one address the script posts to, for Cloudflare's schema
validation (Security, API Shield, Schema validation: upload the file). Cloudflare then
checks a report before the worker runs: only the known fields, each of its type, length and
characters.

- The file is the union of schema versions 1 to 10: the fields of version 1 are required,
  the later ones allowed. The worker stays the stricter check and requires every field of
  the version a report names.
- Check the size limit of your plan first. Cloudflare inspects a body only up to a size
  that depends on the plan (at the time of writing: Free 1 KiB, Pro and Business 8 KiB,
  Enterprise 128 KiB), and a larger body counts as a violation. Reports are up to 48 KiB;
  of those received so far, four in ten are larger than 1 KiB and a few larger than
  8 KiB. Below Enterprise, "Block" therefore stops real reports, however right the schema
  is. Then leave the validation off or at "Log": the worker checks every report anyway.
- Start with the action "Log", look at what it would have stopped, then switch to "Block".
  The script does not show a failed send as an error, so a wrong rule loses reports unseen.
- It covers `POST /csa-2026-01-report` only. Leave the action for addresses that are not
  in the schema at "none": the dashboard and the export live under the same path.
- The fingerprint check, `POST /csa-2026-01-report/lookup`, is not in `openapi.json`: its
  body is lines of text, not JSON. It stays at "none" as well; the worker checks every
  byte of it itself.
- A new schema version goes into `openapi.json` and into Cloudflare before a script sends
  it, like the worker itself. The tests fail when a field is missing in the file.

## Tests

```bash
node test/run.mjs
```

```bash
node test/run.mjs serve
```

The second command serves the worker on `127.0.0.1:8787` with storage in memory, KV and
a D1 database, and with the fingerprint check switched on. Point the script at it with
`GL_TRIAGE_REPORT_URL=http://127.0.0.1:8787/csa-2026-01-report` (the worker takes reports
only at that path) and, for the check, with
`GL_TRIAGE_LOOKUP_URL=http://127.0.0.1:8787/csa-2026-01-report/lookup`. For each report it
prints the status and the stored report, for each check the status and the answer.

A seed file fills the check, so that a run of the script can get every answer:

```bash
node test/run.mjs serve seed.json
```

```json
{ "labels": { "changed /etc/init.d/example": { "hashes": ["<sha256 of the file>"] } },
  "bad_hashes": [{ "sha256": "<sha256 of a file>", "answer": 1 }] }
```

Each label is set as a mark "probably safe", checked as the dashboard checks one; each
entry goes through `tools/bad-hashes-sql.mjs`, with the note "seed" unless it has one.

## The page that explains a result

`src/result.html` is a page for people who cannot do much with the script's output. Under
its verdict the script prints an address like

```
https://csa.gl-i.net/#AA006011D
```

and the page behind it says in plain words what was found, what that means and what to do,
in English, German and Chinese. Over ssh the address often cannot be clicked and has to be
typed, so the result is nine characters. Without a code the page offers a field to type
one into and a short list to tick by hand.

- The code stands after `#`. A browser does not send that part of an address, so the
  worker serves the same page to everyone and learns nothing about a device. A code typed
  without the `#` (`csa.gl-i.net/aa006011d`) works too; then it reaches the worker as the
  path, and the page moves it behind the `#` at once.
- Capitals do not matter, dashes and spaces are ignored. The alphabet has 32 characters
  without I, L, O and U; a typed I or L is read as 1, an O as 0.
- Eight characters hold 40 bits: 7 the script's version (the number after `2.`), 2 the
  device (unknown, router, KVM), 24 one per kind of finding (22 used), 2 GoodCloud (not
  known, on, off), 1 restarted since the attacks began, 2 what `--fix` did (not run, done,
  incomplete), 2 whether other changes are listed for review (0 none, 1 some, 2 some, and
  the fingerprint check found one of them to be known malware; 3 is unused and read as 1).
  With 2 the page explains that finding as a known trace: the device counts as infected,
  and `--fix` does not remove the file. Never a path, a name or an
  ID. The verdict is not in the code: it follows from the kinds of findings.
- The ninth character is a check: the sum of the eight values, each times its position,
  modulo 31. A single wrong character is caught in all but one rare case, two neighbours
  typed the wrong way round always. The page then says that the code is not valid, and
  does not explain somebody else's result.
- The order of the kinds is `RESULT_KINDS` in the script and `ORDER` in the page, and it
  may only grow at the end. The worker's tests fail when the two differ, when a language
  lacks a text another one has, or when a plan names a step without a text; the script's
  tests read every code they produce back with the page's own reader.
- Where the script knows model and firmware, five more characters follow after a dash:
  `csa.gl-i.net/#AA006011D-2PJ2W`. Four hold 20 bits (7 the model as its place in
  `RESULT_MODELS` / `MODELS`, 2 + 5 + 5 the three numbers of the firmware version, 1 a test
  build), the fifth is their check character, tied to the check character of the first
  nine. The first nine work without them. A model and a version, never a serial number:
  nothing in the code tells one device from another of its kind. The list of models may
  only grow at the end.
- With model and version the page says whether newer firmware exists. The worker takes
  the newest release and beta per model from `firmware.gl-i.net/api/all.json` (the firmware
  archive, built every few hours), keeps the list in KV, fetches it again at most once an
  hour and puts it into the page; when the archive cannot be reached, the copy here keeps
  being used, and without one the page says nothing about firmware. Only entries that look
  like a model name and a version get in. The page compares versions number by number,
  names the date of the list, and does not claim that a version closes the hole.
- Scripts 2.39 and 2.40 printed a longer form, `csa.gl-i.net/2026-01/#v=2.39&p=r&...`.
  It still works.
- The worker puts in the version of the script it serves, and the page warns when a result
  comes from an older one.

It is served without a login at `/` and at `/<nine characters>` on a host whose name begins
with `csa.`, and at `/2026-01/` on every host. For `csa.gl-i.net`, add the host to the
routes in `wrangler.toml` and deploy:

```toml
routes = [
  { pattern = "app.gl-i.net/csa-2026-01-report*", zone_name = "gl-i.net" },
  # ... the routes you already have ...
  { pattern = "csa.gl-i.net", custom_domain = true },
]
```

A new form of the address must be understood by the page before the script prints it:
deploy the worker first, then publish the script.

After a change to the page: `node build.mjs`, which also writes `src/result.js`.

## The table for the advisory

`https://csa.gl-i.net/2026-01/reported.json` gives the models and firmware versions on
which the reports show traces of the attack of 20 November. The advisory on gl-i.net reads
it and adds it to the table it keeps by hand. Open to all, no login:

```json
{ "advisory": "CSA-2026-01", "as_of": "2026-11-22T18:30Z", "min_devices": 5,
  "models": [ { "model": "mt6000", "sku": "GL-MT6000", "kind": "Router", "firmware": ["4.8.3", "4.9.1"] } ] }
```

Nobody reads this list before a public page shows it, and anyone can send a report. So a
model and version are listed only when all of this holds:

- At least five different devices reported traces on them. Only reports with a device id
  count; without one, two reports of the same device cannot be told apart. Reports of the
  first day, sent by scripts that had no id yet, therefore do not count here.
- The firmware archive knows the model, and the version looks like a version.
- The firmware is older than the attack. A trace on a build from 20 November on was
  brought along by an upgrade or is something new; both are for a person to look at, and
  for the table kept by hand.

A device counts for the firmware of its first report with traces, so that checking,
upgrading and checking again does not move a trace to the new firmware. "Traces" means
what the dashboard counts under "With traces": the older backdoor is left out.

The list says nothing per device or per report, and no numbers. It is worked out at most
every 15 minutes and kept in KV in between. It needs the reports in D1; without the
database the address answers 503, and the advisory shows its own table alone.

Each run reads only the reports received since the last one (with two minutes of
overlap), through the index on `received`. Which device had its first report with traces
on which firmware is kept in KV under `reported/csa-2026-01-devices`, with how far the
reports have been read. When the rules for a trace change in the code, or that entry is
missing, the next run reads all reports once. To force that, delete the entry:
`npx wrangler kv key delete --remote --binding REPORTS reported/csa-2026-01-devices`.

## Version and table for the pages on gl-i.net

`https://csa.gl-i.net/2026-01/live.json` gives what the advisory and the fix guide show
between two builds, in one small answer: the version of the script served now with its
release time, and the table above. A reader's browser asks for it once per page, instead
of fetching the whole script for its version and the table in a second call.

```json
{ "script": { "version": "2.55", "released": "2026-11-24T14:41:00Z" },
  "reported": { "advisory": "CSA-2026-01", "as_of": "2026-11-25T08:22Z", "min_devices": 5, "models": [] } }
```

It takes nothing in: GET and HEAD only, parameters, headers and bodies are not read, and
it answers the same to everyone. A part that is not known is `null`. Browsers may keep it
for a minute. Deploy the worker before the website uses the address.

## Known release files

`src/known-hashes.json` lists the SHA-256 of every binary in the releases of the
community's Tailscale and AdGuard Home builds, taken from the `checksums.txt` of each
release in `admonstrator/glinet-tailscale-updater` and `admonstrator/glinet-adguard-updater`.
`build.mjs` puts the list into the dashboard. A finding whose every reported file has one
of these fingerprints is a known release file: it is hidden like a finding marked as
probably safe, needs no mark, and is listed with its release on the "Review" page.
Another file at the same path is still listed for review.

After a new release:

```sh
sh tools/known-hashes.sh
node build.mjs
```

A release that was built again keeps only its latest checksums, so an older build of the
same version is not in the list. The list only ever hides review findings; it never
changes whether a device counts as hit.

The fingerprint check answers `known_safe` for these files too, at any path. `build.mjs`
writes their fingerprints into `src/known.js`, which the worker imports; the tests fail
when that file does not match `known-hashes.json`.
