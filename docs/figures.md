# Figures for the advisory

Part of the [report service](../worker/README.md).

The advisory on gl-i.net shows figures from the anonymous reports: how many devices sent
one, how many of them show traces, the three charts and a few more. Until 28 November 2026
they were worked out by hand from an export and typed into the page. From now on the
worker works them out, the same way, and gives them in the `figures` part of
`https://csa.gl-i.net/2026-01/live.json`. The page takes them at its daily build and again
in the reader's browser. This file is the contract between the two.

## The method

One way of counting, the one the page has used since 21 November:

- Every report goes through `shape()`, the function the dashboard uses (`src/shape.js`,
  written from `dashboard.html` by `build.mjs`). "With traces" means `ioc > 0` after
  `shape()`: the attack of 20 November, the older backdoor counted apart.
- **A device** is one device ID. Of its reports, the one with the most traces counts, and
  of those the newest. A report without a device ID counts as a device of its own.
  Reports that `shape()` marks `isTest` count for nothing; a device whose chosen report is
  such a test drops out. This is "the pool".
- **Security firmware**: a router whose firmware string ends in a build date of
  2026-11-22 or later; a KVM on `V1.10.3 release1`, or a GL-RMQ1 on `1.8.7`. "Updated"
  means on security firmware, "open" means not.
- Routers are `type === 'Router'`, KVM devices `kvm === true`, both as `shape()` sets them.

## The answer

```json
{
  "as_of": "2026-11-28T12:56Z",
  "devices": 3747, "routers": 3169, "kvm": 578,
  "updated": { "routers": [1, 1115], "kvm": [0, 239] },
  "open": { "routers": [831, 2054], "kvm": [177, 339] },
  "cleaned": { "routers": 81, "kvm": 44, "still": 0 },
  "shell": 72,
  "goodcloud": { "on": [490, 880], "off": [105, 665] },
  "pipe": { "since22": 39, "since24": 9, "last": "2026-11-28" },
  "newest_command": "2026-11-21T18:58Z",
  "backdoor": { "devices": 127, "mt2500": 70, "after_update": 18 },
  "kvm_release": { "rm10_release8": [8, 10, 5], "rm10rc_release3": [4, 6, 2] },
  "series": [{ "name": "4.6 and older", "hit": 0, "of": 196 }, { "name": "4.7", "hit": 87, "of": 125 }],
  "sweep": [{ "model": "GL-AXT1800", "at": "2026-11-20T22:15Z", "n": 65, "of": 68 }],
  "hours": [{ "hour": "2026-11-20T20", "n": 27 }],
  "hours_routers": 828
}
```

The values are those of the export of 28 November 2026, 12:56 UTC (the lists shortened
here). A pair `[a, b]` is "a with traces of b"; a triple adds "with the malware's files".
Times are UTC to the minute, cut, not rounded; `pipe.last` is a day. All counts are whole numbers from 0.
A time a device gives (`pipe_time`, `state_file_time`) that is more than 10 minutes later
than the report's `received` comes from a wrong clock and is left out wherever a time is used.

| Field | What it counts |
| --- | --- |
| `as_of` | The time the figures were worked out (in a tool run on an export: the newest `received`). |
| `devices`, `routers`, `kvm` | Routers and KVM devices in the pool; `devices` is their sum. |
| `updated.*` | Routers / KVM devices in the pool on security firmware: with traces, all. |
| `open.*` | The same for those not on security firmware. |
| `cleaned` | Devices (with an ID, test reports left out) with a report with traces on other firmware and, received later, a report on security firmware. Counted as router or KVM by the last of those later reports. `still`: those where one of the later reports has traces. |
| `shell` | Devices in the pool whose report shows the remote shell (`shape()`'s `shell`). |
| `goodcloud` | Open routers in the pool with `goodcloud` `on`, and `off`: with traces, all. |
| `pipe` | Reports (tests and security firmware left out) whose `pipe_time` is 22 November or later, by device (ID, else the report): how many devices, how many of them with their latest such time on 24 November or later, the day of the latest time (`2026-11-28`). `last` is `null` when there is none. |
| `newest_command` | The newest `state_file_time` of a report (tests and security firmware left out) whose kinds include `cloud-command`. `null` when there is none. |
| `backdoor` | Devices (ID, else the report; tests left out) with any report of the older backdoor (`shape()`'s `bd`): how many, how many of them on a `mt2500` by their first such report received, how many with such a report on security firmware. |
| `kvm_release` | KVM devices in the pool whose firmware matches `V1.10.3 release8` / `V1.10.3 release3`: with traces, all, with kind `marker`. |
| `series` | Open routers in the pool by firmware `major.minor` (from `shape()`'s `fw`, at most 2 and 3 digits), 4.6 and older as one group named `4.6 and older`, then in version order; a firmware without such a version is left out, and so is a group of fewer than 5 routers. `hit`: with traces, `of`: all. |
| `sweep` | Open routers in the pool with traces and a `state_file_time`, by `model` as the reported table reads it (`GL-MT3000`, `GL.iNet GL-MT3000 (NAND)` and `mt3000` are `mt3000`; anything but 2 to 16 of `a-z`, `0-9`, `-` names no model and is left out here, not in `hours`), named `GL-` and the model in capitals. For each model with at least 5 such routers and at least one time from 2026-11-20 22:00 to before 2026-11-21 08:00: the minute in that window that most of them share (the earliest of equals), `n` the routers within one minute of it (all their times, not only the window), `of` all of them. Sorted by `at`, then `model`. |
| `hours` | The same routers by the hour of `state_file_time`, only from 2026-11-19 00:00 to before 2026-11-22 00:00, sorted; `hours_routers` is how many fell into that window. |

What the answer never holds: a device ID, an account name, a file name or hash, a time of
a single device, anything about one device. A model shows up in `sweep` and a firmware group
in `series` only with at least 5 routers; `pipe.last` is only a day. Only what the page
shows goes in.

## When it is worked out

Like the reported table: at most every 15 minutes, behind a request, reading only the
reports received since the last run (two minutes of overlap). Once a day, at the first run
from 04:00 UTC, and whenever the rules change, all reports are read again. When something
fails, the last figures stay; `figures` is `null` while there are none. `script` and
`reported` do not depend on it.

## How the page uses it

The page keeps the figures it last showed as its own fallback, and checks an answer before
it uses it: routers and KVM devices add up to `devices`, and `open` and `updated` add up to
`routers` and `kvm`; no `a` is larger than its `b`; `hours` add up to `hours_routers`;
`as_of` is not in the future and not older than the fallback, `pipe.last` and
`newest_command` are not later than `as_of`; the number of devices is not below 90 % of the
fallback's and does not grow faster than a limit per day; `newest_command` is the one the
page expects; and the figures give every value the page's text names. If any check fails,
the page shows its fallback, all of it. At build, figures that pass but are more than two
days old are used, and the workflow run fails afterwards, so that a report service that
stopped working them out is noticed.
