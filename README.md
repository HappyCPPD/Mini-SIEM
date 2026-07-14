# Mini SIEM

A small Python tool that reads a Linux `auth.log`, parses it into structured login events, and runs four detection rules over them. It prints a report that counts alerts per rule so the loudest thing sits at the top.

I built it as the next step up from my [failed-login counter](https://github.com/HappyCPPD/AuthLogReader). That script only ever answered one question. This one parses the log once and then asks several at the same time, which is closer to how a real detection pipeline works. Standard library only, no dependencies.

## What it does

- Parses every SSH login line (`Accepted` / `Failed password`) into an event with the status, user, IP, and timestamp.
- Runs four detection rules over the parsed events and the raw lines.
- Prints a summary that counts alerts per rule, then the detail for each rule underneath.

## Usage

```bash
python3 siem.py sample_auth.log
```

By default the off-hours rule only flags successful logins at night. To widen it to every attempt in the night window:

```bash
python3 siem.py sample_auth.log --night-all
```

There is also a larger real log to try it against, 2000 lines pulled from a public dataset of a box that sat on the internet getting scanned:

```bash
python3 siem.py openssh_2k_real.log
```

## Example output

On the small sample log:

```text
Parsed 30 login events from 36 log lines.

======================================================================
MINI SIEM REPORT - 35 alert(s)
======================================================================
  brute_force     1
  suspicious_ip   12
  off_hours       1
  keyword         21
----------------------------------------------------------------------

[brute_force]
  203.0.113.45 - 9 failed logins (5 within 12s)
```

On the real 2000-line log the picture changes completely. Brute force lights up with real botnets, the watchlist matches nothing because its IPs were made up for testing, off-hours is empty because the log only spans a single morning, and keyword drowns everything at 1042 hits:

```text
Parsed 520 login events from 2000 log lines.

======================================================================
MINI SIEM REPORT - 1051 alert(s)
======================================================================
  brute_force     9
  suspicious_ip   0
  off_hours       0
  keyword         1042
----------------------------------------------------------------------

[brute_force]
  183.62.140.253 - 286 failed logins (5 within 8s)
  187.141.143.180 - 80 failed logins (5 within 22s)
  103.99.0.122 - 46 failed logins (5 within 13s)
  112.95.230.3 - 26 failed logins (5 within 11s)
  ...
```

## The rules

- **keyword** — looks for `sudo`, `root`, `invalid user`, and `error` in the raw lines. Runs over the raw text rather than the parsed events on purpose, so it still catches things like `sudo` and `CRON` entries that are not SSH logins.
- **suspicious_ip** — flags any event whose IP is on a small watchlist. A stand-in for a threat intel feed.
- **off_hours** — flags logins between midnight and 6am. A login at 2am is more interesting than one at 2pm.
- **brute_force** — fires when one IP racks up five or more failures inside a short window. It cares about the burst, not the total.

Thresholds and the watchlist live at the top of `siem.py` if you want to change them.

## Limits

It only understands SSH login lines and the keywords I hard-coded, so plenty of real auth events slide past it. The watchlist is a fixed set in the file rather than anything live, and running it on the real log made that obvious: it matched zero of the 27 attacking IPs. It reads a file once and exits, so it is not watching anything in real time. The biggest thing the real log exposed is the keyword rule: it prints one line per hit, which is fine on a small log and useless on a big one, where it buried the nine brute-force alerts that mattered under 1042 correct-but-noisy matches. It needs to count and group its hits rather than list them.

The point was not to replace a real SIEM. It was to build the smallest thing that still thinks the way one does: parse once, detect many times, and rank the results so the loudest thing is at the top.

## Files

- `siem.py` — the tool.
- `sample_auth.log` — a small sample log to run it against.
- `openssh_2k_real.log` — a real 2000-line SSH log from a public dataset.
- `openssh_2k_report.txt` — the full report from running the tool on that log.
