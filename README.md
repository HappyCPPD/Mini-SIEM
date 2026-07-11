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

## Example output

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

## The rules

- **keyword** — looks for `sudo`, `root`, `invalid user`, and `error` in the raw lines. Runs over the raw text rather than the parsed events on purpose, so it still catches things like `sudo` and `CRON` entries that are not SSH logins.
- **suspicious_ip** — flags any event whose IP is on a small watchlist. A stand-in for a threat intel feed.
- **off_hours** — flags logins between midnight and 6am. A login at 2am is more interesting than one at 2pm.
- **brute_force** — fires when one IP racks up five or more failures inside a short window. It cares about the burst, not the total.

Thresholds and the watchlist live at the top of `siem.py` if you want to change them.

## Limits

It only understands SSH login lines and the keywords I hard-coded, so plenty of real auth events slide past it. The watchlist is a fixed set in the file rather than anything live. It reads a file once and exits, so it is not watching anything in real time, and the thresholds are numbers I picked by hand rather than tuned against real traffic.

The point was not to replace a real SIEM. It was to build the smallest thing that still thinks the way one does: parse once, detect many times, and rank the results so the loudest thing is at the top.

## Files

- `siem.py` — the tool.
- `sample_auth.log` — a small sample log to run it against.
