#!/usr/bin/env python3
import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

LOGIN_PATTERN = re.compile(
    r"(Accepted|Failed) password for (?:invalid user )?(\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
# time/date
TS_PATTERN = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})")

KEYWORDS = ["sudo", "root", "invalid user", "error"]

WATCHLIST = {"198.51.100.23", "203.0.113.45"}

NIGHT_START, NIGHT_END = 0, 6  # off hours

BF_THRESHOLD = 5   # failures
BF_WINDOW = 60     # window within failures

ASSUMED_YEAR = 2026 # prevent deprecation notice


def read_log(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def parse_events(lines):
    events = []
    for line in lines:
        match = LOGIN_PATTERN.search(line)
        if not match:
            continue
        status, user, ip = match.groups()
        ts_match = TS_PATTERN.search(line)
        dt = (datetime.strptime(f"{ASSUMED_YEAR} {ts_match.group(1)}", "%Y %b %d %H:%M:%S")
              if ts_match else None)
        hour = dt.hour if dt else None
        events.append({"raw": line.strip(), "status": status, "user": user,
                       "ip": ip, "dt": dt, "hour": hour})
    return events


def detect_keywords(lines):
    alerts = []
    for line in lines:
        for kw in KEYWORDS:
            if kw in line:
                alerts.append({"rule": "keyword", "keyword": kw, "raw": line.strip()})
    return alerts


def detect_suspicious_ips(events):
    alerts = []
    for e in events:
        if e["ip"] in WATCHLIST:
            alerts.append({"rule": "suspicious_ip", "ip": e["ip"], "raw": e["raw"]})
    return alerts


def detect_off_hours(events, include_attempts=False):
    alerts = []
    for e in events:
        if e["hour"] is None:
            continue
        if not (NIGHT_START <= e["hour"] < NIGHT_END):
            continue
        if not include_attempts and e["status"] != "Accepted":
            continue
        alerts.append({"rule": "off_hours", "ip": e["ip"], "user": e["user"], "raw": e["raw"]})
    return alerts


def detect_brute_force(events):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "Failed" and e["dt"] is not None:
            by_ip[e["ip"]].append(e)

    for ip, fails in by_ip.items():
        fails.sort(key=lambda e: e["dt"])
        for i in range(len(fails) - BF_THRESHOLD + 1):
            window = fails[i:i + BF_THRESHOLD]
            span = (window[-1]["dt"] - window[0]["dt"]).total_seconds()
            if span <= BF_WINDOW:
                alerts.append({
                    "rule": "brute_force",
                    "ip": ip,
                    "raw": f"{ip} - {len(fails)} failed logins "
                           f"({BF_THRESHOLD} within {int(span)}s)",
                })
                break
    return alerts


RULE_ORDER = ["brute_force", "suspicious_ip", "off_hours", "keyword"]


def build_report(alerts):
    by_rule = defaultdict(list)
    for a in alerts:
        by_rule[a["rule"]].append(a)

    total = len(alerts)
    lines = []
    lines.append("=" * 70)
    lines.append(f"MINI SIEM REPORT - {total} alert(s)")
    lines.append("=" * 70)
    for rule in RULE_ORDER:
        lines.append(f"  {rule:<15} {len(by_rule[rule])}")
    lines.append("-" * 70)

    for rule in RULE_ORDER:
        rule_alerts = by_rule[rule]
        if not rule_alerts:
            continue
        lines.append("")
        lines.append(f"[{rule}]")
        for a in rule_alerts:
            lines.append(f"  {a['raw']}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM - parse an auth.log and run detection rules.")
    parser.add_argument("logfile", help="path to the auth.log file")
    parser.add_argument("--night-all", action="store_true",
                         help="flag every off-hours attempt, not just successful logins")
    args = parser.parse_args()

    lines = read_log(args.logfile)
    events = parse_events(lines)
    print(f"Parsed {len(events)} login events from {len(lines)} log lines.\n")

    alerts = []
    alerts += detect_brute_force(events)
    alerts += detect_suspicious_ips(events)
    alerts += detect_off_hours(events, include_attempts=args.night_all)
    alerts += detect_keywords(lines)

    print(build_report(alerts))


if __name__ == "__main__":
    sys.exit(main())
