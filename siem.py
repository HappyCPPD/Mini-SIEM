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
        if NIGHT_START <= e["hour"] < NIGHT_END:
            if not include_attempts and e["status"] != "Accepted":
                continue
            alerts.append({"rule": "off_hours", "hour": e["hour"], "raw": e["raw"]})
    return alerts


def detect_brute_force(events):
    fails_by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "Failed" and e["dt"] is not None:
            fails_by_ip[e["ip"]].append(e["dt"])

    alerts = []
    for ip, times in fails_by_ip.items():
        times.sort()
        for i in range(len(times) - BF_THRESHOLD + 1):
            span = (times[i + BF_THRESHOLD - 1] - times[i]).total_seconds()
            if span <= BF_WINDOW:
                alerts.append({"rule": "brute_force", "ip": ip,
                               "count": len(times), "span": span})
                break  # one alert per ip
    return alerts


def format_alert(a):
    rule = a["rule"]
    if rule == "brute_force":
        return f"{a['ip']} - {a['count']} failed logins ({BF_THRESHOLD} within {a['span']:.0f}s)"
    if rule == "suspicious_ip":
        return f"{a['ip']} - {a['raw']}"
    if rule == "off_hours":
        return f"{a['hour']:02d}h - {a['raw']}"
    if rule == "keyword":
        return f"{a['keyword']} - {a['raw']}"
    return a["raw"]


def print_report(alerts):
    print("=" * 70)
    print(f"MINI SIEM REPORT - {len(alerts)} alert(s)")
    print("=" * 70)

    counts = Counter(a["rule"] for a in alerts)
    order = ["brute_force", "suspicious_ip", "off_hours", "keyword"]
    for rule in order:
        if counts[rule]:
            print(f"  {rule:<14} {counts[rule]}")
    print("-" * 70)

    for rule in order:
        rule_alerts = [a for a in alerts if a["rule"] == rule]
        if not rule_alerts:
            continue
        print(f"\n[{rule}]")
        for a in rule_alerts:
            print(f"  {format_alert(a)}")


def main():
    parser = argparse.ArgumentParser(
        description="Mini SIEM: parse a Linux auth.log and run detections."
    )
    parser.add_argument("logfile", help="Path to the auth.log file")
    parser.add_argument("--night-all", action="store_true",
                        help="Include failed attempts in off-hours alerts, not just successful logins")
    args = parser.parse_args()

    try:
        lines = read_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    events = parse_events(lines)
    print(f"Parsed {len(events)} login events from {len(lines)} log lines.\n")

    alerts = []
    alerts += detect_keywords(lines)
    alerts += detect_suspicious_ips(events)
    alerts += detect_off_hours(events, include_attempts=args.night_all)
    alerts += detect_brute_force(events)

    print_report(alerts)


if __name__ == "__main__":
    main()