#!/usr/bin/env python3
# analyzer/log_analyzer.py
"""
Robust log analyzer for FlexiWAF
- Scans ./logs for access.log, honeypot_access.log, denied.log, error.log (configurable via env)
- Produces ./data/stats.json with fields expected by the dashboard
- Designed to detect WAF rejections (403, 429) and honeypot hits reliably
"""

import os
import re
import json
import time
from datetime import datetime, timezone
from collections import Counter, defaultdict

# Configuration via environment variables (with sensible defaults)
LOG_DIR = os.getenv("LOG_DIR", "/app/logs")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
STATS_FILENAME = os.getenv("STATS_FILE", "stats.json")
STATS_PATH = os.path.join(DATA_DIR, STATS_FILENAME)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "10"))  # seconds
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "10"))

# Log filenames to check (in order of priority)
CANDIDATE_FILES = [
    "access.log",
    "denied.log",
    "honeypot_access.log",
    "error.log",
]

# Regular expressions for parsing
COMMON_ACCESS_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\[(?P<time>[^\]]+)\]\s+"(?P<req>[^"]+)"\s+(?P<status>\d{3})',
    re.IGNORECASE,
)

# nginx error log line including client and request
ERROR_NGINX_RE = re.compile(
    r'(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}).*?client:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?request:\s*"(?P<req>[^"]+)"',
    re.IGNORECASE,
)

# Generic WAF logging patterns (from waf.lua style messages)
# examples matched:
#  "WAF: Rate limit exceeded for 1.2.3.4. Redirecting to challenge page. Request: /some/path"
#  "WAF: Denied access for IP 1.2.3.4 is in the blocked list."
WAF_SIMPLE_RE = re.compile(
    r'WAF:\s*(?P<reason>Denied access for IP|Rate limit exceeded for).*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE,
)

WAF_REQ_RE = re.compile(r'Request:\s*(?P<req>.+)$', re.IGNORECASE)

# Fallback ip finder
IP_FINDER_RE = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})')

# time parse candidates
def parse_time(ts_str):
    if not ts_str or not isinstance(ts_str, str):
        return None
    ts_str = ts_str.strip()
    # Try nginx access time: 16/Sep/2025:22:55:38 +0000
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        pass
    # Try nginx error time: 2025/09/16 22:55:38
    try:
        return datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    # Try ISO
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        pass
    return None

def safe_iso(dt):
    if not dt:
        return datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

def analyze_once():
    """
    Scan logs and generate aggregated stats (single pass, recompute each time).
    This approach avoids tricky offset bookkeeping and is simpler for periodic runs.
    """
    total_requests = 0
    total_rejections = 0
    honeypot_attempts = 0
    unique_ips = set()
    rejection_types = Counter()
    top_ips = Counter()
    hourly = defaultdict(int)
    last_events = []

    # Build absolute paths for candidate files present
    files = []
    for fname in CANDIDATE_FILES:
        path = os.path.join(LOG_DIR, fname)
        if os.path.exists(path):
            files.append((fname, path))

    # If no log files found, return empty stats but still valid structure
    if not files:
        print(f"[analyzer] No log files found in {LOG_DIR}. Checked: {', '.join(CANDIDATE_FILES)}")
    else:
        print(f"[analyzer] Found log files: {', '.join(p for _, p in files)}")

    for fname, path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue

                    ip = None
                    dt = None
                    req = None
                    status = None
                    event_type = "Request"

                    # 1) Try common access log
                    m = COMMON_ACCESS_RE.search(line)
                    if m:
                        ip = m.group("ip")
                        time_str = m.group("time")
                        dt = parse_time(time_str)
                        req = m.group("req")
                        try:
                            status = int(m.group("status"))
                        except Exception:
                            status = None
                        # count this as a request
                        total_requests += 1
                        unique_ips.add(ip)
                        if dt:
                            hourly[str(dt.hour)] += 1

                        # classify honeypot if file is honeypot or path looks like admin paths
                        if "honeypot" in fname.lower() or any(p in req.lower() for p in ["/admin", "/wp-admin", "/phpmyadmin", "/xmlrpc.php"]):
                            honeypot_attempts += 1
                            event_type = "Honeypot"
                            # many honeypot hits are 404 - but status already set
                            if status and status >= 400:
                                rejection_types[str(status)] += 1
                                total_rejections += 1
                                top_ips[ip] += 1
                        else:
                            # general request: if status >=400 count as rejection
                            if status and status >= 400:
                                total_rejections += 1
                                rejection_types[str(status)] += 1
                                top_ips[ip] += 1

                    else:
                        # 2) Try WAF simple pattern (custom messages in error.log)
                        mw = WAF_SIMPLE_RE.search(line)
                        if mw:
                            ip = mw.group("ip")
                            reason = mw.group("reason") or ""
                            # try to extract Request: ... if present
                            reqm = WAF_REQ_RE.search(line)
                            req = reqm.group("req").strip() if reqm else line
                            # decide status from reason
                            if "Rate limit" in reason:
                                status = 429
                            else:
                                # Denied access -> 403
                                status = 403
                            event_type = "WAF Rejection"
                            total_rejections += 1
                            rejection_types[str(status)] += 1
                            top_ips[ip] += 1
                            unique_ips.add(ip)
                            # attempt to extract timestamp if present (error logs often start with yyyy/mm/dd HH:MM:SS)
                            ts_match = re.search(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                            if ts_match:
                                dt = parse_time(ts_match.group(1))
                            # WAF events may not have an hour bucket; if dt present, count it
                            if dt:
                                hourly[str(dt.hour)] += 1
                            # do not increment total_requests here (we already count web requests from access.log). But it's safe to increment:
                            total_requests += 1
                        else:
                            # 3) Try nginx error log detailed pattern
                            me = ERROR_NGINX_RE.search(line)
                            if me:
                                ip = me.group("ip")
                                req = me.group("req")
                                time_str = me.group("time")
                                dt = parse_time(time_str)
                                # Some error logs do not include numeric status; infer as rejection
                                status = None
                                event_type = "ErrorLog"
                                total_rejections += 1
                                rejection_types["error"] += 1
                                top_ips[ip] += 1
                                unique_ips.add(ip)
                                if dt:
                                    hourly[str(dt.hour)] += 1
                                total_requests += 1
                            else:
                                # 4) Fallback: try to find an IP and maybe a timestamp
                                ipf = IP_FINDER_RE.search(line)
                                if ipf:
                                    ip = ipf.group("ip")
                                    unique_ips.add(ip)
                                # Attempt to find status if present anywhere
                                st_match = re.search(r'\s(\d{3})(?:\s|$)', line)
                                if st_match:
                                    try:
                                        status = int(st_match.group(1))
                                        if status >= 400:
                                            total_rejections += 1
                                            rejection_types[str(status)] += 1
                                            top_ips[ip] += 1
                                        total_requests += 1
                                    except Exception:
                                        pass
                                # Attempt to extract any timestamp for ordering
                                ts_alt = re.search(r'(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4})', line)
                                if ts_alt:
                                    dt = parse_time(ts_alt.group(1))
                                    if dt:
                                        hourly[str(dt.hour)] += 1

                    # Prepare event entry only if we have an IP or request info
                    if ip or req:
                        ev_ts = dt.strftime("%d/%b/%Y:%H:%M:%S %z") if dt else datetime.utcnow().astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
                        event = {
                            "timestamp": ev_ts,
                            "ip": ip if ip else "0.0.0.0",
                            "request": req if req else "-",
                            "status": int(status) if status else 0,
                            "type": event_type
                        }
                        last_events.append(event)

        except Exception as e:
            print(f"[analyzer] ERROR reading {path}: {e}")

    # post-process results
    last_events_sorted = []
    try:
        # try to sort by parseable timestamp (most recent first)
        def _parse_ev_ts(ev):
            try:
                return datetime.strptime(ev["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
            except Exception:
                try:
                    return datetime.fromisoformat(ev["timestamp"])
                except Exception:
                    return datetime.min.replace(tzinfo=timezone.utc)
        last_events_sorted = sorted(last_events, key=_parse_ev_ts, reverse=True)
    except Exception:
        last_events_sorted = list(reversed(last_events))

    top_5 = dict(top_ips.most_common(5))

    # ensure hourly has all keys as strings
    hourly_dict = {str(h): int(hourly.get(str(h), 0)) for h in range(24)}

    stats = {
        "total_requests": int(total_requests),
        "total_rejections": int(total_rejections),
        "honeypot_attempts": int(honeypot_attempts),
        "unique_ips": int(len(unique_ips)),
        "rejection_types": dict(rejection_types),
        "top_5_ips": top_5,
        "hourly_distribution": hourly_dict,
        "last_10_events": last_events_sorted[:MAX_EVENTS],
        "last_updated": safe_iso(datetime.utcnow().replace(tzinfo=timezone.utc))
    }

    return stats

def atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    os.replace(tmp, path)
    print(f"[analyzer] Wrote stats to {path}")

def main_loop():
    ensure_dirs()
    print(f"[analyzer] Starting analyzer. logs={LOG_DIR}, data={DATA_DIR}, poll_interval={POLL_INTERVAL}s")
    while True:
        try:
            stats = analyze_once()
            atomic_write(STATS_PATH, stats)
        except Exception as e:
            print(f"[analyzer] Unexpected error during analysis: {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main_loop()
