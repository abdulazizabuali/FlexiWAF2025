#!/usr/bin/env python3
# analyzer/log_analyzer.py
"""
Enhanced log analyzer for FlexiWAF
- Scans ./logs for new log types with improved pattern matching
- Produces ./data/stats.json with enhanced attack-focused metrics
- Designed to detect real attacks with high accuracy and distinguish between ban types
"""

import os
import re
import json
import time
from datetime import datetime, timezone
from collections import Counter, defaultdict

# Configuration via environment variables (with sensible defaults)
LOG_DIR = os.getenv("LOG_DIR", "./logs")
DATA_DIR = os.getenv("DATA_DIR", "./data")
STATS_FILENAME = os.getenv("STATS_FILE", "stats.json")
STATS_PATH = os.path.join(DATA_DIR, STATS_FILENAME)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "10"))  # seconds
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "500"))

# ✅ التعديل: توحيد ملفات سجل WAF في ملف واحد
CANDIDATE_FILES = [
    "waf_events.log",                       # Unified WAF events (Rate Limit, Bans, CAPTCHA, Grace Period)
    "honeypot_access.log",                  # Honeypot hits (REAL ATTACKS)
    "access.log",                           # Regular access logs
    "error.log",                            # System errors
]

# --------------------------------------------------------------------------------
# ✅ التعديل: التعبير المنتظم الموحد لجميع سجلات WAF (waf_events.log)
# يطابق التنسيق waf_log في nginx.conf
WAF_LOG_RE = re.compile(
    # IP, Remote User, Timestamp
    r'(?P<ip>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>.+?)\] '
    # Request, Status, Body Bytes Sent (نستخدم \S+ لتجنب التفاصيل غير الضرورية في التحليل الأولي)
    r'"(?P<request>.*?)" \S+ \S+ '
    # Referer, User-Agent
    r'"(?P<referer>.*?)" "(?P<user_agent>.*?)" '
    # WAF Event Type
    r'waf_type=(?P<waf_type>\S+) '
    # URI
    r'uri=(?P<uri>\S+) '
    # CAPTCHA attempts (أو '-')
    r'failed_attempts=(?P<failed_attempts>\S+) '
    # Ban Duration (أو '-')
    r'ban_duration=(?P<ban_duration>\S+) '
    # Ban Reason (أو 'NONE')
    r'ban_reason=(?P<ban_reason>.*)'
)
# --------------------------------------------------------------------------------

# Enhanced regular expressions for other log formats (Honeypot, Access)
HONEYPOT_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - \[(?P<time>[^\]]+)\] "HONEYPOT" Path: "(?P<path>[^"]+)" "(?P<ua>[^"]+)"',
    re.IGNORECASE
)

# Fallback patterns
COMMON_ACCESS_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\[(?P<time>[^\]]+)\]\s+"(?P<req>[^"]+)"\s+(?P<status>\d{3})',
    re.IGNORECASE,
)

# ... (parse_time, safe_iso, ensure_dirs - لم تتغير)
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
# ... (parse_time, safe_iso, ensure_dirs - لم تتغير)


def process_honeypot_log(line):
    """Process honeypot access logs (REAL ATTACKS)"""
    m = HONEYPOT_RE.search(line)
    if m:
        path = m.group("path")
        threat_level = 'CRITICAL' if any(p in path.lower() for p in ['/admin', '/wp-admin', '/phpmyadmin']) else 'HIGH'
        
        return {
            'ip': m.group("ip"),
            'timestamp': m.group("time"),
            'path': path,
            'request': path, # لغرض التوحيد مع سجلات WAF
            'user_agent': m.group("ua"),
            'type': 'honeypot',
            'is_attack': True,
            'threat_level': threat_level,
            'details': f"Honeypot access attempt on path: {path}"
        }
    return None

def process_waf_log_line(line):
    """
    ✅ دالة موحدة لمعالجة جميع أحداث WAF من ملف waf_events.log
    """
    m = WAF_LOG_RE.search(line)
    if not m:
        return None

    data = m.groupdict()
    waf_type = data['waf_type']
    
    event_data = {
        'ip': data['ip'],
        'timestamp': data['timestamp'],
        'request': data['request'],
        'user_agent': data['user_agent'],
        'type': 'WAF_EVENT',
        'waf_type': waf_type,
        'is_attack': False,
        'threat_level': 'INFO',
        'details': 'N/A',
        'attempt': 0,
    }

    try:
        attempts = int(data['failed_attempts']) if data['failed_attempts'].isdigit() else 0
        event_data['attempt'] = attempts
    except ValueError:
        pass
        
    duration = data['ban_duration']
    reason = data['ban_reason']

    if waf_type == "RATE_LIMIT":
        event_data['type'] = 'rate_limit'
        event_data['threat_level'] = 'LOW'
        event_data['details'] = "Rate limit triggered. May indicate scanning or high traffic."
    
    elif waf_type == "TEMP_BAN":
        event_data['type'] = 'temporary_ban'
        event_data['is_attack'] = True
        event_data['threat_level'] = 'HIGH'
        event_data['details'] = f"IP temporarily banned for {duration}s. Reason: {reason}"
    
    elif waf_type == "BLOCKED_IP":
        event_data['type'] = 'permanent_ban'
        event_data['is_attack'] = True
        event_data['threat_level'] = 'CRITICAL'
        event_data['details'] = "IP permanently blocked - Found in IP blocklist."
        
    elif waf_type == "CAPTCHA_FAIL":
        event_data['type'] = 'captcha_fail'
        # تحديد مستوى التهديد بناءً على عدد المحاولات الفاشلة
        if attempts >= 5:
            event_data['threat_level'] = 'HIGH'
            event_data['details'] = f"CAPTCHA failed (Final attempt {attempts}/5) - Temporary ban applied"
            event_data['is_attack'] = True
        elif attempts >= 3:
            event_data['threat_level'] = 'MEDIUM'
            event_data['details'] = f"CAPTCHA failed (Attempt {attempts}/5) - Multiple failures detected"
        else:
            event_data['threat_level'] = 'LOW'
            event_data['details'] = f"CAPTCHA failed (Attempt {attempts}/5) - Single failure"
    
    elif waf_type == "CAPTCHA_SUCCESS":
        event_data['type'] = 'captcha_success'
        event_data['threat_level'] = 'INFO'
        event_data['details'] = f"CAPTCHA passed successfully after {attempts} attempts - Grace period activated"

    elif waf_type == "GRACE_PERIOD":
        event_data['type'] = 'grace_period'
        event_data['threat_level'] = 'INFO'
        event_data['details'] = "Request allowed during grace period (after successful CAPTCHA)"
        
    return event_data

# ✅ إزالة دوال process_rate_limit_log, process_temporary_ban_log, إلخ.

def analyze_once():
    """
    Scan logs and generate enhanced attack-focused stats with accurate counters.
    """
    # Counters for different metrics
    total_requests = 0
    rate_limit_triggers = 0
    temporary_bans = 0
    permanent_bans = 0
    honeypot_attempts = 0
    captcha_failures_total = 0
    captcha_success_total = 0
    grace_period_access = 0
    captcha_attempts_distribution = defaultdict(int)
    
    unique_attackers = set()
    unique_ips = set()
    
    # Detailed counters
    rejection_breakdown = Counter()
    top_attackers = Counter()
    hourly_attacks = defaultdict(int)
    last_attacks = []
    
    # Build absolute paths for candidate files present
    files = []
    for fname in CANDIDATE_FILES:
        path = os.path.join(LOG_DIR, fname)
        if os.path.exists(path):
            files.append((fname, path))

    for fname, path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue

                    event = None
                    is_attack = False
                    
                    # ✅ منطق المعالجة الموحد
                    if "waf_events.log" in fname:
                        event = process_waf_log_line(line)
                    elif "honeypot_access.log" in fname:
                        event = process_honeypot_log(line)
                    elif "access.log" in fname:
                        # Fallback processing for access.log
                        m = COMMON_ACCESS_RE.search(line)
                        if m:
                            event = {
                                'ip': m.group("ip"),
                                'timestamp': m.group("time"),
                                'request': m.group("req"),
                                'status': m.group("status"),
                                'type': 'access',
                                'threat_level': 'INFO'
                            }
                    # تجاهل error.log للتجميع الإحصائي البسيط

                    if not event:
                        continue
                        
                    # تحديث إحصائيات الطلبات الأساسية
                    total_requests += 1
                    unique_ips.add(event['ip'])
                    dt = parse_time(event.get('timestamp'))

                    # تحديث الإحصائيات بناءً على نوع الحدث
                    event_type = event['type']
                    is_attack = event.get('is_attack', False)

                    if event_type == 'rate_limit':
                        rate_limit_triggers += 1
                    
                    elif event_type == 'temporary_ban':
                        temporary_bans += 1
                        rejection_breakdown['temporary_ban'] += 1
                        top_attackers[event['ip']] += 1
                        unique_attackers.add(event['ip'])
                        is_attack = True
                    
                    elif event_type == 'permanent_ban':
                        permanent_bans += 1
                        rejection_breakdown['permanent_ban'] += 1
                        top_attackers[event['ip']] += 1
                        unique_attackers.add(event['ip'])
                        is_attack = True
                        
                    elif event_type == 'honeypot':
                        honeypot_attempts += 1
                        rejection_breakdown['honeypot'] += 1
                        top_attackers[event['ip']] += 1
                        unique_attackers.add(event['ip'])
                        is_attack = True
                        
                    elif event_type == 'captcha_fail':
                        captcha_failures_total += 1
                        rejection_breakdown['captcha_fail'] += 1
                        attempt = event.get('attempt', 1)
                        captcha_attempts_distribution[str(attempt)] += 1
                        if is_attack: # تعتبر هجوم فقط عند الفشل النهائي (Attempts >= 5)
                            unique_attackers.add(event['ip'])

                    elif event_type == 'captcha_success':
                        captcha_success_total += 1
                    
                    elif event_type == 'grace_period':
                        grace_period_access += 1

                    # تحديث الهجمات الساعية وقائمة الأحداث الأخيرة
                    if dt and (is_attack or event_type in ['captcha_fail', 'captcha_success', 'grace_period']):
                        hourly_attacks[str(dt.hour)] += 1

                    if (is_attack or event_type in ['captcha_fail', 'captcha_success', 'grace_period']) and event:
                        attack_event = {
                            "timestamp": event.get('timestamp', safe_iso(dt)),
                            "ip": event['ip'],
                            "type": event_type,
                            "threat_level": event.get('threat_level', 'INFO'),
                            "details": event.get('details', 'N/A'),
                            "request": event.get('request', 'N/A')
                        }
                        last_attacks.append(attack_event)

        except Exception as e:
            print(f"[analyzer] ERROR reading {path}: {e}")

    # حساب الإحصائيات المحسنة
    total_attacks = temporary_bans + permanent_bans + honeypot_attempts
    
    # حساب معدلات الكابتشا
    total_captcha_attempts = captcha_success_total + captcha_failures_total
    captcha_success_rate = (captcha_success_total / total_captcha_attempts * 100) if total_captcha_attempts > 0 else 0
    
    # حساب متوسط محاولات الكابتشا
    total_attempts = sum(int(k)*v for k, v in captcha_attempts_distribution.items())
    total_failures = sum(captcha_attempts_distribution.values())
    avg_captcha_attempts = total_attempts / total_failures if total_failures > 0 else 0
    
    # حساب معدل الحظر المؤقت
    captcha_timeout_rate = (temporary_bans / captcha_failures_total * 100) if captcha_failures_total > 0 else 0

    # Sort last attacks by timestamp (most recent first)
    try:
        last_attacks_sorted = sorted(
            last_attacks, 
            key=lambda x: parse_time(x["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True
        )
    except Exception:
        last_attacks_sorted = last_attacks[::-1]

    # Get top 5 attackers
    top_5_attackers = dict(top_attackers.most_common(5))
    
    # Ensure hourly data has all 24 hours
    hourly_dict = {str(h): int(hourly_attacks.get(str(h), 0)) for h in range(24)}

    stats = {
        "total_requests": int(total_requests),
        "total_attacks": int(total_attacks),
        "temporary_bans": int(temporary_bans),
        "permanent_bans": int(permanent_bans),
        "honeypot_hits": int(honeypot_attempts),
        "rate_limit_triggers": int(rate_limit_triggers),
        "captcha_failures": int(captcha_failures_total),
        "captcha_success": int(captcha_success_total),
        "grace_period_access": int(grace_period_access),
        "captcha_success_rate": round(captcha_success_rate, 1),
        "avg_captcha_attempts": round(avg_captcha_attempts, 1),
        "captcha_timeout_rate": round(captcha_timeout_rate, 1),
        "captcha_attempts_distribution": dict(captcha_attempts_distribution),
        "unique_attackers": int(len(unique_attackers)),
        "unique_ips": int(len(unique_ips)),
        "rejection_breakdown": dict(rejection_breakdown),
        "top_attackers": top_5_attackers,
        "hourly_attacks": hourly_dict,
        "last_10_attacks": last_attacks_sorted[:MAX_EVENTS],
        "last_updated": safe_iso(datetime.utcnow().replace(tzinfo=timezone.utc))
    }

    return stats

def atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    os.replace(tmp, path)
    print(f"[analyzer] Wrote enhanced stats to {path}")

def debug_log_analysis():
    """
    وظيفة مساعدة لتصحيح وتحليل اللوجز
    """
    print(f"[debug] Analyzing log files in: {LOG_DIR}")
    
    for fname in CANDIDATE_FILES:
        path = os.path.join(LOG_DIR, fname)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                print(f"[debug] {fname}: {len(lines)} lines")
                
                # عرض عينة من السطور للتحقق من التنسيق
                for i, line in enumerate(lines[-3:]):  # آخر 3 سطور
                    print(f"[debug] {fname} sample {i+1}: {line.strip()}")
        else:
            print(f"[debug] {fname}: File not found")

def main_loop():
    ensure_dirs()
    print(f"[analyzer] Starting enhanced analyzer. logs={LOG_DIR}, data={DATA_DIR}, poll_interval={POLL_INTERVAL}s")
    print(f"[analyzer] Monitoring log types: {', '.join(CANDIDATE_FILES)}")
    
    # تشغيل التحليل التصحيحي الأولي
    debug_log_analysis()
    
    while True:
        try:
            stats = analyze_once()
            atomic_write(STATS_PATH, stats)
            
            # طباعة إحصائيات التصحيح
            print(f"[analyzer] Stats updated - Temp Bans: {stats.get('temporary_bans', 0)}, Perm Bans: {stats.get('permanent_bans', 0)}, CAPTCHA Fail: {stats.get('captcha_failures', 0)}")
            
        except Exception as e:
            print(f"[analyzer] Unexpected error during enhanced analysis: {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main_loop()
