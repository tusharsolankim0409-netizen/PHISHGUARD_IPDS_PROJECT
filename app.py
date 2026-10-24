"""
PhishGuard — Intelligent Phishing Detection System
Web Application (Flask)

Author : Tushar Solanki
Serves : http://localhost:8080

Run:
    pip install flask
    python app.py

All PhishGuard logic is self-contained in this file.
The scanned URL is NEVER visited or resolved during analysis.
"""

from __future__ import annotations

import re
import json
import csv
import sqlite3
import hashlib
import datetime
import io
import os
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ── Flask import (graceful error if not installed) ──────────
try:
    from flask import Flask, request, jsonify, Response
    _FLASK_OK = True
except ImportError:
    _FLASK_OK = False

# ── Optional: requests for VirusTotal ───────────────────────
try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _requests = None       # type: ignore
    _REQUESTS_OK = False

# ============================================================
#  CONFIGURATION
# ============================================================
PORT = 8080
HOST = "0.0.0.0"   # bind to all interfaces so Chrome can reach it
DB_PATH = "phishguard_history.db"

# Set your VirusTotal v3 API key here (leave empty to skip)
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")

RISK_THRESHOLDS = {"low": (0, 39), "suspicious": (40, 69), "high": (70, 100)}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "paypal",
    "apple", "microsoft", "google", "amazon", "facebook",
    "ebay", "netflix", "support", "helpdesk", "webscr",
    "wallet", "crypto", "recover", "suspended", "validate",
    "authenticate", "urgent", "alert", "limited", "winner",
]

COMMON_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov",
    ".co.uk", ".co.in", ".io", ".dev",
}

# ============================================================
#  FEATURE EXTRACTION
# ============================================================
@dataclass
class URLFeatures:
    raw_url:             str  = ""
    scheme:              str  = ""
    hostname:            str  = ""
    path:                str  = ""
    query:               str  = ""
    fragment:            str  = ""
    url_length:          int  = 0
    is_https:            bool = False
    is_ip_hostname:      bool = False
    has_at_symbol:       bool = False
    has_double_slash:    bool = False
    subdomain_count:     int  = 0
    suspicious_kw_count: int  = 0
    suspicious_kw_found: List[str] = field(default_factory=list)
    has_hex_encoding:    bool = False
    has_port:            bool = False
    port:                Optional[int] = None
    has_tld_in_path:     bool = False
    unusual_tld:         bool = False
    tld:                 str  = ""
    dash_count_hostname: int  = 0
    dot_count_hostname:  int  = 0
    digit_count_hostname:int  = 0
    query_param_count:   int  = 0
    has_data_uri:        bool = False
    has_javascript_uri:  bool = False
    is_punycode:         bool = False
    path_length:         int  = 0
    valid:               bool = True
    parse_error:         str  = ""


def extract_features(raw_url: str) -> URLFeatures:
    """
    Parse a raw URL and extract all security-relevant features.
    The URL is NEVER visited or resolved during this process.
    """
    f = URLFeatures(raw_url=raw_url.strip())

    if not f.raw_url:
        f.valid = False
        f.parse_error = "Empty URL"
        return f

    url_lower = f.raw_url.lower()

    if url_lower.startswith("javascript:"):
        f.has_javascript_uri = True
        f.valid = False
        f.parse_error = "javascript: URI — cannot be scanned"
        return f

    if url_lower.startswith("data:"):
        f.has_data_uri = True
        f.valid = False
        f.parse_error = "data: URI — cannot be scanned"
        return f

    working = f.raw_url
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', working):
        working = "http://" + working

    try:
        parsed = urlparse(working)
    except Exception as exc:
        f.valid = False
        f.parse_error = str(exc)
        return f

    f.scheme   = parsed.scheme.lower()
    f.hostname = (parsed.hostname or "").lower()
    f.path     = parsed.path
    f.query    = parsed.query
    f.fragment = parsed.fragment

    if not f.hostname:
        f.valid = False
        f.parse_error = "No hostname could be parsed"
        return f

    f.url_length  = len(f.raw_url)
    f.path_length = len(f.path)
    f.is_https    = f.scheme == "https"

    f.is_ip_hostname = bool(
        re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', f.hostname)
    )
    f.has_at_symbol   = "@" in f.raw_url
    f.has_double_slash = "//" in parsed.path

    parts = f.hostname.split(".")
    f.subdomain_count = max(0, len(parts) - 2)

    full_lower = url_lower
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_lower]
    f.suspicious_kw_found = found_kw
    f.suspicious_kw_count = len(found_kw)

    f.has_hex_encoding = bool(re.search(r'%[0-9a-fA-F]{2}', f.raw_url))

    if parsed.port:
        f.has_port = True
        f.port     = parsed.port

    f.has_tld_in_path = bool(
        re.search(r'\.(com|net|org|gov|edu|io)/', f.path.lower())
    )

    if len(parts) >= 2:
        tld_candidate = "." + parts[-1]
        if len(parts) >= 3:
            two_level = "." + parts[-2] + "." + parts[-1]
            f.tld = two_level if two_level in COMMON_TLDS else tld_candidate
        else:
            f.tld = tld_candidate
        f.unusual_tld = f.tld not in COMMON_TLDS

    f.dash_count_hostname   = f.hostname.count("-")
    f.dot_count_hostname    = f.hostname.count(".")
    f.digit_count_hostname  = sum(c.isdigit() for c in f.hostname)

    if f.query:
        f.query_param_count = len(f.query.split("&"))

    f.is_punycode = "xn--" in f.hostname
    return f


# ============================================================
#  RISK CLASSIFICATION
# ============================================================
@dataclass
class ScanResult:
    url:        str
    risk_label: str
    risk_score: int
    reasons:    List[str]
    features:   URLFeatures
    ti_result:  Dict = field(default_factory=dict)
    scanned_at: str  = field(default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))
    scan_id:    str  = ""

    def __post_init__(self):
        if not self.scan_id:
            raw = f"{self.url}{self.scanned_at}"
            self.scan_id = hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        f = self.features
        return {
            "scan_id":    self.scan_id,
            "url":        self.url,
            "risk_label": self.risk_label,
            "risk_score": self.risk_score,
            "reasons":    self.reasons,
            "scanned_at": self.scanned_at,
            "ti_result":  self.ti_result,
            "features": {
                "scheme":              f.scheme,
                "hostname":            f.hostname,
                "is_https":            f.is_https,
                "is_ip_hostname":      f.is_ip_hostname,
                "has_at_symbol":       f.has_at_symbol,
                "has_double_slash":    f.has_double_slash,
                "subdomain_count":     f.subdomain_count,
                "suspicious_kw_count": f.suspicious_kw_count,
                "suspicious_kw_found": f.suspicious_kw_found,
                "has_hex_encoding":    f.has_hex_encoding,
                "has_port":            f.has_port,
                "port":                f.port,
                "has_tld_in_path":     f.has_tld_in_path,
                "unusual_tld":         f.unusual_tld,
                "tld":                 f.tld,
                "dash_count_hostname": f.dash_count_hostname,
                "url_length":          f.url_length,
                "is_punycode":         f.is_punycode,
                "valid":               f.valid,
                "parse_error":         f.parse_error,
            },
        }


def classify_url(features: URLFeatures) -> Tuple[int, str, List[str]]:
    """
    Heuristic scoring — NOT a probability.
    Score is a risk index (0–100).
    """
    score   = 0
    reasons = []

    if not features.valid:
        return 100, "High Risk", [f"Invalid URL: {features.parse_error}"]

    if not features.is_https:
        score += 10
        reasons.append("Uses HTTP (not HTTPS) — connection is not encrypted")

    if features.is_ip_hostname:
        score += 30
        reasons.append("Hostname is a raw IP address — legitimate sites use domain names")

    if features.has_at_symbol:
        score += 20
        reasons.append("URL contains '@' — browsers ignore everything before '@', used for deception")

    if features.url_length > 100:
        score += 10
        reasons.append(f"URL is very long ({features.url_length} chars) — often used to obscure the real destination")
    elif features.url_length > 75:
        score += 5
        reasons.append(f"URL is moderately long ({features.url_length} chars)")

    kw = features.suspicious_kw_count
    if kw >= 3:
        score += 20
        reasons.append(f"Contains {kw} suspicious keywords: {', '.join(features.suspicious_kw_found[:5])}")
    elif kw == 2:
        score += 12
        reasons.append(f"Contains suspicious keywords: {', '.join(features.suspicious_kw_found)}")
    elif kw == 1:
        score += 6
        reasons.append(f"Contains suspicious keyword: '{features.suspicious_kw_found[0]}'")

    if features.subdomain_count >= 3:
        score += 15
        reasons.append(f"Excessive subdomain depth ({features.subdomain_count}) — often mimics legitimate domains")
    elif features.subdomain_count == 2:
        score += 8
        reasons.append(f"Multiple subdomains ({features.subdomain_count}) detected")

    if features.dash_count_hostname >= 3:
        score += 10
        reasons.append(f"Many hyphens in hostname ({features.dash_count_hostname}) — common in phishing domains")
    elif features.dash_count_hostname == 2:
        score += 5
        reasons.append(f"Multiple hyphens in hostname ({features.dash_count_hostname})")

    if features.has_hex_encoding:
        score += 8
        reasons.append("URL uses percent-encoding — may be obfuscating the real content")

    if features.has_double_slash:
        score += 10
        reasons.append("Double slash '//' in path — may indicate an open redirect")

    if features.has_port:
        non_std = features.port not in (80, 443, 8080, 8443)
        if non_std:
            score += 10
            reasons.append(f"Non-standard port {features.port} — legitimate sites rarely use unusual ports")
        else:
            score += 3
            reasons.append(f"Explicit port {features.port} specified in URL")

    if features.has_tld_in_path:
        score += 12
        reasons.append("TLD appears inside the URL path — classic double-domain deception trick")

    if features.unusual_tld:
        score += 8
        reasons.append(f"Unusual TLD '{features.tld}' — legitimate organisations rarely use obscure TLDs")

    if features.is_punycode:
        score += 15
        reasons.append("Punycode (xn--) in hostname — possible IDN homograph attack")

    if features.digit_count_hostname >= 4:
        score += 7
        reasons.append(f"Many digits in hostname ({features.digit_count_hostname}) — unusual for legitimate sites")

    score = min(score, 100)

    if score <= RISK_THRESHOLDS["low"][1]:
        label = "Low Risk"
    elif score <= RISK_THRESHOLDS["suspicious"][1]:
        label = "Suspicious"
    else:
        label = "High Risk"

    if not reasons:
        reasons.append("No specific risk indicators detected by heuristic rules")

    return score, label, reasons


def scan_url(raw_url: str, api_key: str = "") -> ScanResult:
    """Full pipeline. The URL is NEVER automatically visited."""
    features = extract_features(raw_url)
    score, label, reasons = classify_url(features)
    ti_result = {}
    if api_key and _REQUESTS_OK and features.valid:
        ti_result = _query_virustotal(raw_url, api_key)
    return ScanResult(
        url=raw_url, risk_label=label, risk_score=score,
        reasons=reasons, features=features, ti_result=ti_result,
    )


# ============================================================
#  THREAT INTELLIGENCE (VirusTotal — optional)
# ============================================================
def _query_virustotal(url: str, api_key: str, timeout: int = 10) -> dict:
    result = {"status": "unavailable", "malicious": 0, "suspicious": 0,
              "harmless": 0, "undetected": 0, "message": ""}

    if not api_key:
        result["message"] = "No API key provided"
        return result
    if not _REQUESTS_OK:
        result["message"] = "'requests' not installed"
        return result

    headers = {"x-apikey": api_key}
    try:
        r = _requests.post("https://www.virustotal.com/api/v3/urls",
                           headers=headers, data={"url": url}, timeout=timeout)
    except Exception as exc:
        result["message"] = f"Network error: {exc}"
        return result

    if r.status_code == 401:
        result["message"] = "API key invalid (HTTP 401)"
        return result
    if r.status_code == 429:
        result["message"] = "Rate limit reached (HTTP 429)"
        return result
    if r.status_code != 200:
        result["message"] = f"HTTP {r.status_code}"
        return result

    try:
        analysis_id = r.json()["data"]["id"]
        rep = _requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers, timeout=timeout)
        stats = rep.json()["data"]["attributes"]["stats"]
        result.update({"status": "success",
                        "malicious":  stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless":   stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "message":    "VirusTotal analysis complete"})
    except Exception as exc:
        result["message"] = f"Parse error: {exc}"
    return result


# ============================================================
#  SQLITE HISTORY
# ============================================================
class HistoryManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id      TEXT PRIMARY KEY,
                    url          TEXT NOT NULL,
                    risk_label   TEXT NOT NULL,
                    risk_score   INTEGER NOT NULL,
                    reasons      TEXT NOT NULL,
                    ti_status    TEXT,
                    ti_malicious INTEGER DEFAULT 0,
                    scanned_at   TEXT NOT NULL
                )
            """)
            conn.commit()

    def save(self, result: ScanResult):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scan_history
                (scan_id, url, risk_label, risk_score, reasons,
                 ti_status, ti_malicious, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (result.scan_id, result.url, result.risk_label,
                  result.risk_score, json.dumps(result.reasons),
                  result.ti_result.get("status", ""),
                  result.ti_result.get("malicious", 0),
                  result.scanned_at))
            conn.commit()

    def load_all(self, limit: int = 200) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            try:
                d["reasons"] = json.loads(d["reasons"])
            except Exception:
                d["reasons"] = []
            out.append(d)
        return out

    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]

    def clear(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM scan_history")
            conn.commit()

    def stats(self) -> dict:
        records = self.load_all()
        if not records:
            return {"total": 0, "low": 0, "suspicious": 0, "high": 0, "avg_score": 0.0}
        total = len(records)
        return {
            "total":      total,
            "low":        sum(1 for r in records if r["risk_label"] == "Low Risk"),
            "suspicious": sum(1 for r in records if r["risk_label"] == "Suspicious"),
            "high":       sum(1 for r in records if r["risk_label"] == "High Risk"),
            "avg_score":  round(sum(r["risk_score"] for r in records) / total, 1),
        }


history_manager = HistoryManager(DB_PATH)


# ============================================================
#  FLASK APPLICATION
# ============================================================
if not _FLASK_OK:
    raise SystemExit(
        "\n[ERROR] Flask is not installed.\n"
        "Install it with:  pip install flask\n"
        "Then re-run:      python app.py\n"
    )

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False


# ── HTML template (single-file, no external assets) ─────────
_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishGuard — Phishing Detection</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:24px 32px;border-bottom:1px solid #2d3748;display:flex;align-items:center;gap:16px}
header h1{font-size:24px;font-weight:700;color:#fff}
header p{font-size:13px;color:#94a3b8;margin-top:4px}
.badge{background:#e53e3e;color:#fff;font-size:11px;padding:3px 8px;border-radius:20px;font-weight:600;letter-spacing:.5px}
main{max-width:960px;margin:32px auto;padding:0 24px}
.card{background:#1e2130;border:1px solid #2d3748;border-radius:12px;padding:24px;margin-bottom:20px}
.card h2{font-size:16px;font-weight:600;margin-bottom:16px;color:#cbd5e0}
.scan-row{display:flex;gap:10px}
#url-input{flex:1;background:#0f1117;border:2px solid #2d3748;color:#e2e8f0;padding:11px 16px;border-radius:8px;font-size:15px;transition:border .2s}
#url-input:focus{outline:none;border-color:#4299e1}
#url-input::placeholder{color:#4a5568}
.btn{padding:11px 20px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s}
.btn-primary{background:#4299e1;color:#fff}
.btn-primary:hover{background:#3182ce}
.btn-primary:disabled{background:#2d3748;cursor:not-allowed}
.btn-sm{padding:7px 14px;font-size:13px}
.btn-danger{background:#e53e3e;color:#fff}
.btn-danger:hover{background:#c53030}
.btn-success{background:#38a169;color:#fff}
.btn-success:hover{background:#2f855a}
.btn-ghost{background:#2d3748;color:#a0aec0}
.btn-ghost:hover{background:#4a5568}
#result-area{min-height:60px}
.result-card{border-radius:10px;padding:20px;border:2px solid}
.low-risk{border-color:#38a169;background:#1a2e23}
.suspicious{border-color:#d69e2e;background:#2d2510}
.high-risk{border-color:#e53e3e;background:#2d1515}
.verdict{font-size:22px;font-weight:700;margin-bottom:4px}
.score-row{display:flex;align-items:center;gap:12px;margin:12px 0}
.score-bar-bg{flex:1;height:8px;background:#2d3748;border-radius:4px}
.score-bar{height:8px;border-radius:4px;transition:width .5s}
.url-display{font-size:13px;color:#94a3b8;word-break:break-all;background:#0f1117;padding:8px 12px;border-radius:6px;margin:10px 0;font-family:monospace}
.reasons{margin-top:12px}
.reasons h4{font-size:13px;color:#94a3b8;margin-bottom:8px}
.reason-item{display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;font-size:13px}
.reason-item::before{content:"⚠";flex-shrink:0;margin-top:1px}
.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-top:14px}
.feat{background:#0f1117;border:1px solid #2d3748;border-radius:6px;padding:8px 12px}
.feat-label{font-size:11px;color:#4a5568;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px}
.feat-val{font-size:14px;font-weight:600}
.feat-val.good{color:#68d391}
.feat-val.bad{color:#fc8181}
.feat-val.neutral{color:#e2e8f0}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;background:#0f1117;color:#64748b;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td{padding:9px 12px;border-bottom:1px solid #1e2130}
tr:hover td{background:#0f1117}
.label-badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
.label-low{background:#1a2e23;color:#68d391}
.label-sus{background:#2d2510;color:#ecc94b}
.label-high{background:#2d1515;color:#fc8181}
.stats-row{display:flex;gap:16px;flex-wrap:wrap}
.stat-box{flex:1;min-width:130px;background:#0f1117;border:1px solid #2d3748;border-radius:8px;padding:14px 16px;text-align:center}
.stat-num{font-size:26px;font-weight:700;line-height:1}
.stat-lbl{font-size:12px;color:#4a5568;margin-top:4px}
.actions-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.notice{background:#1a2e23;border:1px solid #276749;color:#68d391;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:14px}
.error-msg{background:#2d1515;border:1px solid #822727;color:#fc8181;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:14px}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid #4a5568;border-top-color:#4299e1;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
.disclaimer{background:#1e2130;border:1px solid #2d3748;border-radius:8px;padding:12px 16px;font-size:12px;color:#64748b;margin-bottom:20px}
.disclaimer strong{color:#94a3b8}
.empty-state{text-align:center;padding:40px;color:#4a5568}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡️ PhishGuard <span class="badge">PROTOTYPE</span></h1>
    <p>Intelligent Phishing Detection System — by Tushar Solanki &nbsp;|&nbsp; Educational cybersecurity tool</p>
  </div>
</header>
<main>
  <div class="disclaimer">
    <strong>⚠️ Disclaimer:</strong> PhishGuard uses heuristic analysis — it can produce <strong>false positives and false negatives</strong> and
    <strong>cannot guarantee</strong> any URL is safe or malicious. The scanned URL is <strong>never visited</strong> by this tool.
    This is an educational prototype, not a production security product.
  </div>

  <div class="card">
    <h2>🔍 URL Scanner</h2>
    <div class="scan-row">
      <input id="url-input" type="text" placeholder="https://example.com/path?param=value" autocomplete="off" spellcheck="false">
      <button class="btn btn-primary" id="scan-btn" onclick="doScan()">Scan</button>
    </div>
    <div style="font-size:12px;color:#4a5568;margin-top:8px">
      Press Enter or click Scan. The URL is analysed structurally — it is <em>never opened or visited</em>.
    </div>
  </div>

  <div id="result-area"></div>

  <div class="card" id="dashboard-card">
    <h2>📊 Dashboard</h2>
    <div class="stats-row" id="stats-row">
      <div class="stat-box"><div class="stat-num" id="s-total">—</div><div class="stat-lbl">Total Scans</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#68d391" id="s-low">—</div><div class="stat-lbl">Low Risk</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#ecc94b" id="s-sus">—</div><div class="stat-lbl">Suspicious</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#fc8181" id="s-high">—</div><div class="stat-lbl">High Risk</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#4299e1" id="s-avg">—</div><div class="stat-lbl">Avg Score</div></div>
    </div>
  </div>

  <div class="card">
    <h2>📋 Scan History</h2>
    <div class="actions-row">
      <button class="btn btn-sm btn-success" onclick="exportData('csv')">📥 Export CSV</button>
      <button class="btn btn-sm btn-success" onclick="exportData('json')">📥 Export JSON</button>
      <button class="btn btn-sm btn-danger" onclick="clearHistory()">🗑️ Clear History</button>
      <button class="btn btn-sm btn-ghost" onclick="loadHistory()">🔄 Refresh</button>
    </div>
    <div id="history-area"><div class="empty-state">No scans yet. Enter a URL above to begin.</div></div>
  </div>
</main>

<script>
const $ = id => document.getElementById(id);

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadHistory();
  $('url-input').addEventListener('keydown', e => { if (e.key === 'Enter') doScan(); });
});

function riskClass(label) {
  if (label === 'Low Risk') return 'low-risk';
  if (label === 'Suspicious') return 'suspicious';
  return 'high-risk';
}
function riskIcon(label) {
  if (label === 'Low Risk') return '🟢';
  if (label === 'Suspicious') return '🟡';
  return '🔴';
}
function riskColor(label) {
  if (label === 'Low Risk') return '#68d391';
  if (label === 'Suspicious') return '#ecc94b';
  return '#fc8181';
}
function labelBadge(label) {
  const cls = label === 'Low Risk' ? 'label-low' : label === 'Suspicious' ? 'label-sus' : 'label-high';
  return `<span class="label-badge ${cls}">${riskIcon(label)} ${label}</span>`;
}

async function doScan() {
  const url = $('url-input').value.trim();
  if (!url) { showError('Please enter a URL.'); return; }
  const btn = $('scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Scanning…';
  $('result-area').innerHTML = '';
  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, api_key: ''})
    });
    const data = await resp.json();
    if (data.error) { showError(data.error); return; }
    renderResult(data);
    loadStats();
    loadHistory();
  } catch(e) {
    showError('Network error: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Scan';
  }
}

function showError(msg) {
  $('result-area').innerHTML = `<div class="error-msg">❌ ${msg}</div>`;
}

function renderResult(d) {
  const f = d.features;
  const color = riskColor(d.risk_label);
  const reasons = d.reasons.map(r => `<div class="reason-item">${r}</div>`).join('');
  const feats = [
    ['Scheme',        f.scheme || 'N/A',                   f.is_https ? 'good' : 'bad'],
    ['HTTPS',         f.is_https ? 'Yes ✓' : 'No ✗',       f.is_https ? 'good' : 'bad'],
    ['IP Hostname',   f.is_ip_hostname ? 'Yes ⚠' : 'No',   f.is_ip_hostname ? 'bad' : 'good'],
    ['@ Symbol',      f.has_at_symbol ? 'Yes ⚠' : 'No',    f.has_at_symbol ? 'bad' : 'good'],
    ['URL Length',    f.url_length + ' chars',              f.url_length > 75 ? 'bad' : 'good'],
    ['Subdomains',    f.subdomain_count,                    f.subdomain_count >= 2 ? 'bad' : 'good'],
    ['Keywords',      f.suspicious_kw_count + (f.suspicious_kw_found.length ? ` (${f.suspicious_kw_found.slice(0,3).join(', ')})` : ''), f.suspicious_kw_count > 0 ? 'bad' : 'good'],
    ['TLD',           f.tld || 'N/A',                       f.unusual_tld ? 'bad' : 'good'],
    ['Punycode',      f.is_punycode ? 'Yes ⚠' : 'No',      f.is_punycode ? 'bad' : 'good'],
    ['Port',          f.port ? f.port : 'standard',         (f.port && ![80,443,8080,8443].includes(f.port)) ? 'bad' : 'neutral'],
  ].map(([lbl,val,cls]) => `<div class="feat"><div class="feat-label">${lbl}</div><div class="feat-val ${cls}">${val}</div></div>`).join('');

  let ti = '';
  if (d.ti_result && d.ti_result.status === 'success') {
    ti = `<div style="margin-top:14px;padding-top:12px;border-top:1px solid #2d3748">
      <strong style="font-size:13px;color:#94a3b8">Threat Intelligence (VirusTotal)</strong>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:8px;font-size:13px">
        <div class="feat"><div class="feat-label">Malicious</div><div class="feat-val ${d.ti_result.malicious>0?'bad':'good'}">${d.ti_result.malicious}</div></div>
        <div class="feat"><div class="feat-label">Suspicious</div><div class="feat-val neutral">${d.ti_result.suspicious}</div></div>
        <div class="feat"><div class="feat-label">Harmless</div><div class="feat-val good">${d.ti_result.harmless}</div></div>
        <div class="feat"><div class="feat-label">Undetected</div><div class="feat-val neutral">${d.ti_result.undetected}</div></div>
      </div></div>`;
  } else if (d.ti_result && d.ti_result.message) {
    ti = `<div style="margin-top:10px;font-size:12px;color:#4a5568">ℹ️ ${d.ti_result.message}</div>`;
  }

  $('result-area').innerHTML = `
  <div class="result-card ${riskClass(d.risk_label)}" style="margin-bottom:20px">
    <div class="verdict" style="color:${color}">${riskIcon(d.risk_label)} ${d.risk_label}</div>
    <div class="score-row">
      <span style="font-size:13px;color:#94a3b8">Risk Score: <strong style="color:${color}">${d.risk_score}/100</strong></span>
      <div class="score-bar-bg"><div class="score-bar" style="width:${d.risk_score}%;background:${color}"></div></div>
      <span style="font-size:11px;color:#4a5568">heuristic index</span>
    </div>
    <div class="url-display">${escapeHtml(d.url)}</div>
    <div class="reasons">
      <h4>Risk Indicators (${d.reasons.length})</h4>
      ${reasons}
    </div>
    <div class="features-grid" style="margin-top:14px">${feats}</div>
    ${ti}
    <div style="margin-top:12px;font-size:11px;color:#4a5568;border-top:1px solid #2d3748;padding-top:8px">
      Scan ID: ${d.scan_id} &nbsp;·&nbsp; ${d.scanned_at}
      &nbsp;·&nbsp; ⚠️ Heuristic scores are NOT probabilities and may produce false results.
    </div>
  </div>`;
}

async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();
    $('s-total').textContent = s.total;
    $('s-low').textContent   = s.low;
    $('s-sus').textContent   = s.suspicious;
    $('s-high').textContent  = s.high;
    $('s-avg').textContent   = s.avg_score;
  } catch(e) {}
}

async function loadHistory() {
  try {
    const r = await fetch('/api/history');
    const data = await r.json();
    if (!data.records || data.records.length === 0) {
      $('history-area').innerHTML = '<div class="empty-state">No scans yet.</div>';
      return;
    }
    const rows = data.records.map(r => {
      const urlShort = r.url.length > 70 ? r.url.slice(0, 70) + '…' : r.url;
      return `<tr>
        <td style="color:#4a5568;white-space:nowrap">${r.scanned_at}</td>
        <td style="font-family:monospace;font-size:12px" title="${escapeHtml(r.url)}">${escapeHtml(urlShort)}</td>
        <td>${labelBadge(r.risk_label)}</td>
        <td style="text-align:center;font-weight:600;color:${riskColor(r.risk_label)}">${r.risk_score}</td>
      </tr>`;
    }).join('');
    $('history-area').innerHTML = `
      <table>
        <thead><tr><th>Time</th><th>URL</th><th>Verdict</th><th style="text-align:center">Score</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch(e) {}
}

async function clearHistory() {
  if (!confirm('Delete all scan history?')) return;
  await fetch('/api/history', {method:'DELETE'});
  loadStats();
  loadHistory();
}

async function exportData(fmt) {
  window.location.href = `/api/export/${fmt}`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


# ── Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    return Response(_HTML, mimetype="text/html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    body = request.get_json(silent=True) or {}
    raw_url = (body.get("url") or "").strip()
    api_key = (body.get("api_key") or VIRUSTOTAL_API_KEY or "").strip()

    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    # Refuse if the URL would resolve to the scanner itself (localhost)
    try:
        _parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
        _h = (_parsed.hostname or "").lower()
        if _h in ("localhost", "127.0.0.1", "::1", "0.0.0.0") and \
           (_parsed.port == PORT or not _parsed.port):
            return jsonify({"error": "Cannot scan the PhishGuard server itself"}), 400
    except Exception:
        pass

    result = scan_url(raw_url, api_key=api_key)
    history_manager.save(result)
    return jsonify(result.to_dict())


@app.route("/api/history", methods=["GET"])
def api_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    records = history_manager.load_all(limit=limit)
    return jsonify({"records": records, "total": history_manager.count()})


@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    history_manager.clear()
    return jsonify({"ok": True, "message": "History cleared"})


@app.route("/api/stats")
def api_stats():
    return jsonify(history_manager.stats())


@app.route("/api/export/csv")
def api_export_csv():
    records = history_manager.load_all(limit=5000)
    if not records:
        return Response("No records to export.", mimetype="text/plain"), 204

    buf = io.StringIO()
    fieldnames = ["scan_id", "url", "risk_label", "risk_score",
                  "reasons", "ti_status", "ti_malicious", "scanned_at"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in records:
        r2 = dict(r)
        if isinstance(r2.get("reasons"), list):
            r2["reasons"] = " | ".join(r2["reasons"])
        writer.writerow(r2)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=phishguard_{ts}.csv"},
    )


@app.route("/api/export/json")
def api_export_json():
    records = history_manager.load_all(limit=5000)
    payload = {
        "exported_at":   datetime.datetime.now().isoformat(timespec="seconds"),
        "tool":          "PhishGuard — Intelligent Phishing Detection System",
        "author":        "Tushar Solanki",
        "total_records": len(records),
        "records":       records,
    }
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=phishguard_{ts}.json"},
    )


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "db_records": history_manager.count(),
        "vt_key_configured": bool(VIRUSTOTAL_API_KEY),
    })


# ============================================================
#  ENTRY POINT
# ============================================================
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  🛡️  PhishGuard — Intelligent Phishing Detection System")
    print("=" * 60)
    print(f"  Author  : Tushar Solanki")
    print(f"  Server  : http://localhost:{PORT}")
    print(f"  DB      : {os.path.abspath(DB_PATH)}")
    print(f"  VT API  : {'configured' if VIRUSTOTAL_API_KEY else 'not set (set VT_API_KEY env var)'}")
    print("=" * 60)
    print(f"\n  ➜  Open Chrome at:  http://localhost:{PORT}\n")
    print("  Press Ctrl+C to stop.\n")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
