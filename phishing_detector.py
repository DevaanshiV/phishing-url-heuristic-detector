#!/usr/bin/env python3
"""
Phishing URL Heuristic Detector
Advanced heuristic scanning engine for URL threat assessment.
Uses only Python built-in libraries (urllib.parse, re, sys, time).
"""

import sys
import re
import time
from urllib.parse import urlparse, ParseResult

# -------------------- Configuration Constants --------------------
# Thresholds and lists for heuristic analysis

# Maximum URL length considered safe (beyond this is suspicious)
MAX_URL_LENGTH = 120

# Common dangerous keywords found in phishing URLs (case-insensitive)
DANGEROUS_KEYWORDS = [
    'login', 'verify', 'banking', 'secure-update', 'paypal',
    'update-password', 'account', 'confirm', 'signin', 'auth',
    'wallet', 'security', 'alert', 'validate', 'recover'
]

# Standard ports for common protocols (safe)
STANDARD_PORTS = {80, 443, 8080, 8443}

# Heuristic weights for risk score calculation
WEIGHTS = {
    'ip_host': 2,
    'length_exceed': 1,
    'keyword_match': 1,          # per keyword
    'excessive_tracking': 1,
    'excessive_hyphens': 1,
    'deep_subdomains': 1,
    'non_standard_port': 1
}

# Risk thresholds
RISK_THRESHOLDS = {
    'SAFE': (0, 3),
    'SUSPICIOUS': (4, 6),
    'CRITICAL': (7, float('inf'))   # 7+ is critical
}


# -------------------- Heuristic Functions --------------------

def is_ip_address(host: str) -> bool:
    """
    Check if the host part of the URL is an IPv4 address.
    (IPv6 support is omitted for simplicity, but can be extended.)
    """
    # IPv4 pattern: four groups of 1-3 digits separated by dots, each 0-255
    ipv4_pattern = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    return bool(ipv4_pattern.match(host))


def check_url_length(url: str) -> bool:
    """Flag if URL length exceeds MAX_URL_LENGTH."""
    return len(url) > MAX_URL_LENGTH


def find_dangerous_keywords(url: str) -> list:
    """
    Scan URL (case-insensitive) for any dangerous keyword.
    Returns a list of matched keywords (unique).
    """
    url_lower = url.lower()
    matched = []
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in url_lower:
            matched.append(keyword)
    # Remove duplicates while preserving order
    unique = []
    for kw in matched:
        if kw not in unique:
            unique.append(kw)
    return unique


def count_structural_anomalies(parsed: ParseResult) -> dict:
    """
    Analyze structural anomalies:
      - Excessive tracking characters: count of ? & = in query string and path.
      - Excessive hyphens in the host name.
      - Deep sub-domain layering (number of dots in host before the TLD).
    Returns a dictionary with counts and booleans for thresholds.
    """
    host = parsed.netloc.split(':')[0] if parsed.netloc else ''
    path_query = parsed.path + parsed.query

    # Tracking characters: commonly used for tracking parameters
    tracking_chars = path_query.count('?') + path_query.count('&') + path_query.count('=')
    excessive_tracking = tracking_chars > 5   # arbitrary threshold

    # Hyphens in host (excluding possible port)
    hyphens = host.count('-')
    excessive_hyphens = hyphens > 2

    # Subdomain layering: number of dots in host (excluding trailing dot)
    # We consider typical domain like www.example.com -> 2 dots, so > 3 levels (4 dots) is deep
    dot_count = host.count('.')
    # Remove TLD: we count dots before the last dot; but we just use total dots.
    # For simplicity, if host has more than 3 dots, flag as deep subdomain.
    deep_subdomains = dot_count > 3

    return {
        'tracking_chars': tracking_chars,
        'excessive_tracking': excessive_tracking,
        'hyphens': hyphens,
        'excessive_hyphens': excessive_hyphens,
        'dot_count': dot_count,
        'deep_subdomains': deep_subdomains
    }


def extract_port(parsed: ParseResult) -> int:
    """
    Extract port number from netloc.
    Returns None if no port specified.
    """
    netloc = parsed.netloc
    if ':' in netloc:
        # Split on last colon (IPv6 might have colons, but we ignore IPv6 for simplicity)
        # We assume host:port format; for IPv6 we would need brackets, but we ignore.
        parts = netloc.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def check_non_standard_port(parsed: ParseResult) -> bool:
    """Flag if port is present and not in STANDARD_PORTS."""
    port = extract_port(parsed)
    if port is None:
        return False  # no port specified, assume default (safe)
    return port not in STANDARD_PORTS


# -------------------- Risk Scoring --------------------

def compute_risk_score(flags: dict) -> int:
    """
    Compute aggregate risk score based on heuristic flags.
    flags is a dictionary with keys: 'ip_host', 'length_exceed', 'keywords',
    'excessive_tracking', 'excessive_hyphens', 'deep_subdomains',
    'non_standard_port'.
    'keywords' is a list of matched keywords (count contributes per keyword).
    """
    score = 0

    if flags.get('ip_host', False):
        score += WEIGHTS['ip_host']

    if flags.get('length_exceed', False):
        score += WEIGHTS['length_exceed']

    # Each matched keyword contributes weight
    keyword_list = flags.get('keywords', [])
    score += len(keyword_list) * WEIGHTS['keyword_match']

    if flags.get('excessive_tracking', False):
        score += WEIGHTS['excessive_tracking']

    if flags.get('excessive_hyphens', False):
        score += WEIGHTS['excessive_hyphens']

    if flags.get('deep_subdomains', False):
        score += WEIGHTS['deep_subdomains']

    if flags.get('non_standard_port', False):
        score += WEIGHTS['non_standard_port']

    return score


def classify_risk(score: int) -> str:
    """Classify risk based on score thresholds."""
    for category, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return category
    return 'SAFE'  # fallback


# -------------------- Main Execution --------------------

def main():
    # 1. Obtain URL from user input (command-line argument or prompt)
    if len(sys.argv) > 1:
        url_input = sys.argv[1]
    else:
        url_input = input("Enter URL to analyze: ").strip()

    if not url_input:
        print("Error: No URL provided.")
        sys.exit(1)

    # 2. Parse URL (if scheme missing, prepend http:// for proper parsing)
    if not urlparse(url_input).scheme:
        # Add default scheme so parsing works
        url_input = 'http://' + url_input

    parsed = urlparse(url_input)
    host = parsed.netloc.split(':')[0] if parsed.netloc else ''

    # 3. Run heuristics
    flags = {}

    # IP address check
    flags['ip_host'] = is_ip_address(host)

    # Length check
    flags['length_exceed'] = check_url_length(url_input)

    # Keyword scan
    matched_keywords = find_dangerous_keywords(url_input)
    flags['keywords'] = matched_keywords

    # Structural anomalies
    struct = count_structural_anomalies(parsed)
    flags['excessive_tracking'] = struct['excessive_tracking']
    flags['excessive_hyphens'] = struct['excessive_hyphens']
    flags['deep_subdomains'] = struct['deep_subdomains']

    # Port check
    flags['non_standard_port'] = check_non_standard_port(parsed)

    # 4. Compute risk score and classification
    risk_score = compute_risk_score(flags)
    risk_class = classify_risk(risk_score)

    # 5. Build report data for ASCII table
    # We'll create a list of rows for the table
    rows = [
        ("URL", url_input),
        ("Host", host),
        ("Risk Score", str(risk_score)),
        ("Risk Classification", risk_class),
        ("IP Address as Host", "YES" if flags['ip_host'] else "NO"),
        ("Length Exceeds Threshold", "YES" if flags['length_exceed'] else "NO"),
        ("Dangerous Keywords Found", ", ".join(matched_keywords) if matched_keywords else "None"),
        ("Tracking Characters Count", str(struct['tracking_chars'])),
        ("Excessive Tracking", "YES" if flags['excessive_tracking'] else "NO"),
        ("Hyphens in Host", str(struct['hyphens'])),
        ("Excessive Hyphens", "YES" if flags['excessive_hyphens'] else "NO"),
        ("Subdomain Layers (dot count)", str(struct['dot_count'])),
        ("Deep Subdomain Layering", "YES" if flags['deep_subdomains'] else "NO"),
        ("Non-Standard Port", "YES" if flags['non_standard_port'] else "NO"),
        ("Timestamp", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    ]

    # 6. Print ASCII summary table
    # Determine column widths
    max_label_len = max(len(row[0]) for row in rows)
    max_value_len = max(len(str(row[1])) for row in rows)
    # Ensure minimum width
    col_width = max(max_label_len, max_value_len, 20) + 2

    # Header
    print("\n" + "=" * (col_width * 2 + 3))
    print(f"{'Phishing URL Heuristic Detector':^{col_width*2+3}}")
    print("=" * (col_width * 2 + 3))

    # Table rows
    for label, value in rows:
        # Truncate value if too long to avoid breaking layout
        value_str = str(value)
        if len(value_str) > col_width - 2:
            value_str = value_str[:col_width-5] + "..."
        print(f"| {label.ljust(col_width-1)} | {value_str.ljust(col_width-1)} |")

    print("=" * (col_width * 2 + 3))

    # Additional note for classification
    if risk_class == "SAFE":
        print("✅ No significant phishing indicators detected.")
    elif risk_class == "SUSPICIOUS":
        print("⚠️  Proceed with caution – multiple suspicious patterns found.")
    elif risk_class == "CRITICAL":
        print("❌ CRITICAL – Phishing target confirmed! Do not proceed.")

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()