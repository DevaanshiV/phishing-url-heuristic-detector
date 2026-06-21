# Phishing URL Heuristic Detector

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Overview

A **zero‑dependency**, production‑ready Python 3 tool for **heuristic‑based phishing URL detection**.  
Developed for the IIT Kanpur B.Cyber application portfolio, this engine evaluates URLs against a multi‑faceted risk matrix using only Python’s standard library (`urllib.parse`, `re`, `sys`, `time`).

The scanner outputs a clear risk classification and a detailed ASCII summary table, making it ideal for both educational study and real‑world security triage.

---

## ⚙️ Heuristic Risk Score Mechanics

Each URL undergoes a battery of heuristic checks; every triggered flag contributes a **weighted score**. The total risk score is then mapped to one of three threat levels.

| Heuristic Check            | Weight | Description                                                                 |
|----------------------------|--------|-----------------------------------------------------------------------------|
| **IP as domain**           | 2      | Host is a raw IPv4 address (e.g., `192.168.1.1`)                           |
| **Excessive URL length**   | 1      | URL length exceeds `MAX_URL_LENGTH` (default 120 characters)               |
| **Dangerous keywords**     | 1 each | Matches any keyword from a curated list (e.g., `login`, `paypal`, `verify`) |
| **Excessive tracking chars**| 1      | More than 5 `?`, `&`, or `=` characters in path/query                     |
| **Excessive hyphens**      | 1      | More than 2 hyphens (`-`) in the hostname                                 |
| **Deep subdomain layering**| 1      | More than 3 dots in the host (indicating ≥4 subdomain levels)              |
| **Non‑standard port**      | 1      | Port is explicitly specified and **not** in {80, 443, 8080, 8443}         |

**Risk Classification Thresholds:**

| Risk Class      | Score Range | Description                                      |
|-----------------|-------------|--------------------------------------------------|
| `SAFE`          | 0 – 3       | No significant indicators detected.              |
| `SUSPICIOUS`    | 4 – 6       | Multiple anomalies present – exercise caution.   |
| `CRITICAL`      | ≥ 7         | High‑confidence phishing target – do not proceed.|

---

## 🔍 Pattern Parsing & Obfuscation Rules

### 1. **IP Address Detection**
- **IPv4 regex** (full 0‑255 range) strictly matches the host portion.
- IPv6 is omitted for simplicity, but the architecture can be extended.

### 2. **Keyword Scanning**
- Case‑insensitive check against a built‑in list of 11 terms commonly abused in phishing campaigns.
- The list is extensible; each unique match adds 1 point to the score.

### 3. **Structural Anomaly Metrics**
| Metric                | Threshold | Purpose                                 |
|-----------------------|-----------|-----------------------------------------|
| **Tracking characters** | `>5`     | Flags URLs overloaded with query params often used for redirection or fingerprinting. |
| **Hyphens in host**   | `>2`     | Abused to mimic legitimate domains (e.g., `paypal-secure-login.com`). |
| **Subdomain layers**  | `>3`     | Excessive dots (e.g., `a.b.c.d.e.com`) indicate deep nesting, a common evasion tactic. |

### 4. **Port Parsing**
- Extracts the port from `netloc` (if specified) and compares against a whitelist of standard ports.
- Any deviation (e.g., `:8081`, `:4443`) triggers the warning.

### 5. **Length Obfuscation**
- URLs exceeding 120 characters are considered suspicious – long strings often hide malicious payloads or redirection chains.

---

## 📦 Prerequisites

- **Python 3.6** or higher.
- No external libraries – runs in any sandbox, cloud shell, or offline environment without installation headaches.

---

## 🚀 Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/phishing-url-heuristic-detector.git
cd phishing-url-heuristic-detector

# 2. Make the script executable (Unix/Linux/macOS)
chmod +x phishing_detector.py
