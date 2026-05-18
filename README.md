# 🔍 OSINT Security Scanner

> OSINT security analysis tool that audits the public infrastructure of any domain **without sending a single direct attack**. Automatically generates professional PDF reports with security scoring.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Legal](https://img.shields.io/badge/100%25-Legal-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

---

## 📸 Sample Results

| Domain | DNS Score | HTTP Score | Subdomain Score | Overall |
|--------|-----------|------------|-----------------|---------|
| apple.com | 90/100 | 100/100 | 100/100 | **97/100 ✅** |
| netflix.com | 65/100 | 100/100 | 100/100 | **88/100 ✅** |

---

## 🧠 What does it analyze?

### 📧 Email Security (DNS)
- **SPF** — Verifies if the domain authorizes legitimate mail servers
- **DKIM** — Detects cryptographic email signatures (tests 8 common selectors)
- **DMARC** — Validates anti-phishing policy (`none` / `quarantine` / `reject`)

### 🌐 HTTP Security Headers
| Header | Protects against |
|--------|-----------------|
| `Strict-Transport-Security` | Downgrade attacks, MITM |
| `Content-Security-Policy` | XSS, code injection |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing |
| `Referrer-Policy` | Data leakage |
| `Permissions-Policy` | Browser API abuse |
| `X-XSS-Protection` | Legacy XSS |

### 🔎 Subdomain Enumeration
- Checks **40 common subdomains** in parallel using `ThreadPoolExecutor`
- Detects active subdomains with IP address and HTTP status
- Identifies **Subdomain Takeover** vulnerabilities across services like GitHub Pages, Heroku, AWS S3, Netlify, and more

---

## 📄 PDF Report

Each scan generates a professional PDF report including:
- Overall domain security score (0–100)
- DNS records table with visual status indicators
- Full list of present and missing HTTP headers
- Active subdomain map with takeover risk flags
- Scan metadata footer

> 📁 See example reports in [`/sample_reports`](./sample_reports/)

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/VladimirRamirez07/osint-security-scanner.git
cd osint-security-scanner

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ⚡ Usage

```bash
# Scan a single domain
python main.py apple.com

# Scan multiple domains at once
python main.py apple.com netflix.com google.com
```

### Expected output
```
🎯 Target: apple.com

── 📧 DNS Security (SPF / DKIM / DMARC) ──
  SPF  : ✓ v=spf1 include:icloud.com ...
  DKIM : ✓ Found
  DMARC: ✓ v=DMARC1; p=quarantine ...
  DNS Score: 90/100 [GOOD]

── 🌐 HTTP Security Headers ──
  HTTPS   : ✓ Enabled
  Headers present (6): HSTS, CSP, X-Frame-Options...
  HTTP Score: 100/100 [GOOD]

── 🔎 Subdomain Enumeration ──
  Found: 10 active subdomains
  Subdomain Score: 100/100 [GOOD]

── 📊 Overall Score ──
  apple.com: 97/100 [GOOD]

✓ Report saved: sample_reports/apple_com_security_report.pdf
```

---

## 🗂️ Project Structure

```
osint-security-scanner/
│
├── scanner/
│   ├── dns_checker.py        # SPF, DKIM, DMARC via dnspython
│   ├── http_checker.py       # HTTP security headers analysis
│   └── subdomain_checker.py  # Parallel subdomain + takeover detection
│
├── report/
│   └── pdf_generator.py      # Professional PDF reports with ReportLab
│
├── sample_reports/           # Generated PDF reports (examples)
├── main.py                   # CLI entry point
└── requirements.txt
```

---

## 📦 Dependencies

```
dnspython==2.6.1
requests==2.31.0
reportlab==4.1.0
colorama==0.4.6
```

---

## ⚖️ Legal & Ethics

> **100% legal** — This tool uses only:
> - Public DNS records (queryable by anyone)
> - Public HTTP response headers
> - No fuzzing, no payloads, no exploitation of vulnerabilities
>
> Use it only on domains you own or that are publicly accessible.

---

## 👤 Author

**Vladimir Ramirez** — [@VladimirRamirez07](https://github.com/VladimirRamirez07)

> *Built as part of a cybersecurity portfolio to demonstrate real-world OSINT and security analysis skills.*