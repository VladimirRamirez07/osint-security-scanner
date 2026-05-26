# 🔍 OSINT Security Scanner

> OSINT security analysis tool that audits the public infrastructure of any domain **without sending a single direct attack**. Automatically generates professional PDF reports with security scoring.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![Legal](https://img.shields.io/badge/100%25-Legal-22c55e?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-22c55e?style=flat-square)
![DNS](https://img.shields.io/badge/DNS-SPF%20%7C%20DKIM%20%7C%20DMARC-58A6FF?style=flat-square)
![Security](https://img.shields.io/badge/Security-HTTP%20Headers-F85149?style=flat-square&logo=hackthebox&logoColor=white)
![OSINT](https://img.shields.io/badge/OSINT-Subdomain%20Takeover-D29922?style=flat-square)
![ReportLab](https://img.shields.io/badge/Reports-PDF%20ReportLab-EC1C24?style=flat-square&logo=adobeacrobatreader&logoColor=white)
![Threading](https://img.shields.io/badge/Threading-Parallel%20Scanning-8B5CF6?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-0D1117?style=flat-square&logo=windows&logoColor=white)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/vladimir-ram%C3%ADrez-303a433ba)
![CI](https://github.com/VladimirRamirez07/osint-security-scanner/actions/workflows/ci.yml/badge.svg)

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

## 🧪 CI/CD

This project uses **GitHub Actions** for continuous integration. Every push to `main` automatically:

- ✅ Installs all dependencies
- ✅ Runs the full unit test suite with `pytest`
- ✅ Reports test coverage across `scanner/` and `report/`
- ✅ Runs `flake8` lint checks

> See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full pipeline configuration.

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

## 🧪 Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=scanner --cov=report --cov-report=term-missing
```

---

## 🗂️ Project Structure

```
osint-security-scanner/
│
├── .github/
│   └── workflows/
│       └── ci.yml                # GitHub Actions CI/CD pipeline
│
├── scanner/
│   ├── dns_checker.py            # SPF, DKIM, DMARC via dnspython
│   ├── http_checker.py           # HTTP security headers analysis
│   └── subdomain_checker.py      # Parallel subdomain + takeover detection
│
├── report/
│   └── pdf_generator.py          # Professional PDF reports with ReportLab
│
├── tests/
│   ├── test_dns.py               # Unit tests for DNS module
│   ├── test_http.py              # Unit tests for HTTP module
│   └── test_subdomains.py        # Unit tests for subdomain module
│
├── sample_reports/               # Generated PDF reports (examples)
├── main.py                       # CLI entry point
└── requirements.txt
```

---

## 📦 Dependencies

```
dnspython==2.7.0
requests==2.32.3
reportlab==4.4.1
colorama==0.4.6
urllib3==2.4.0
pytest==8.3.5
pytest-cov==6.1.0
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