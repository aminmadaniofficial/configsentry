# ConfigSentry

**ConfigSentry** is a high-performance, asynchronous CLI tool designed to audit web applications for common security misconfigurations, missing HTTP security headers, and SSL/TLS certificate issues.

Built with Python, `httpx`, `Typer`, and `Rich`, ConfigSentry provides clear, actionable security insights and remediation strategies in a visually structured terminal output.

---

## ⚡ Features

* **HTTP Security Header Audit:** Detects missing or weak OWASP-recommended HTTP response headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
* **Information Disclosure Detection:** Scans for server software and technology stack leaks in `Server` and `X-Powered-By` headers.
* **SSL/TLS Certificate Inspection:** Checks certificate validity, expiration timeframes, and transport protocol security.
* **Resilient Network Handling:** Handles DNS failures, connection timeouts, and network unreachable errors gracefully.
* **Extensible Architecture:** Designed using the **Strategy Pattern** for adding custom analysis modules.
* **Rich CLI Output:** Presents findings in color-coded, formatted terminal tables.

---

## 📁 Repository Structure

```text
configsentry/
├── README.md                  # Project documentation
├── LICENSE                    # MIT License
├── pyproject.toml             # Package metadata and dependencies
├── main.py                    # Application entry point
├── configsentry/              # Core package
│   ├── __init__.py
│   ├── cli.py                 # CLI interface setup (Typer)
│   ├── core/                  # Core scanning engine & data models
│   │   ├── engine.py
│   │   └── models.py
│   ├── analyzers/             # Strategy-based security analyzers
│   │   ├── base.py
│   │   ├── headers.py
│   │   ├── ssl_tls.py
│   │   └── server_info.py
│   └── reporters/             # Terminal reporting modules
│       └── console.py
└── tests/                     # Test suite

```

---

## 🚀 Installation

### Prerequisites

* Python 3.10 or higher
* `pip` package manager

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/aminmadaniofficial/configsentry.git
cd configsentry

```


2. **Create and activate a virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

```


3. **Install dependencies:**
```bash
pip install httpx pydantic typer rich pytest

```



---

## 📖 Usage

Run a security audit against a target URL using the CLI:

```bash
python3 main.py scan https://example.com

```

### Options

* **Custom Request Timeout:**
```bash
python3 main.py scan https://example.com -t 5.0

```


* **Display Help:**
```bash
python3 main.py --help

```



---

## 📊 Sample Output

```text
🔍 Initiating security scan against: https://example.com

╭───────── ConfigSentry Scan Summary ─────────╮
│ Target: https://example.com                 │
│ Scan Time: 2026-07-22 12:00:00 UTC          │
│ Total Issues Found: 4                       │
╰─────────────────────────────────────────────╯

                        Identified Security Findings
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Risk Level   ┃ Issue Title                    ┃ Description                              ┃ Remediation Strategy                          ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH         │ Missing Security Header:       │ Enforces HTTPS connections to prevent    │ Add 'Strict-Transport-Security:               │
│              │ Strict-Transport-Security      │ Man-in-the-Middle attacks.               │ max-age=31536000; includeSubDomains' header.  │
│ HIGH         │ Missing Security Header:       │ Prevents Cross-Site Scripting (XSS) and  │ Define a strict Content-Security-Policy       │
│              │ Content-Security-Policy        │ data injection attacks.                  │ header restriction.                           │
│ MEDIUM       │ Missing Security Header:       │ Protects against Clickjacking attacks.   │ Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.  │
│              │ X-Frame-Options                │                                          │                                               │
│ LOW          │ Missing Security Header:       │ Prevents MIME-sniffing vulnerabilities.  │ Set 'X-Content-Type-Options: nosniff'.        │
│              │ X-Content-Type-Options         │                                          │                                               │
└──────────────┴────────────────────────────────┴──────────────────────────────────────────┴───────────────────────────────────────────────┘

```

---

## 🛡️ Disclaimer

ConfigSentry is designed strictly for educational purposes, defensive security auditing, and authorized infrastructure assessment. Users are responsible for ensuring they have authorization to audit target applications before running scans.

---

## 📄 License

This project is licensed under the [MIT License](https://www.google.com/search?q=LICENSE).