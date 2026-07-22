# ConfigSentry

**ConfigSentry** is an asynchronous, high-performance security CLI tool engineered to audit web applications for security misconfigurations, missing HTTP security headers, SSL/TLS certificate flaws, and technology stack leaks.

Designed with **Clean Architecture** and the **Strategy Pattern**, ConfigSentry provides security engineers, DevOps professionals, and developers with clear, color-coded, and actionable remediation guidance directly in their terminal.

---

## Key Features

* **HTTP Security Header Audit:** Identifies missing or misconfigured OWASP-recommended security headers including `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, and `X-Content-Type-Options`.
* **Information Disclosure Detection:** Scans HTTP headers for software version leakage (`Server`) and backend stack identification (`X-Powered-By`).
* **SSL/TLS Certificate Inspection:** Validates HTTPS enforcement, connection state, certificate validity, and expiration timeframes.
* **Resilient Network Handling:** Gracefully handles DNS failures, connection timeouts, and network unreachable scenarios with detailed diagnostic output.
* **Extensible & Modular Architecture:** Easily add custom analyzers by extending the strategy-based base analyzer class.
* **Rich Terminal Output:** Renders formatted tables, risk classifications, and remediation steps using `Rich` and `Typer`.
* **Automated CI/CD Workflows:** Fully integrated with GitHub Actions for multi-version Python testing via `pytest`.

---

## Architecture & Project Structure

```text
configsentry/
├── .github/
│   └── workflows/
│       └── tests.yml          # CI/CD pipeline for automated testing
├── configsentry/              # Core application package
│   ├── __init__.py
│   ├── cli.py                 # Typer-based CLI interface
│   ├── core/                  # Engine orchestrator & Pydantic models
│   │   ├── engine.py
│   │   └── models.py
│   ├── analyzers/             # Strategy-pattern analyzer modules
│   │   ├── base.py
│   │   ├── headers.py
│   │   ├── ssl_tls.py
│   │   └── server_info.py
│   └── reporters/             # Terminal reporting modules (Rich)
│       └── console.py
├── tests/                     # Asynchronous unit test suite
│   └── test_engine.py
├── main.py                    # Entry point execution script
├── pyproject.toml             # Project metadata and pytest configuration
├── requirements.txt           # Dependency requirements
├── LICENSE                    # MIT License
└── README.md                  # Project documentation

```

---

## Installation

### Prerequisites

* Python **3.10** or higher
* `pip` package manager

### Setup Instructions

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
pip install -e .[dev]

```



---

## Usage

### Run a Security Scan

Audit a target web application by executing the `scan` command:

```bash
python3 main.py scan https://example.com

```

### Advanced Usage Options

* **Custom Request Timeout:**
Set a custom connection timeout in seconds (default: 10.0s):
```bash
python3 main.py scan https://example.com --timeout 5.0

```


* **Help Menu:**
View available commands and options:
```bash
python3 main.py --help

```



---

## Running Tests

Execute the asynchronous test suite using `pytest`:

```bash
pytest

```

---

## Sample Scan Output

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

## Disclaimer

ConfigSentry is developed strictly for educational purposes, defensive security auditing, and authorized infrastructure testing. Always obtain explicit permission from the target system owner prior to executing scans.

---

## License

This project is licensed under the [MIT License](https://www.google.com/search?q=LICENSE).