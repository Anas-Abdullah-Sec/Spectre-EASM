
# 🛡️ SpectreEASM — External Attack Surface Management & Risk Tracker

> **An Enterprise-Grade Passive Reconnaissance & Continuous Risk Assessment Framework.**

![Python Version](https://img.shields.io/badge/python-3.9%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security Focus](https://img.shields.io/badge/field-Cybersecurity%20%26%20EASM-red.svg)

---

## 📌 Executive Overview

**SpectreEASM** is an asynchronous Python-based External Attack Surface Management (EASM) engine designed to map an organization's public-facing digital footprint without launching intrusive attacks. 

In modern cybersecurity operations, **Shadow IT** (untracked or forgotten subdomains/servers) poses a major security gap. SpectreEASM rapidly enumerates subdomains using public Certificate Transparency (CT) logs and OSINT feeds, performs HTTP/TLS fingerprinting, identifies missing security headers, and computes an algorithmic **CVSS-style Risk Score** for prioritization.

---

## 🔥 Key Features

* **⚡ Async Passive Subdomain Discovery:** Rapidly aggregates subdomains via CT logs (`crt.sh`) and OSINT APIs (`HackerTarget`) using `aiohttp` and `asyncio`.
* **🔒 Context-Aware Risk Engine:** Evaluates operational status (`200 OK`, `404 Not Found`, `403 Forbidden`) to eliminate false-positive risk scores.
* **🛡️ HTTP Security Header Audit:** Checks presence of critical defensive headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
* **🎨 Hacker-Themed Rich CLI:** Features custom ASCII graphics, live spinner loaders, and color-coded interactive tables using `rich`.
* **📄 Multi-Format Reporting:** Outputs cleanly formatted assessment reports in JSON for SOC/SIEM integration.

---

## 🛠️ Installation & Setup

Ensure you have **Python 3.9+** and `pip` installed on your Kali Linux / Linux machine.

```bash
# Clone the repository
git clone [https://github.com/your-username/spectre-easm.git](https://github.com/your-username/spectre-easm.git)
cd spectre-easm

# Install required dependencies
pip install rich aiohttp

```

---

## 🚀 Usage

### 1. Interactive Mode

Simply run the tool without arguments to enter the interactive prompt mode:

```bash
python3 spectre.py

```

### 2. Command Line Argument Mode

Run non-interactively by specifying the target domain and output report path:

```bash
# Basic Scan
python3 spectre.py -d example.com

# Scan & Save JSON Assessment Report
python3 spectre.py -d example.com -o report.json

```

---

## 📊 Risk Scoring Model

SpectreEASM utilizes a dynamic scoring matrix to prioritize remediation efforts:

| Operational Status | Header Audit / Vulnerability | Risk Score | Severity Level |
| --- | --- | --- | --- |
| **`404 / 403 / Timeout`** | Inactive / Restricted Asset | **`0.0 - 1.5`** | **`LOW / INFO`** |
| **`200 OK`** | Missing MIME Sniffing Protection | **`+0.5`** | **`LOW`** |
| **`200 OK`** | Missing Clickjacking Protection (`X-Frame-Options`) | **`+1.5`** | **`MEDIUM`** |
| **`200 OK`** | Missing Content Security Policy (`CSP`) | **`+2.5`** | **`HIGH`** |
| **`200 OK`** | Missing HSTS Policy (`Strict-Transport-Security`) | **`+2.5`** | **`HIGH`** |
| **Cumulative Max** | All Major Headers Missing | **`7.0 - 10.0`** | **`CRITICAL`** |

---

## 👤 Author & Maintainer

* **Developer:** Anas Abdullah
* **Field:** Cybersecurity, Ethical Hacking & Infrastructure Security
- **LinkedIn:** [Anas Abdullah](https://www.linkedin.com/in/anas2abdullah/)
---

## 📜 License

This project is licensed under the **MIT License** — feel free to modify and expand for educational and enterprise auditing purposes.

---

## ⚠️ Disclaimer & Usage Caution

> **IMPORTANT:** This tool is developed strictly for **authorized security testing, educational purposes, and infrastructure assessment**.

- **Authorized Access Only:** Only scan target domains, networks, or assets that you own or have explicit, documented permission to test.
- **Passive Reconnaissance:** Spectre-EASM primary modules operate passively; however, active network requests (such as HTTP header checks) may be logged by target Intrusion Detection Systems (IDS/WAF).
- **Rate Limiting & Banning:** Excessive API requests or continuous rapid scanning may trigger rate limits or permanent IP blocks on external intelligence services (e.g., SecurityTrails, CRT.sh).
- **No Liability:** The developer assumes **no responsibility** for any misuse, unintended network disruptions, or legal consequences caused by the execution of this framework.


