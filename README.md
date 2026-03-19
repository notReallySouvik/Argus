# ARGUS

**Argus** is an offensive reconnaissance and attack surface intelligence engine for authorized red team operations.

It performs passive and active reconnaissance to discover, correlate, and analyze externally exposed assets across an organization’s internet-facing footprint.

Built on the principle:

> **Visibility before vulnerability.**



# What Argus Does

Argus is not a scanner.
It is an **intelligence engine**.

It collects signals from multiple layers of reconnaissance and converts them into **structured findings that explain exposure and potential risk**.

Argus helps answer:

* What is exposed?
* Why does it exist?
* How could it be abused?



# Core Capabilities

## Discovery

* Domain normalization and validation
* Subdomain candidate generation (wordlist + passive sources)
* DNS resolution and asset expansion
* Discovery source tracking with confidence scoring

## Enumeration

* HTTP/HTTPS probing with protocol awareness
* Redirect detection and preferred endpoint selection
* Web metadata extraction (title, headers)
* Technology fingerprinting (server, frameworks, CDN)

## Service Mapping

* Port detection (common services)
* Service classification (web, database, remote admin, plaintext)
* Exposure identification at the network layer

## Analysis (Signal Engine)

Argus converts raw data into **signals**, then into **findings**.

### Hostname Signals

* admin, dev, staging, test
* backup, internal, legacy

### Transport Signals

* HTTP-only exposure
* HTTPS availability
* redirect chains
* unexpected status codes

### Web Surface Signals

* login panels
* admin interfaces
* default pages
* error pages
* directory listing patterns

### Disclosure Signals

* server banner exposure
* technology disclosure
* framework exposure
* CDN detection

### Service Exposure Signals

* remote administration services (SSH, RDP)
* database services
* plaintext services



# Findings Engine

Each detected signal is transformed into a structured finding that includes:

* **What it means** (likely cause)
* **How it can impact the system**
* **Where it appears**
* **Confidence level**
* **Recommended review**

Argus does not just flag issues — it explains them.



# Output

Argus produces clean, structured outputs:

```
reports/
├── findings.json
├── assets.csv
└── report.html
```

## Terminal Output

* Discovered assets table
* Findings table (severity-based)
* Scan summary
* Output file paths

## JSON

Machine-readable structured data for automation.

## CSV

Flattened asset inventory for quick analysis.

## HTML

Human-readable report with:

* assets
* services
* signals
* findings
* impact descriptions



# Installation

```bash
git clone https://github.com/yourusername/argus.git
cd argus
python -m venv .venv
source .venv/bin/activate
pip install -e .
```



# Usage

Basic scan:

```bash
argus scan example.com
```

With options:

```bash
argus scan example.com --tech --output reports
```

Verbose / debug:

```bash
argus scan example.com --verbose
argus scan example.com --debug
```



# Example Signals

Argus detects patterns such as:

```
admin_keyword
non_production_keyword
backup_keyword
internal_keyword
legacy_keyword

login_panel
admin_panel
directory_listing_possible
default_page_detected

exposed_http_only
redirect_chain_detected

unexpected_server_banner
technology_disclosure
framework_disclosure
cdn_detected

remote_admin_service_exposed
database_service_exposed
plaintext_service_exposed
```



# Project Structure

```
argus/
├── cli.py
├── core/
│   ├── engine.py
│   ├── signals.py
│   ├── findings.py
├── modules/
├── models/
├── output/
├── utils/
├── config.py
```



# Design Principles

**Correlation over collection**
Raw data is not useful until it is connected.

**Signal over noise**
Findings must be meaningful, not overwhelming.

**Operator-first design**
Output should help thinking, not slow it down.

**Scope-aware by design**
Built for authorized environments only.

**Reporting as a feature**
Output is structured, readable, and actionable.



# Roadmap

## v0.2.0

* Passive + active discovery
* Signal-based analysis engine
* Service exposure detection
* Structured findings with impact
* JSON / CSV / HTML reporting
* CLI with verbosity control

## Next

* Expanded passive discovery (more sources)
* Full port scanning and deeper service mapping
* Graph-based asset visualization
* Continuous monitoring mode
* API support



# Legal / Authorized Use

Argus is intended for:

* authorized security assessments
* research and education
* defensive security analysis

You are responsible for ensuring usage is:

* within systems you own, or
* explicitly permitted

Unauthorized scanning may violate laws.



# License

MIT License



# Tagline

**Map what’s exposed. Prioritize what matters.**