<<<<<<< HEAD
# ARGUS

Argus is an attack surface intelligence engine for authorized security reconnaissance.

It performs domain discovery, asset enumeration, technology fingerprinting, and exposure analysis, producing structured reports that help operators understand an organization’s external footprint.

## Features

- Domain intelligence
- Subdomain discovery
- Web service probing
- Technology fingerprinting
- Risk signal detection
- JSON, CSV, and HTML reporting

## Installation

```bash
git clone https://github.com/YOURUSERNAME/argus
cd argus
python -m venv .venv
source .venv/bin/activate
pip install -e .
=======
# ARGUS

**Argus** is an offensive reconnaissance and attack surface intelligence engine for authorized red team operations.

It performs passive and active recon to discover, correlate, and score externally exposed assets across an organization’s internet-facing footprint.

Built on the principle:

> **Visibility before vulnerability.**

---

## What Argus Does

Argus is not just a scanner.

It collects signals from multiple recon layers and turns them into **structured, actionable intelligence**.

- Discovers subdomains and assets
- Resolves infrastructure and services
- Probes web surfaces
- Fingerprints technologies
- Detects exposure patterns (signals)
- Converts signals into structured findings
- Exports clean reports for analysis and reporting

## Core Capabilities

### Discovery
- Domain normalization and validation
- Subdomain candidate generation
- DNS resolution

### Enumeration
- HTTP/HTTPS probing
- Redirect detection
- Web metadata extraction
- Technology fingerprinting

### Analysis
- Hostname-based signals (admin, dev, backup, internal, legacy)
- Transport signals (HTTP-only exposure, redirects)
- Web signals (login panels, admin panels, default pages, errors)
- Disclosure signals (server banners, frameworks, CDN)

### Output
- Structured findings
- JSON export
- CSV export
- HTML report


## Installation

```bash
git clone https://github.com/yourusername/argus.git
cd argus
python -m venv .venv
source .venv/bin/activate
pip install -e .
````


## Usage

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


## Output

Argus generates structured outputs:

```
reports/
├── findings.json
├── assets.csv
└── report.html
```

### Terminal Output

* Discovered assets table
* Findings table (severity-based)
* Scan summary
* Output file paths


## Example Signals

Argus detects patterns such as:

* `admin_keyword`
* `non_production_keyword`
* `backup_keyword`
* `internal_keyword`
* `legacy_keyword`
* `login_panel`
* `admin_panel`
* `exposed_http_only`
* `directory_listing_possible`
* `default_page_detected`
* `unexpected_server_banner`
* `technology_disclosure`
* `cdn_detected`

Each signal is converted into a **structured finding** with:

* severity
* description
* confidence
* recommendation


## Project Structure

```
argus/
├── cli.py
├── core/
├── modules/
├── models/
├── output/
├── utils/
├── config.py
```


## Design Principles

* **Correlation over collection**
  Data is connected, not just gathered.

* **Signal over noise**
  Focus on meaningful exposure, not raw volume.

* **Operator-first design**
  Output is built for humans, not just machines.

* **Scope-aware by design**
  Intended for authorized environments only.

* **Reporting as a feature**
  Output is structured, shareable, and usable.


## Roadmap

### v0.1 (current)

* CLI scanning
* Core recon pipeline
* Signal detection
* Structured findings
* JSON / CSV / HTML output

### Next

* Better subdomain discovery
* Port/service mapping
* Graph-based asset visualization
* Continuous monitoring mode
* API support


## Legal / Authorized Use

Argus is intended for:

* authorized security assessments
* research and educational use
* defensive security analysis

You are responsible for ensuring that all usage is:

* within systems you own, or
* explicitly permitted by the target owner

Unauthorized scanning may violate laws and regulations.

## License

MIT License

## Tagline

**Map what’s exposed. Prioritize what matters.**
>>>>>>> 3b6ed7f (release: argus v0.1.0 mvp)
