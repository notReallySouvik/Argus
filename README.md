# ARGUS

**Argus** is a reconnaissance and attack surface intelligence tool for authorized security testing.

It helps you **see what’s exposed on your domain and understand why it matters.**

> **Visibility before vulnerability.**



# What is Argus (in simple terms)

Give Argus a domain, and it will:

* find related subdomains
* check what’s running on them
* detect risky patterns
* explain what those risks mean

It doesn’t just list data —
it tells you **what could be a problem and why**.



# Quick Start (do this first)

Install:

```bash
git clone https://github.com/yourusername/argus.git
cd argus
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run your first scan:

```bash
argus scan example.com
```

That’s it.



# What you’ll see

After running a scan, Argus will:

### 1. Show results in terminal

* discovered assets (subdomains)
* detected technologies
* potential issues (findings)

### 2. Create a report folder

```
reports/
├── findings.json   # structured data
├── assets.csv     # asset list
└── report.html    # readable report
```

Open `report.html` in your browser — this is the easiest way to understand results.



# Example (what Argus actually finds)

You might see things like:

* `admin.example.com` → possible admin interface
* HTTP only → no HTTPS protection
* login panel exposed → authentication surface
* database service exposed → direct data access risk

And instead of just flagging it, Argus tells you:

* what it likely means
* how it could affect your system
* what to review



# Basic Usage

### Scan a domain

```bash
argus scan example.com
```

### Save reports to a custom folder

```bash
argus scan example.com --output reports
```

### Enable more detailed output

```bash
argus scan example.com --verbose
```

### Debug mode (for development)

```bash
argus scan example.com --debug
```

### Show version

```bash
argus --version
```



# What Argus Actually Does (under the hood)

If you’re curious:

## Discovery

* finds subdomains (wordlist + passive sources)
* resolves DNS → gets IPs
* tracks how each asset was discovered

## Enumeration

* checks HTTP/HTTPS availability
* follows redirects
* extracts page titles and headers
* fingerprints technologies (nginx, cloudflare, react, etc.)

## Service Mapping

* detects open services (like SSH, database, web)
* classifies them (web, admin, database, plaintext)

## Analysis (Signals → Findings)

Argus looks for patterns like:

* admin or dev environments exposed
* login panels or admin interfaces
* HTTP without HTTPS
* default pages or misconfigurations
* server/technology leaks

Then converts them into **findings with explanations**.



# What makes Argus different

Most tools:

* dump data

Argus:

* connects data
* highlights what matters
* explains risk in plain language



# Example Signals

Argus detects patterns such as:

```
admin_keyword
non_production_keyword
login_panel
admin_panel
exposed_http_only
default_page_detected
technology_disclosure
database_service_exposed
```

Each becomes a **structured finding with context and impact**.



# When to use Argus

* reviewing your own projects
* red team / recon workflows
* understanding external exposure
* quick attack surface mapping



# Important: Authorized Use Only

Only use Argus on:

* systems you own, or
* systems you have permission to test

Unauthorized scanning may be illegal.



# Project Structure (for contributors)

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



# Roadmap

### v0.2.0 (current)

* passive + active discovery
* signal-based analysis
* service exposure detection
* structured findings with impact
* JSON / CSV / HTML reports

### Next

* better passive discovery
* deeper port/service mapping
* graph visualization
* continuous monitoring
* API support



# License

MIT License



# Tagline

**Map what’s exposed. Prioritize what matters.**