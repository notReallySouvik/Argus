# ARGUS

**Argus** is a reconnaissance and attack surface intelligence tool for authorized security testing.

It helps you **see what’s exposed on your domain and understand why it matters.**

> **Visibility before vulnerability.**


# What is Argus (in simple terms)

Give Argus a domain, and it will:

* find related subdomains
* check what’s running on them
* detect risky patterns
* connect those patterns together
* explain what they mean and why they matter

It doesn’t just list data —
it tells you **what could be a problem, why it exists, and how it could be abused.**


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

## 1. Show results in terminal

* discovered assets (subdomains)
* detected technologies and services
* potential issues (findings)
* correlated findings (higher-confidence risks)

## 2. Create a report folder

```
reports/
├── findings.json   # structured data
├── assets.csv      # asset inventory
└── report.html     # readable report
```

Open `report.html` in your browser — this is the easiest way to understand results.


# Example (what Argus actually finds)

You might see things like:

* `admin.example.com` → admin interface exposed
* HTTP only → no HTTPS protection
* login panel exposed → authentication surface
* database service exposed → direct data access risk

But more importantly, Argus connects signals:

* admin + admin panel → **privileged interface exposed**
* login + HTTP only → **weakly protected entry point**
* internal + database → **internal data service exposed**

And explains:

* what it likely means
* how it can impact your system
* what you should review


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

## Discovery

* finds subdomains (wordlist + passive sources)
* resolves DNS → gets IPs
* tracks discovery source and confidence

## Enumeration

* checks HTTP/HTTPS availability
* detects redirects
* extracts page titles and headers
* fingerprints technologies (nginx, cloudflare, react, etc.)

## Service Mapping

* detects exposed services (SSH, database, web, etc.)
* classifies them (web, admin, database, plaintext)


## Analysis (Signals → Intelligence)

Argus works in layers:

### 1. Signals (raw patterns)

* admin / dev / internal naming
* login panels, admin panels
* HTTP-only exposure
* default pages, error pages
* technology and server disclosure


### 2. Correlation Engine (core upgrade)

Argus combines multiple weak signals into stronger conclusions:

* admin + admin panel → **privileged interface exposed**
* login + HTTP → **weak entry point**
* internal + database → **internal data service exposed**

This is where raw data becomes **meaningful insight**.


### 3. Context Awareness

Each asset is described as:

> what it is
> what it exposes
> why it matters

Argus assigns:

* **context tags** (admin-surface, entry-point, data-service, etc.)
* **exposure summary** (human-readable explanation)
* **relationships** (host → service → technology → exposure)


### 4. Findings Engine

Each signal (and correlated signal) becomes a structured finding:

* **What it means (cause)**
* **How it can impact the system**
* **Where it appears**
* **Confidence level**
* **What to review next**


# Output (what makes Argus useful)

## HTML Report

* asset overview with context
* services and technologies
* signals and relationships
* correlated findings (high value)
* base findings (raw signals)

## JSON

* full structured data
* includes context, relationships, signals, findings

## CSV

* flattened asset inventory
* useful for quick filtering and analysis


# What makes Argus different

Most tools:

* collect data

Argus:

* connects data
* explains meaning
* prioritizes risk
* gives context

> Weak signals → Strong conclusions


# Example Signals

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

### Correlated Signals (new)

```
privileged_interface_exposed
public_remote_admin_surface
internal_data_service_exposed
weakly_protected_entry_point
high_value_target_surface
```


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
│   ├── correlation.py
│   ├── context.py
│   ├── findings.py
├── modules/
├── models/
├── output/
├── utils/
├── config.py
```


# Roadmap

## v0.2.1 (current)

* correlation engine
* context-aware asset modeling
* correlated findings (higher-order risk)
* relationship-aware reporting
* improved HTML output

## Next

* better passive discovery
* deeper port/service mapping
* graph-based visualization
* continuous monitoring mode
* API support


# License

MIT License


# Tagline

**Map what’s exposed. Prioritize what matters.**