# 🧠 TODO — CVE Aggregation & Processing Framework

## 🏗️ Core Setup

* [ ] Establish proper **project structure**

  * [ ] `src/` for core logic
  * [ ] `parsers/` for custom source parsers
  * [ ] `io/` for input/output format handlers
  * [ ] `utils/` for shared helpers
  * [ ] `tests/` for unit testing
* [ ] Replace `argparse` with faster CLI parsing (e.g. **`typer`**, **`click`**, or **`argparse + caching`**)
* [ ] Implement **auto-help message** when no arguments are passed
* [ ] Setup `venv` and lock dependencies (`requirements.txt` or `pyproject.toml`)
* [ ] Add a script or Makefile target to **auto-detect and update dependencies**

---

## 🧩 Input Formats

> Sources that define *what to fetch or process.*

* [x] XLSX (current working version)
* [ ] JSON
* [ ] CSV
* [ ] Plain text
* [ ] XLS (legacy Excel)
* [ ] YAML (for config-based runs)

---

## 📤 Output Formats

> Ways to export normalized and processed CVE data.

* [x] XLSX
* [ ] JSON
* [ ] CSV
* [ ] Plain text
* [ ] XLS (legacy Excel)
* [ ] XML
* [ ] HTML (for readable reports)
* [ ] SQLite (for caching / local DB use)

---

## 🌐 Data Sources

> Fetch CVE and remediation data from multiple external feeds.

### 🧱 Phase 1 — Core Feeds

* [ ] NVD
* [ ] Red Hat
* [ ] OSV (Open Source Vulnerabilities)

### 🏢 Phase 2 — Extended Feeds

* [ ] CVE.org (MITRE)
* [ ] GitHub Security Advisories (GHSA)
* [ ] Microsoft Security Response Center (MSRC)
* [ ] Cisco Security Advisories
* [ ] Debian / Ubuntu trackers

### 🧩 Future — Custom Sources

* [ ] Add support for **user-defined sources** (URL + parser module)
* [ ] Define parser plugin interface (e.g., `parse(data) -> list[dict]`)
* [ ] Dynamic loading with importlib

---

## 🧠 Processing & Normalization

> Transform raw feed data into a consistent internal structure.

* [ ] Design unified **CVE schema** (ID, severity, CVSS, vendor, product, description, references, etc.)
* [ ] Implement **normalization layer** to map external fields → internal schema
* [ ] Add **deduplication** logic (CVE IDs across multiple feeds)
* [ ] Add **cross-referencing** (e.g., CVE <-> CPE <-> vendor advisory)
* [ ] Implement **delta detection** (track new or updated CVEs since last run)
* [ ] Add **remediation enrichment** (fetch patch info, references, etc.)

---

## 🔧 Core Features

* [ ] Configurable **logging and verbosity**
* [ ] Configurable **rate limiting / retry** per source
* [ ] **Parallel fetcher** for multi-source performance
* [ ] CLI flags for filtering (vendor, severity, etc.)
* [ ] Config file (`config.yaml`) for default options
* [ ] Tests for all key modules

---

## ☁️ Service Mode (Later Stage)

> When evolving from CLI → service / API.

* [ ] Add **database connection layer** (PostgreSQL or SQLite fallback)
* [ ] Store fetched CVE data and history
* [ ] Build **REST API endpoints**

  * [ ] `/fetch` → trigger updates
  * [ ] `/query` → retrieve processed data
  * [ ] `/status` → monitor jobs
* [ ] Add simple **web UI** for viewing results

---

## 🧾 Misc / Quality of Life

* [ ] Add README with license + contribution guidelines
* [ ] Add unit tests and CI pipeline
* [ ] Add release workflow (versioning, changelog)
