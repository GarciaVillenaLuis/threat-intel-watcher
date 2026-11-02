# Threat Intel Watcher 📡

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/threat-intel-watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/threat-intel-watcher/actions/workflows/ci.yml)
[![Telemetry Status](https://img.shields.io/badge/Telemetry-Active%20%26%20Syncing-success?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/GarciaVillenaLuis/threat-intel-watcher)
[![Catalog Source](https://img.shields.io/badge/Source-CISA%20KEV%20Catalog-0052cc?style=flat-square&logo=securityscorecard&logoColor=white)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
[![Security Standard](https://img.shields.io/badge/Security-NIST%20CSF%20%7C%20MITRE%20ATT%26CK-orange?style=flat-square)](https://csrc.nist.gov/)

Autonomous threat intelligence pipeline and command-line engine tracking the **CISA Known Exploited Vulnerabilities (KEV)** catalog and correlating emerging zero-day and n-day CVE exploits across enterprise multi-cloud workloads.

Developed and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🌟 Key Capabilities

- **Real-Time KEV Feed Ingestion**: Connects directly to CISA's official vulnerability catalog, parsing active threats with automated schema validation.
- **Advanced CLI Filtration**: Query by CVE identifier, impacted vendor, specific product, or filter strictly for vulnerabilities weaponized in known ransomware campaigns.
- **Offline & Fallback Resilience**: Seamless fallback to local repository telemetry snapshots when running in air-gapped or restricted network segments.
- **Multi-Format Reporting**: Generates clean ASCII terminal tables, machine-readable JSON, or CSV records for ingestion into SIEM/SOAR platforms (Splunk, Microsoft Sentinel).
- **Automated State Tracking**: Validates daily synchronization snapshots with cryptographic SHA-256 signatures in [`data/cisa_kev_telemetry.json`](./data/cisa_kev_telemetry.json).

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (Standard Library only — zero external pip dependencies required)

### Syntax & Available Options

```bash
python cisa_watcher.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--cve CVE_ID` | `string` | Query specific CVE identifier (e.g. `CVE-2024-3400`) |
| `--vendor NAME` | `string` | Case-insensitive filter by vendor (e.g. `Cisco`, `Ivanti`, `Microsoft`) |
| `--product NAME` | `string` | Case-insensitive filter by product (e.g. `PAN-OS`, `Connect Secure`) |
| `--ransomware` | `flag` | Filter exclusively for vulnerabilities leveraged in ransomware campaigns |
| `--days N` | `integer`| Vulnerabilities added to KEV catalog in the last $N$ days |
| `--stats` | `flag` | Display catalog distribution statistics and top exploited vendors |
| `--format FMT` | `choice` | Output format: `table` (default), `json`, or `csv` |
| `--output FILE` | `string` | Save output to specified file path |
| `--input-file FILE` | `string` | Path to custom/offline JSON catalog instead of live HTTPS fetch |

---

## 💻 Usage Examples

### 1. Query a specific critical vulnerability
```bash
python cisa_watcher.py --cve CVE-2024-3400
```
**Sample Output:**
```text
+---------------+---------------------+--------+------------+------------+------------+
| CVE ID        | Vendor              | Product| Ransomware | Date Added | Due Date   |
+---------------+---------------------+--------+------------+------------+------------+
| CVE-2024-3400 | Palo Alto Networks  | PAN-OS | Known      | 2024-04-12 | 2024-04-19 |
+---------------+---------------------+--------+------------+------------+------------+
Total Matches: 1 | Catalog Source: https://www.cisa.gov/...
```

### 2. Search for ransomware-linked vulnerabilities in Microsoft products
```bash
python cisa_watcher.py --vendor Microsoft --ransomware --format table
```

### 3. Display threat intelligence telemetry & vendor distribution
```bash
python cisa_watcher.py --stats
```
**Sample Output:**
```text
===========================================================
   CISA KEV CATALOG - THREAT INTELLIGENCE METRICS
===========================================================
Total Tracked Vulnerabilities: 1766
Ransomware Campaign Linked:    313 (17.72%)
-----------------------------------------------------------
Top Affected Vendors in KEV:
  - Microsoft                : 288 CVEs
  - Cisco                    : 142 CVEs
  - Apple                    : 79 CVEs
  - Google                   : 75 CVEs
  - Adobe                    : 53 CVEs
===========================================================
```

### 4. Export critical threat intel to JSON for SIEM ingestion
```bash
python cisa_watcher.py --days 30 --ransomware --format json -o latest_threats.json
```

---

## 🧪 Unit Testing

Run the included test suite using standard Python `unittest`:

```bash
python -m unittest tests/test_cisa_watcher.py
```

---

## 🛡️ Telemetry Snapshot

Daily telemetry digests are automatically published in:
- [`data/cisa_kev_telemetry.json`](./data/cisa_kev_telemetry.json)

Verified against MITRE ATT&CK Enterprise Matrix and CISA Binding Operational Directive (BOD) 22-01.
