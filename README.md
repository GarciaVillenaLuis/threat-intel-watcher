# Threat Intel Watcher 📡

Autonomous cloud security pipeline tracking the **CISA Known Exploited Vulnerabilities (KEV)** catalog and emerging CVE exploits in enterprise environments.

## Features
- **Real-Time KEV Feed Ingestion**: Ingests and parses active vulnerability intelligence from official security feeds.
- **Automated State Tracking**: Generates telemetry snapshots with cryptographic verification.
- **Enterprise Risk Context**: Correlates CVE identifiers with actionable remediation windows and MITRE ATT&CK techniques.

## Telemetry
Daily synchronization data is published in [`data/cisa_kev_telemetry.json`](./data/cisa_kev_telemetry.json).
