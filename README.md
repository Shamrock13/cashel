# 🔥 Flintlock

**Flintlock** is a firewall configuration auditing tool with a web UI and CLI. It detects common security misconfigurations, generates scored severity reports, compares configs across time, and connects directly to live devices via SSH. Deployable in minutes via Docker Compose.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Flintlock-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Supported Vendors

| Vendor | Config Format | Status |
|---|---|---|
| Cisco ASA | Text | ✅ Supported |
| Palo Alto Networks | XML | ✅ Supported |
| Fortinet | Text | ✅ Supported |
| pfSense | XML | ✅ Supported |
| AWS Security Groups | JSON | ✅ Supported |
| Azure NSG | JSON | ✅ Supported |

---

## Features

### Free (Open Source)
- **Web UI** — browser-based interface, no terminal required
- **Auto-detect vendor** — Flintlock identifies the vendor from file content automatically
- **Live SSH connection** — connect directly to a Cisco ASA, Fortinet, or Palo Alto device to pull and audit its running config in real time
- **Rule change diff** — upload two configs of the same vendor to see exactly what was added, removed, and unchanged
- **Audit History** — save audit results and browse them later with vendor filter, sort, and filename search
- **Archival reviews** — select any two saved audits and compare them: see resolved findings, new issues, and delta scores
- **Activity Log** — full record of every audit, SSH attempt, and config diff, including failures
- **PDF report export** — download a color-coded findings report
- Detect overly permissive any/any rules
- Detect permit rules missing logging
- Detect missing deny-all rule
- Detect redundant/shadowed rules
- Fortinet enhanced checks: disabled policies, all-service rules, insecure services (Telnet/HTTP/FTP), unnamed policies
- AWS: open ingress to 0.0.0.0/0, unrestricted port ranges
- Azure: inbound Any rules, overly permissive NSG rules
- Severity scoring (HIGH / MEDIUM)
- Clickable severity filters on results
- Light and dark mode (preference saved automatically)
- CLI output with audit summary
- Docker Compose deployment

### Paid (License Required)
- CIS Benchmark compliance checks
- PCI-DSS compliance checks
- NIST SP 800-41 compliance checks
- Specific control references (e.g. PCI Req 1.3, NIST AC-6)

> 💳 **Purchase a license at [Gumroad](https://shamrock13.gumroad.com/l/flintlock)**

---

## Installation

### Option 1 — Docker Compose (Recommended)

The fastest way to get Flintlock running. No Python environment setup required.

**Requirements:** Docker Desktop or OrbStack

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
docker compose up --build
```

Open **http://localhost:8080** in your browser.

Uploaded reports, audit history, activity log, and your license key are all persisted in a Docker volume across restarts. To set a custom secret, create a `.env` file in the project root:

```
FWAUDIT_SECRET=your-secret-here
```

To stop:
```bash
docker compose down
```

---

### Option 2 — Local Python

**Requirements:** Python 3.8+, and `paramiko` for live SSH support

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
pip install -r requirements.txt
```

**Run the web UI:**
```bash
PYTHONPATH=src python -m flask --app src/flintlock/web.py run
```
Open **http://localhost:5000**

**Run the CLI:**
```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa
```

---

## Web UI

The web interface provides the full feature set without needing a terminal. It is organized into five tabs.

### File Audit
1. Upload a firewall config file (text, XML, or JSON)
2. Select a vendor or leave on **Auto-detect**
3. Optionally select a compliance framework (license required)
4. Check **Generate PDF Report** and/or **Save to Audit History** as needed
5. Click **Run Audit**

Results are sorted high → medium. Click the summary boxes to filter by severity.

### Compare Configs
Upload two configs of the same vendor to see a line-by-line diff of what changed — rules added, removed, and unchanged. Auto-detects vendor from the baseline file.

### Live Connect
Connect directly to a device over SSH to pull and audit its running configuration without touching a file. Supported vendors: **Cisco ASA**, **Fortinet**, **Palo Alto Networks**.

- Credentials are used only for the single connection and are never stored
- Successful audits are automatically saved to Audit History
- Failed connections are recorded in the Activity Log only

### Audit History
Browse all saved audits. Filter by vendor, sort by date or issue count, and search by filename. Select any two entries and click **Compare Selected** to see a full diff of findings between the two audits — including resolved issues, new issues, and HIGH/MEDIUM/Total deltas. The older audit is always used as the baseline regardless of selection order.

### Activity Log
A complete record of every action taken in Flintlock — file audits, SSH connections, and config diffs — including failures. Shows action type, vendor, timestamp, and error message for failed attempts. Entries can be deleted individually or cleared in bulk.

---

## Roadmap

- [x] Web UI with file upload and inline results
- [x] Docker Compose deployment
- [x] Auto vendor detection
- [x] Clickable severity filters
- [x] Light / dark mode
- [x] PDF report redesign
- [x] Live SSH/API connection mode
- [x] Fortinet v2 checks
- [x] AWS Security Group support
- [x] Azure NSG support
- [x] Rule change diff (compare two configs)
- [x] Activity Log (usage monitoring)
- [x] Archival reviews (compare historical configs)
- [ ] Archival review trends & scoring graphs
- [ ] Scheduled audits
- [ ] Multi-device bulk audit

---

## Support the Project

Flintlock is free and open source. If it's saved you time or caught something in your configs, consider buying me a coffee — it goes directly toward keeping this maintained and adding new features.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white&style=for-the-badge)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Buy%20me%20a%20coffee-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white&style=for-the-badge)](https://ko-fi.com/shamrock13)

---

## License

The core tool is open source under the MIT License. The compliance module requires a paid license key.

---

## Author

Built by a network security engineer for network security engineers.
