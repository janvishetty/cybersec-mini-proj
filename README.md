# Honeypot + Blue-Team Detection Engine

A live SSH honeypot that captures real internet attacks, feeding a custom
detection pipeline that parses, enriches, scores, and visualises them — mapped
to the MITRE ATT&CK framework.

Group security project. The honeypot runs on a public cloud VM and
is attacked by real bots within minutes of going live; everything downstream
runs on the captured data, so the detection side can be developed and tested
safely offline.

---

## Architecture

```
Internet attackers (bots worldwide)
        │  (hit port 22)
        ▼
Cowrie SSH honeypot  ──► Cowrie JSON logs ──► Log parser
 (decoy shell,                                     │
  Azure VM)                                        ▼
                                           Enrichment (GeoIP + AbuseIPDB)
                                                   │
                                                   ▼
                                     Detection rules + MITRE ATT&CK mapping
                                                   │
                                                   ▼
                                       ML anomaly scoring / clustering
                                                   │
                                                   ▼
                                   Dashboard (world map · timeline · alerts)
```

The honeypot is the only component exposed to the internet. Admin SSH is moved
to a non-standard port; port 22 is redirected to Cowrie so attackers reach the
decoy while the real machine stays separate.

---

## Repository layout

| Folder | Purpose | Owner |
| --- | --- | --- |
| `ingestion/` | Parse Cowrie JSON logs into clean, structured events | Member 1 |
| `enrichment/` | Add GeoIP location + AbuseIPDB reputation per source IP | Member 2 |
| `detection/` | Detection rules (brute force, bad IPs, suspicious commands) + MITRE mapping | Member 2 |
| `ml/` | Attacker clustering + anomaly scoring | Member 3 |
| `dashboard/` | Self-contained HTML dashboard (map, timeline, alerts, credentials) | Member 3 |
| `docs/` | Report, screenshots, notes | All |

---

## Setup

### 1. Honeypot (on the cloud VM)
- Ubuntu 24.04 VM, SSH key auth only.
- Admin SSH moved to a high port; port 22 redirected to Cowrie (port 2222) via iptables.
- Cowrie installed under a dedicated non-root `cowrie` user, logging JSON to
  `~/cowrie/var/log/cowrie/cowrie.json`.

### 2. Detection pipeline (local or on the VM)
```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Set your AbuseIPDB key as an environment variable (never commit it):
```bash
export ABUSEIPDB_API_KEY="your-key-here"
```

### 3. Run the pipeline
```bash
python ingestion/parse_cowrie.py   --in cowrie.json --out events.csv
python enrichment/enrich.py        --in events.csv  --out enriched.csv
python detection/rules.py          --in enriched.csv --out alerts.csv
python ml/cluster.py               --in enriched.csv --out clusters.csv
```

### 4. Dashboard
Open `dashboard/index.html` in a browser. Replace the placeholder `DATA`
object with real figures (or point it at a small API serving the pipeline
output).

---

## Deliverables
- [x] Live honeypot capturing real attacks
- [ ] Parser → structured events
- [ ] Enrichment (GeoIP + AbuseIPDB)
- [ ] Detection rules + MITRE mapping
- [ ] ML clustering / anomaly scoring
- [ ] Dashboard wired to live data
- [ ] Report with screenshots
- [ ] 7–8 min video (all members)

---

## Tech stack
Python · pandas · scikit-learn · Cowrie · iptables · Azure · HTML/SVG dashboard

## Safety note
This project deliberately exposes a decoy service to attract attackers. The
honeypot is a contained fake shell — captured payloads are stored for analysis
but never executed. No credentials, keys, or the private SSH key are committed
to this repository (see `.gitignore`).
