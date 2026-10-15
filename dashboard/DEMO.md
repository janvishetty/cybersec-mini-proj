# Live Dashboard Demo

The dashboard reads `fulldata.json` and **re-checks it every 2.5 seconds**, so when
you re-run the pipeline the map, KPIs, alerts and anomalies update on screen on
their own — no manual refresh. A **● LIVE** badge (top-right) pulses on each update.

## Files
- `index.html`   — the live dashboard (polls `fulldata.json`)
- `fulldata.json`— the data it shows (ships with the real captured data)
- `rebuild.py`   — regenerates `fulldata.json` from the pipeline CSVs

## One-time: serve the folder
The dashboard uses `fetch()`, which browsers block on `file://`. Serve it over HTTP:

```bash
cd <this folder>
python3 -m http.server 8000
```
Open **http://localhost:8000** in your browser. You should see the data and the LIVE badge.

> Opening `index.html` by double-click will show "Could not load fulldata.json" —
> that's expected; use the `http.server` command above.

## The live demo (what to record for the video)
Open **two terminals**.

**Terminal 1 — keep the dashboard served:**
```bash
python3 -m http.server 8000
```

**Terminal 2 — run the pipeline, then rebuild the data:**
```bash
# 1. run your pipeline so the CSVs are fresh
python ingestion/parse_cowrie.py
python enrichment/enrich.py
python detection/rules.py
python ml/cluster.py

# 2. regenerate the dashboard data (CSVs are read from --dir)
python3 rebuild.py --dir .
```
The moment `rebuild.py` finishes, watch the browser — the numbers jump and the
LIVE badge pulses. That's requirement 2 ("explore and demonstrate all
functionalities") shown end to end, live.

### Want it to look continuously live?
Re-run the rebuild on a loop while you talk:
```bash
watch -n 5 'python3 rebuild.py --dir .'
```

## rebuild.py inputs
Reads these from `--dir` (default: current folder):
- `enriched.csv` — events + GeoIP + AbuseIPDB (from `enrich.py`)
- `alerts.csv`   — fired alerts + MITRE technique (from `rules.py`)
- `clusters.csv` — per-IP behaviour + anomaly score (from `cluster.py`)

If your CSV column names differ slightly, `rebuild.py` auto-detects common
variants (e.g. `src_ip`/`ip`, `eventid`/`event`, `input`/`command`). If a file
is missing it still writes a best-effort `fulldata.json` and tells you what it used.

## Deploying the live version (GitHub Pages)
`index.html` + `fulldata.json` work on GitHub Pages too (same-origin fetch is
allowed). Push both to the repo and enable Pages — the hosted dashboard shows
whatever `fulldata.json` you committed. (On Pages it refreshes only when you push
a new `fulldata.json`; true second-by-second live updating is the local
`http.server` setup above.)
