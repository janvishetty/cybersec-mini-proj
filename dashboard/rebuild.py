#!/usr/bin/env python3
"""
rebuild.py  —  regenerate dashboard/fulldata.json from the pipeline CSVs.

Run this after the pipeline (parse -> enrich -> detect -> cluster) has produced
its CSVs. The live dashboard polls fulldata.json every 2.5s, so each time you
run this the dashboard refreshes on its own — no manual reload.

Inputs (looked up in --dir, default: current folder):
    enriched.csv   event-level rows with geo + reputation (from enrich.py)
    alerts.csv     one row per fired alert                 (from rules.py)
    clusters.csv   per-IP behaviour + anomaly score        (from cluster.py)

Output:
    fulldata.json  (next to this script, or --out)

Usage:
    python3 rebuild.py                      # read CSVs here, write ./fulldata.json
    python3 rebuild.py --dir ../data        # CSVs live elsewhere
    watch -n 5 python3 rebuild.py           # keep regenerating every 5s (live demo)
"""
import argparse, json, os, sys
from datetime import datetime, timezone

try:
    import pandas as pd
except ImportError:
    sys.exit("pandas is required:  pip install pandas")

# rule id -> MITRE technique (id, human name)
MITRE = {
    "brute_force":        ("T1110", "Brute Force"),
    "known_bad_ip":       ("T1595", "Active Scanning"),
    "suspicious_command": ("T1059", "Command and Scripting Interpreter"),
    "malware_download":   ("T1105", "Ingress Tool Transfer"),
    "root_login":         ("T1078", "Valid Accounts"),
    "recon_command":      ("T1082", "System Information Discovery"),
}
SEV_RANK = {"critical": 0, "warning": 1, "info": 2}


def col(df, *names):
    """Return the first matching column name (case-insensitive), or None."""
    low = {c.lower(): c for c in df.columns}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return None


def load(path):
    if not os.path.exists(path):
        return None
    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"  ! could not read {os.path.basename(path)}: {e}")
        return None


def build(d):
    enr = load(os.path.join(d, "enriched.csv"))
    if enr is None:
        enr = load(os.path.join(d, "events.csv"))   # fallback: no enrichment yet
    alr = load(os.path.join(d, "alerts.csv"))
    clu = load(os.path.join(d, "clusters.csv"))
    if enr is None:
        sys.exit("No enriched.csv or events.csv found — run the pipeline first.")

    ip_c   = col(enr, "src_ip", "ip", "source_ip")
    ev_c   = col(enr, "eventid", "event", "event_type", "type")
    user_c = col(enr, "username", "user")
    pass_c = col(enr, "password", "pass")
    cmd_c  = col(enr, "input", "command", "cmd")
    ts_c   = col(enr, "timestamp", "time", "ts", "@timestamp")
    ctry_c = col(enr, "country")

    is_connect = enr[ev_c].astype(str).str.contains("connect", case=False, na=False) if ev_c else None
    is_login   = enr[ev_c].astype(str).str.contains("login",   case=False, na=False) if ev_c else None

    # ---- totals ----
    attacks = int(is_connect.sum()) if is_connect is not None and is_connect.any() else int(len(enr))
    logins  = int(is_login.sum())   if is_login   is not None and is_login.any()   else 0
    ips     = int(enr[ip_c].nunique()) if ip_c else 0
    countries_n = int(enr[ctry_c].nunique()) if ctry_c else 0
    anomalies = 0
    if clu is not None:
        an_c = col(clu, "is_anomaly", "anomaly")
        if an_c is not None:
            anomalies = int(pd.to_numeric(clu[an_c], errors="coerce").fillna(0).astype(bool).sum())

    # ---- attackers (one row per IP: geo from enriched + behaviour from clusters) ----
    attackers = []
    if ip_c:
        # first geo row per IP
        geo_cols = {k: col(enr, k) for k in
                    ("country", "country_code", "city", "lat", "lon", "isp",
                     "abuse_score", "total_reports")}
        first = enr.drop_duplicates(subset=[ip_c]).set_index(ip_c)
        # per-IP counts from enriched
        conn = enr.groupby(ip_c).size()
        logn = enr[is_login].groupby(enr[ip_c]).size() if is_login is not None else None
        cmdn = (enr[enr[cmd_c].notna()].groupby(ip_c).size() if cmd_c else None)
        clu_i = clu.set_index(col(clu, "src_ip", "ip")) if clu is not None and col(clu, "src_ip", "ip") else None

        for ip in enr[ip_c].dropna().unique():
            r = first.loc[ip] if ip in first.index else None
            def gv(key, default=""):
                c = geo_cols.get(key)
                if c and r is not None and c in first.columns:
                    v = r[c]
                    return v if pd.notna(v) else default
                return default
            a = {
                "src_ip": str(ip),
                "country": gv("country"), "country_code": gv("country_code"),
                "city": gv("city"),
                "lat": float(gv("lat", 0) or 0), "lon": float(gv("lon", 0) or 0),
                "isp": gv("isp"),
                "abuse_score": int(float(gv("abuse_score", 0) or 0)),
                "total_reports": int(float(gv("total_reports", 0) or 0)),
                "n_connections": int(conn.get(ip, 0)),
                "n_logins": int(logn.get(ip, 0)) if logn is not None else 0,
                "n_commands": int(cmdn.get(ip, 0)) if cmdn is not None else 0,
                "n_sessions": int(conn.get(ip, 0)),
                "cluster_name": "", "anomaly_score": 0.0, "is_anomaly": False,
            }
            if clu_i is not None and ip in clu_i.index:
                cr = clu_i.loc[ip]
                cn = col(clu, "cluster_name", "cluster")
                asc = col(clu, "anomaly_score", "score")
                anc = col(clu, "is_anomaly", "anomaly")
                for k, srccol in (("cluster_name", cn), ("n_sessions", col(clu, "n_sessions"))):
                    if srccol and srccol in clu.columns and pd.notna(cr[srccol]):
                        a[k] = cr[srccol] if k == "cluster_name" else int(cr[srccol])
                if asc and pd.notna(cr[asc]): a["anomaly_score"] = round(float(cr[asc]), 3)
                if anc and pd.notna(cr[anc]): a["is_anomaly"] = bool(float(cr[anc]) if str(cr[anc]).replace('.','').replace('-','').isdigit() else cr[anc])
            attackers.append(a)
        attackers.sort(key=lambda x: -x["n_connections"])

    # ---- alerts (latest ~14) + severity + mitre counts ----
    alerts, severity, mitre_counts = [], {"info": 0, "warning": 0, "critical": 0}, {}
    if alr is not None and len(alr):
        a_ip  = col(alr, "src_ip", "ip")
        a_sev = col(alr, "severity", "sev")
        a_rule= col(alr, "rule", "name")
        a_mit = col(alr, "mitre", "technique", "tag")
        a_det = col(alr, "detail", "message", "desc")
        a_ts  = col(alr, "timestamp", "time", "ts")
        if a_sev:
            for s, c in alr[a_sev].astype(str).str.lower().value_counts().items():
                if s in severity: severity[s] = int(c)
        if a_mit:
            for m, c in alr[a_mit].astype(str).value_counts().items():
                mitre_counts[m] = int(c)
        rows = alr.copy()
        if a_ts: rows = rows.sort_values(a_ts, ascending=False)
        for _, rr in rows.head(14).iterrows():
            rule = str(rr[a_rule]) if a_rule else ""
            mid, mname = MITRE.get(rule, (str(rr[a_mit]) if a_mit else "", ""))
            t = str(rr[a_ts]) if a_ts else ""
            alerts.append({
                "sev": (str(rr[a_sev]).lower() if a_sev else "info"),
                "rule": rule, "mitre": mid, "mitre_name": mname,
                "ip": str(rr[a_ip]) if a_ip else "",
                "detail": str(rr[a_det]) if a_det else "",
                "time": t[5:16] if len(t) >= 16 else t,
            })

    # ---- mitre table (named, sorted) ----
    mitre = []
    name_by_id = {v[0]: v[1] for v in MITRE.values()}
    for mid, cnt in sorted(mitre_counts.items(), key=lambda kv: -kv[1]):
        mitre.append({"id": mid, "name": name_by_id.get(mid, ""), "count": cnt})

    # ---- top countries ----
    countries = []
    if ctry_c:
        for name, n in enr[ctry_c].dropna().value_counts().items():
            countries.append({"name": str(name), "n": int(n)})

    # ---- timeline (hourly buckets) ----
    timeline = []
    if ts_c:
        tt = pd.to_datetime(enr[ts_c], errors="coerce", utc=True).dropna()
        if len(tt):
            try:
                floored = tt.dt.floor("h")      # pandas >= 2.2
            except ValueError:
                floored = tt.dt.floor("H")      # older pandas
            by_hour = floored.value_counts().sort_index()
            timeline = [{"t": str(ts), "n": int(n)} for ts, n in by_hour.items()]

    # ---- top credentials ----
    creds = []
    if user_c and pass_c:
        lp = enr
        if is_login is not None and is_login.any(): lp = enr[is_login]
        pair = lp.groupby([user_c, pass_c]).size().sort_values(ascending=False).head(10)
        for (u, p), n in pair.items():
            creds.append({"u": str(u), "p": str(p), "n": int(n)})

    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "totals": {"attacks": attacks, "ips": ips, "logins": logins,
                   "alerts": int(len(alr)) if alr is not None else len(alerts),
                   "countries": countries_n, "anomalies": anomalies},
        "attackers": attackers, "alerts": alerts, "creds": creds,
        "timeline": timeline, "countries": countries,
        "severity": severity, "mitre": mitre,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".", help="folder holding the pipeline CSVs")
    ap.add_argument("--out", default=None, help="output path (default: <script dir>/fulldata.json)")
    args = ap.parse_args()
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "fulldata.json")
    data = build(args.dir)
    with open(out, "w") as f:
        json.dump(data, f, indent=0)
    t = data["totals"]
    print(f"✓ wrote {out}")
    print(f"  {t['attacks']} attacks · {t['ips']} IPs · {t['countries']} countries · "
          f"{t['alerts']} alerts · {t['anomalies']} anomalies · {len(data['attackers'])} attackers")
