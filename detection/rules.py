"""
rules.py — detection rules over enriched events + MITRE ATT&CK mapping.
Member 2 (Detection)
Usage: python detection/rules.py --in enriched.csv --out alerts.csv
"""
import argparse
import pandas as pd

MITRE = {
    "brute_force":        ("T1110", "Brute Force"),
    "known_bad_ip":       ("T1595", "Active Scanning"),
    "suspicious_command": ("T1059", "Command and Scripting Interpreter"),
    "malware_download":   ("T1105", "Ingress Tool Transfer"),
    "root_login":         ("T1078", "Valid Accounts"),
    "recon_command":      ("T1082", "System Information Discovery"),
}

SUSPICIOUS = ("wget", "curl", "chmod +x", "chmod 777", "tftp", "base64 -d",
              "xmrig", "./", "/tmp/", "nohup", "crontab", "sh -c")
DOWNLOAD   = ("wget", "curl", "tftp", "ftpget")
RECON      = ("uname", "whoami", "cat /etc/passwd", "cat /proc/cpuinfo",
              "lscpu", "free -m", "ps aux", "id", "cat /etc/shadow")
BRUTE_THRESHOLD = 10   # login attempts from one IP -> brute force
ABUSE_THRESHOLD = 75   # AbuseIPDB score -> known-bad

def detect(infile, outfile):
    df = pd.read_csv(infile)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    alerts = []

    def add(sev, rule, ip, detail, ts):
        tid, tname = MITRE[rule]
        alerts.append({
            "severity": sev, "rule": rule, "mitre_id": tid, "mitre_name": tname,
            "src_ip": ip, "detail": detail, "timestamp": ts,
        })

    logins = df[df["eventid"].isin(["cowrie.login.success","cowrie.login.failed"])]
    cmds   = df[df["eventid"] == "cowrie.command.input"]

    # per-IP rules
    for ip, g in df.groupby("src_ip"):
        n_login = len(g[g["eventid"].isin(["cowrie.login.success","cowrie.login.failed"])])
        score   = g["abuse_score"].dropna().max() if "abuse_score" in g else None
        country = g["country"].dropna().iloc[0] if g["country"].notna().any() else "?"
        last_ts = g["timestamp"].max()

        if n_login >= BRUTE_THRESHOLD:
            add("critical", "brute_force", ip,
                f"{n_login} login attempts from {country}", last_ts)
        if score is not None and score >= ABUSE_THRESHOLD:
            add("warning", "known_bad_ip", ip,
                f"AbuseIPDB score {int(score)} ({country})", last_ts)

    # successful root logins
    root = df[(df["eventid"]=="cowrie.login.success") & (df["username"]=="root")]
    for _, r in root.iterrows():
        add("critical", "root_login", r["src_ip"],
            f"root / {r['password']}", r["timestamp"])

    # command-based rules
    for _, r in cmds.iterrows():
        c = str(r.get("command", "")).lower()
        if any(d in c for d in DOWNLOAD):
            add("critical", "malware_download", r["src_ip"], f"cmd: {r['command']}", r["timestamp"])
        elif any(s in c for s in SUSPICIOUS):
            add("warning", "suspicious_command", r["src_ip"], f"cmd: {r['command']}", r["timestamp"])
        elif any(k in c for k in RECON):
            add("info", "recon_command", r["src_ip"], f"cmd: {r['command']}", r["timestamp"])

    out = pd.DataFrame(alerts).sort_values("timestamp", ascending=False)
    out.to_csv(outfile, index=False)

    print(f"Total alerts: {len(out)}")
    print("\nBy severity:")
    print(out["severity"].value_counts().to_string())
    print("\nBy MITRE technique:")
    print(out.groupby(["mitre_id","mitre_name"]).size().sort_values(ascending=False).to_string())

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",  dest="infile",  default="enriched.csv")
    ap.add_argument("--out", dest="outfile", default="alerts.csv")
    a = ap.parse_args()
    detect(a.infile, a.outfile)
