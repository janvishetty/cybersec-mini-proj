"""
parse_cowrie.py — Cowrie JSON log -> clean events.csv
Member 1 (Capture & Ingestion)
Usage: python ingestion/parse_cowrie.py --in cowrie.json --out events.csv
"""
import argparse, json
import pandas as pd

KEEP = {
    "cowrie.session.connect", "cowrie.login.success", "cowrie.login.failed",
    "cowrie.command.input", "cowrie.session.closed", "cowrie.client.version",
    "cowrie.client.kex",
}

def parse(infile, outfile):
    rows, raw, bad = [], 0, 0
    with open(infile, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw += 1
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            eid = e.get("eventid")
            if eid not in KEEP:
                continue
            rows.append({
                "timestamp": e.get("timestamp"),
                "session":   e.get("session"),
                "src_ip":    e.get("src_ip"),
                "src_port":  e.get("src_port"),
                "eventid":   eid,
                "username":  e.get("username"),
                "password":  e.get("password"),
                "login_success": eid == "cowrie.login.success",
                "command":   e.get("input"),
                "duration":  e.get("duration"),
                "ssh_version": e.get("version"),
                "hassh":     e.get("hassh"),
            })
    df = pd.DataFrame(rows)
    # tidy types
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    # flag / drop our own localhost test traffic
    df["is_test"] = df["src_ip"].eq("127.0.0.1")
    real = df[~df["is_test"]].copy()
    real.to_csv(outfile, index=False)

    print(f"Raw lines read       : {raw}")
    print(f"Unparseable lines    : {bad}")
    print(f"Kept events (total)  : {len(df)}")
    print(f"Localhost test events: {int(df['is_test'].sum())}")
    print(f"Real events written  : {len(real)}  -> {outfile}")
    print(f"Unique attacker IPs  : {real['src_ip'].nunique()}")
    print(f"Login attempts       : {int(real['eventid'].isin(['cowrie.login.success','cowrie.login.failed']).sum())}")
    print(f"Commands run         : {int(real['eventid'].eq('cowrie.command.input').sum())}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",  dest="infile",  default="cowrie.json")
    ap.add_argument("--out", dest="outfile", default="events.csv")
    a = ap.parse_args()
    parse(a.infile, a.outfile)
