"""
cluster.py — per-IP attacker clustering + anomaly scoring.
Member 3 (ML)
Usage: python ml/cluster.py --in enriched.csv --out clusters.csv
"""
import argparse
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

def build_features(df):
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    rows = []
    for ip, g in df.groupby("src_ip"):
        logins = g[g["eventid"].isin(["cowrie.login.success","cowrie.login.failed"])]
        cmds   = g[g["eventid"] == "cowrie.command.input"]
        conns  = g[g["eventid"] == "cowrie.session.connect"]
        span = (g["timestamp"].max() - g["timestamp"].min()).total_seconds()
        rows.append({
            "src_ip": ip,
            "n_connections": len(conns),
            "n_logins": len(logins),
            "n_distinct_users": logins["username"].nunique(),
            "n_distinct_pass": logins["password"].nunique(),
            "n_commands": len(cmds),
            "n_sessions": g["session"].nunique(),
            "abuse_score": g["abuse_score"].dropna().max() if g["abuse_score"].notna().any() else 0,
            "span_minutes": round(span/60, 1) if span and span > 0 else 0,
            "country": g["country"].dropna().iloc[0] if g["country"].notna().any() else "?",
        })
    return pd.DataFrame(rows)

def name_clusters(feat, labels):
    """Give each cluster a human label from its centroid behaviour."""
    feat = feat.copy(); feat["cluster"] = labels
    names = {}
    for c, g in feat.groupby("cluster"):
        cmds = g["n_commands"].mean(); logins = g["n_logins"].mean()
        if cmds > g["n_commands"].median() and cmds > 5:
            names[c] = "Interactive intruder (runs commands)"
        elif logins > 20:
            names[c] = "Brute-forcer (login flood)"
        else:
            names[c] = "Scanner / prober (light touch)"
    return names

def run(infile, outfile):
    df = pd.read_csv(infile)
    feat = build_features(df)
    print(f"Built feature table for {len(feat)} IPs")

    cols = ["n_connections","n_logins","n_distinct_users","n_distinct_pass",
            "n_commands","n_sessions","abuse_score","span_minutes"]
    X = StandardScaler().fit_transform(feat[cols].fillna(0))

    k = min(3, len(feat))
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    feat["cluster"] = km.fit_predict(X)
    feat["cluster_name"] = feat["cluster"].map(name_clusters(feat, feat["cluster"]))

    iso = IsolationForest(contamination=0.15, random_state=42)
    feat["anomaly"] = iso.fit_predict(X)              # -1 = anomaly
    feat["anomaly_score"] = (-iso.score_samples(X)).round(3)  # higher = more anomalous
    feat["is_anomaly"] = feat["anomaly"] == -1

    feat = feat.sort_values("anomaly_score", ascending=False)
    feat.drop(columns=["anomaly"]).to_csv(outfile, index=False)

    print("\nCluster sizes:")
    print(feat.groupby(["cluster","cluster_name"]).size().to_string())
    print("\nTop 5 most anomalous attackers:")
    print(feat.head(5)[["src_ip","country","n_logins","n_commands","abuse_score","anomaly_score"]].to_string(index=False))
    print(f"\nFlagged {int(feat['is_anomaly'].sum())} anomalies -> {outfile}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",  dest="infile",  default="enriched.csv")
    ap.add_argument("--out", dest="outfile", default="clusters.csv")
    a = ap.parse_args()
    run(a.infile, a.outfile)
