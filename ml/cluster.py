"""
cluster.py  —  Member 3 (ML: clustering + anomaly scoring)

Group attackers into behaviour types and flag outliers.

Input : enriched.csv   (from enrichment/enrich.py)
Output: clusters.csv   (per-IP features + cluster label + anomaly score)

Suggested per-IP features:
  - number of connection attempts
  - number of distinct usernames / passwords tried
  - number of commands run
  - mean session duration
  - AbuseIPDB reputation score
  - distinct hassh fingerprints

Models:
  - KMeans or DBSCAN  -> cluster into types (scanner / brute-forcer / malware dropper)
  - IsolationForest   -> anomaly score per IP

Usage:
    python cluster.py --in enriched.csv --out clusters.csv

TODO (Member 3):
  - aggregate events to one row per src_ip (the feature table)
  - scale features (StandardScaler), fit the cluster model, label each IP
  - fit IsolationForest for an anomaly score
  - name the clusters by inspecting their centroids
"""
import argparse


def run(infile: str, outfile: str) -> None:
    # TODO: build per-IP feature table, cluster, score, save
    print(f"(stub) would cluster + score {infile} -> {outfile}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default="enriched.csv")
    ap.add_argument("--out", dest="outfile", default="clusters.csv")
    args = ap.parse_args()
    run(args.infile, args.outfile)
