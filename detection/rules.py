"""
rules.py  —  Member 2 (Detection + MITRE ATT&CK mapping)

Run detection rules over the enriched events and emit alerts, each tagged with
the MITRE ATT&CK technique it maps to.

Input : enriched.csv   (from enrichment/enrich.py)
Output: alerts.csv     (one row per fired alert)

Rules to implement (starting set):
  Brute force        -> many failed/attempted logins from one IP in a short window   (T1110)
  Known-bad IP       -> AbuseIPDB score above a threshold (e.g. >= 75)               (T1595)
  Suspicious command -> wget/curl, chmod +x, miner strings, base64 payloads          (T1059)
  Malware download   -> fetch of a binary into the shell                             (T1105)
  Root login         -> successful login as root                                     (T1078)

Usage:
    python rules.py --in enriched.csv --out alerts.csv

TODO (Member 2):
  - group events by src_ip / session
  - implement each rule as a small function returning alerts
  - attach severity (info/warning/critical) and the MITRE technique id
"""
import argparse

MITRE = {
    "brute_force": "T1110",
    "known_bad_ip": "T1595",
    "suspicious_command": "T1059",
    "malware_download": "T1105",
    "root_login": "T1078",
}

SUSPICIOUS = ("wget", "curl", "chmod +x", "base64", "/tmp/", "xmrig", "./")


def detect(infile: str, outfile: str) -> None:
    # TODO: load enriched.csv, apply rules, write alerts.csv
    print(f"(stub) would run detection on {infile} -> {outfile}")
    print("MITRE techniques covered:", ", ".join(sorted(set(MITRE.values()))))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default="enriched.csv")
    ap.add_argument("--out", dest="outfile", default="alerts.csv")
    args = ap.parse_args()
    detect(args.infile, args.outfile)
