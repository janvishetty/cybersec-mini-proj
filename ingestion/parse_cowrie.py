"""
parse_cowrie.py  —  Member 1 (Capture & Ingestion)

Turn Cowrie's raw JSON event log into clean, structured events: one tidy
table the rest of the pipeline (enrichment, detection, ML, dashboard) reads.

Input : cowrie.json   (one JSON object per line, from ~/cowrie/var/log/cowrie/)
Output: events.csv    (one row per meaningful event)

Cowrie event types we care about:
  cowrie.session.connect   -> a new connection (src_ip, src_port, timestamp)
  cowrie.login.success     -> credential tried (username, password)  <- succeeded
  cowrie.login.failed      -> credential tried (username, password)  <- failed
  cowrie.command.input     -> a command the attacker ran (input)
  cowrie.session.closed    -> session end (duration_ms)
  cowrie.client.version    -> attacker SSH client string
  cowrie.client.kex        -> hassh fingerprint (good ML feature)

Usage:
    python parse_cowrie.py --in cowrie.json --out events.csv

TODO (Member 1):
  - stream the file line by line (it can be large) and json.loads each line
  - keep only the event types above; pull out the fields listed
  - normalise timestamps to UTC datetimes
  - drop localhost (127.0.0.1) test sessions, or flag them with is_test=True
  - write one clean row per event to events.csv with pandas
"""
import argparse
import json


def parse(infile: str, outfile: str) -> None:
    rows = []
    with open(infile, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            # TODO: branch on e["eventid"] and append the fields you need
            rows.append(e)
    print(f"Read {len(rows)} raw events from {infile}")
    # TODO: build a pandas DataFrame from the fields you kept and save to outfile
    # import pandas as pd; pd.DataFrame(clean).to_csv(outfile, index=False)
    print(f"(stub) would write structured events to {outfile}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default="cowrie.json")
    ap.add_argument("--out", dest="outfile", default="events.csv")
    args = ap.parse_args()
    parse(args.infile, args.outfile)
