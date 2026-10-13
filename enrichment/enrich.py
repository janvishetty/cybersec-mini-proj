"""
enrich.py  —  Member 2 (Enrichment)

Add context to each source IP:
  - GeoIP   : country, city, latitude, longitude   (MaxMind GeoLite2, local .mmdb)
  - AbuseIPDB: abuse confidence score (0-100), total reports

Input : events.csv     (from ingestion/parse_cowrie.py)
Output: enriched.csv    (same rows + geo + reputation columns)

Set your key as an env var, never hard-code it:
    export ABUSEIPDB_API_KEY="..."

Usage:
    python enrich.py --in events.csv --out enriched.csv

TODO (Member 2):
  - collect the unique src_ip values (don't call the API once per row)
  - GeoIP: geoip2.database.Reader('GeoLite2-City.mmdb').city(ip)
  - AbuseIPDB: GET https://api.abuseipdb.com/api/v2/check
      headers={'Key': KEY, 'Accept': 'application/json'}
      params={'ipAddress': ip, 'maxAgeInDays': 90}
  - cache results per IP; merge back onto the events table
"""
import argparse
import os

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")


def enrich(infile: str, outfile: str) -> None:
    if not ABUSEIPDB_API_KEY:
        print("WARNING: ABUSEIPDB_API_KEY not set — reputation lookups will be skipped")
    # TODO: load events.csv, get unique IPs, look up geo + reputation, merge, save
    print(f"(stub) would enrich {infile} -> {outfile}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default="events.csv")
    ap.add_argument("--out", dest="outfile", default="enriched.csv")
    args = ap.parse_args()
    enrich(args.infile, args.outfile)
