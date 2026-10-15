"""
enrich.py — add GeoIP (ip-api.com) + AbuseIPDB reputation to each source IP.
Member 2 (Enrichment)
Usage: python enrichment/enrich.py --in events.csv --out enriched.csv
Needs: export ABUSEIPDB_API_KEY="..."
"""
import argparse, os, time, requests
import pandas as pd

ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

def geo_lookup(ips):
    """ip-api.com batch endpoint — up to 100 IPs per call, free, no key."""
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i+100]
        payload = [{"query": ip, "fields": "query,status,country,countryCode,city,lat,lon,isp,org,as"} for ip in chunk]
        try:
            r = requests.post("http://ip-api.com/batch", json=payload, timeout=20)
            for rec in r.json():
                if rec.get("status") == "success":
                    out[rec["query"]] = rec
        except Exception as e:
            print("geo error:", e)
        time.sleep(1)  # be polite to the free endpoint
    return out

def abuse_lookup(ip):
    if not ABUSE_KEY:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "usage_type": d.get("usageType"),
            "domain": d.get("domain"),
        }
    except Exception as e:
        print("abuse error for", ip, ":", e)
        return {}

def enrich(infile, outfile):
    df = pd.read_csv(infile)
    ips = sorted(df["src_ip"].dropna().unique().tolist())
    print(f"Enriching {len(ips)} unique IPs...")

    geo = geo_lookup(ips)
    print(f"  GeoIP: resolved {len(geo)}/{len(ips)}")

    if not ABUSE_KEY:
        print("  WARNING: ABUSEIPDB_API_KEY not set — skipping reputation")

    rep = {}
    for n, ip in enumerate(ips, 1):
        rep[ip] = abuse_lookup(ip)
        if n % 10 == 0:
            print(f"  AbuseIPDB: {n}/{len(ips)}")
        time.sleep(0.6)  # stay well under rate limit

    # build a per-IP enrichment table
    rows = []
    for ip in ips:
        g = geo.get(ip, {})
        a = rep.get(ip, {})
        rows.append({
            "src_ip": ip,
            "country": g.get("country"), "country_code": g.get("countryCode"),
            "city": g.get("city"), "lat": g.get("lat"), "lon": g.get("lon"),
            "isp": g.get("isp"), "org": g.get("org"), "asn": g.get("as"),
            "abuse_score": a.get("abuse_score"), "total_reports": a.get("total_reports"),
            "usage_type": a.get("usage_type"),
        })
    enr = pd.DataFrame(rows)
    enr.to_csv("ip_enrichment.csv", index=False)

    merged = df.merge(enr, on="src_ip", how="left")
    merged.to_csv(outfile, index=False)
    print(f"Wrote per-IP table -> ip_enrichment.csv ({len(enr)} IPs)")
    print(f"Wrote enriched events -> {outfile} ({len(merged)} rows)")
    # quick peek
    top = enr.sort_values("abuse_score", ascending=False, na_position="last").head(8)
    print("\nTop IPs by abuse score:")
    print(top[["src_ip","country","abuse_score","isp"]].to_string(index=False))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",  dest="infile",  default="events.csv")
    ap.add_argument("--out", dest="outfile", default="enriched.csv")
    a = ap.parse_args()
    enrich(a.infile, a.outfile)
