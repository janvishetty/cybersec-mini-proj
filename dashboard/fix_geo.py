import json, requests, os, time
f = os.path.join(os.path.dirname(__file__), "fulldata.json")
d = json.load(open(f))
ips = [a["src_ip"] for a in d["attackers"]]
geo = {}
for i in range(0, len(ips), 100):
    chunk = ips[i:i+100]
    payload = [{"query": ip, "fields": "query,status,country,countryCode,city,lat,lon,isp"} for ip in chunk]
    r = requests.post("http://ip-api.com/batch", json=payload, timeout=25)
    for rec in r.json():
        if rec.get("status") == "success":
            geo[rec["query"]] = rec
    time.sleep(1)
got = 0
for a in d["attackers"]:
    g = geo.get(a["src_ip"])
    if g:
        a["country"] = g.get("country"); a["country_code"] = g.get("countryCode")
        a["city"] = g.get("city"); a["lat"] = g.get("lat"); a["lon"] = g.get("lon")
        a["isp"] = g.get("isp"); got += 1
# rebuild country counts weighted by connections
from collections import Counter
cc = Counter()
for a in d["attackers"]:
    if a.get("country"): cc[a["country"]] += a.get("n_connections", 0)
d["countries"] = [{"name": k, "n": int(v)} for k, v in cc.most_common()]
d["totals"]["countries"] = len(cc)
json.dump(d, open(f, "w"), indent=1)
print(f"geo filled for {got}/{len(ips)} IPs; {len(cc)} countries")
