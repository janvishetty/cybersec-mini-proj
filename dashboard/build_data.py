"""
build_data.py — read pipeline CSVs, bake real data into a standalone dashboard.
Writes dashboard/dashboard.html (self-contained) and prints DATA as JSON.
Usage: python dashboard/build_data.py
"""
import json, pandas as pd, os

HERE = os.path.dirname(__file__)
root = os.path.join(HERE, "..")
def p(name): return os.path.join(root, name)

events  = pd.read_csv(p("events.csv"))
ipenr   = pd.read_csv(p("ip_enrichment.csv"))
alerts  = pd.read_csv(p("alerts.csv"))
clusters= pd.read_csv(p("clusters.csv"))
events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce", utc=True)

conns  = events[events["eventid"]=="cowrie.session.connect"]
logins = events[events["eventid"].isin(["cowrie.login.success","cowrie.login.failed"])]

# per-IP connection counts + geo
cc = conns.groupby("src_ip").size().rename("count").reset_index()
geo = ipenr.merge(cc, on="src_ip", how="left").fillna({"count":0})
geo["count"] = geo["count"].astype(int)

# map sources: top 15 IPs by count
src = geo.sort_values("count", ascending=False).head(15)
sources = []
for _, r in src.iterrows():
    sev = "high" if (r.get("abuse_score",0) or 0) >= 90 else "repeat"
    if pd.notna(r.get("lat")) and pd.notna(r.get("lon")):
        sources.append({"country": str(r.get("country","?")),
                        "lat": float(r["lat"]), "lon": float(r["lon"]),
                        "count": int(r["count"]), "sev": sev})

# top countries by connections
byc = conns.merge(ipenr[["src_ip","country"]], on="src_ip", how="left")
countries = (byc.groupby("country").size().sort_values(ascending=False)
             .head(7).reset_index(name="n"))
countries = [{"name": str(c), "n": int(n)} for c,n in zip(countries["country"], countries["n"])]

# timeline: 24 hourly buckets ending at last event
tl = conns.set_index("timestamp").resample("1h").size()
timeline = [int(x) for x in tl.tail(24).tolist()] or [0]*24

# recent alerts (top 10)
al = alerts.copy()
al["timestamp"] = pd.to_datetime(al["timestamp"], errors="coerce", utc=True)
al = al.sort_values("timestamp", ascending=False).head(10)
alert_list = []
for _, r in al.iterrows():
    t = r["timestamp"].strftime("%H:%M") if pd.notna(r["timestamp"]) else ""
    alert_list.append({"sev": r["severity"],
                       "title": str(r["rule"]).replace("_"," ").title(),
                       "time": t, "detail": f"{r['src_ip']} · {str(r['detail'])[:60]}",
                       "tag": r["mitre_id"]})

# top credentials
creds = (logins.groupby(["username","password"]).size()
         .sort_values(ascending=False).head(8).reset_index(name="n"))
cred_list = []
for _, r in creds.iterrows():
    anip = logins[(logins["username"]==r["username"]) & (logins["password"]==r["password"])]["src_ip"].iloc[0]
    cred_list.append({"u": str(r["username"]), "p": str(r["password"]),
                      "ip": str(anip), "n": int(r["n"]), "real": True})

top_country = countries[0]["name"] if countries else "?"
n_crit = int((alerts["severity"]=="critical").sum())
n_warn = int((alerts["severity"]=="warning").sum())

DATA = {
  "kpis": [
    {"label":"Total attacks","val": f"{len(conns):,}","meta": f"{len(conns):,} SSH connections captured","sm":False},
    {"label":"Unique source IPs","val": str(events['src_ip'].nunique()),"meta": f"across {len(set(c['name'] for c in countries))}+ countries","sm":False},
    {"label":"Top source country","val": top_country,"meta": f"{countries[0]['n']:,} connections" if countries else "","sm":True},
    {"label":"Alerts fired","val": str(len(alerts)),"meta": f"{n_crit} critical · {n_warn} warning","sm":False},
  ],
  "honeypot": {"name":"Honeypot","lat":18.5,"lon":73.8},
  "sources": sources, "countries": countries, "timeline": timeline,
  "alerts": alert_list, "creds": cred_list,
}

# write standalone dashboard with real data baked in
tpl = open(p("dashboard/index.html")).read()
s = tpl.index("const DATA =")
e = tpl.index("const $ = (id)")
out = tpl[:s] + "const DATA = " + json.dumps(DATA) + ";\n\n" + tpl[e:]
# flip the PREVIEW badge off
out = out.replace('<span class="pill preview">PREVIEW · placeholder data</span>',
                  '<span class="pill" style="color:var(--good)">LIVE DATA · '+str(len(conns))+' attacks</span>')
open(p("dashboard/dashboard.html"), "w").write(out)

print("Wrote dashboard/dashboard.html (open this — real data baked in)")
print("\n===DATA_JSON_START===")
print(json.dumps(DATA))
print("===DATA_JSON_END===")
