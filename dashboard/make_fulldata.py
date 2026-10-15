import json, pandas as pd, os
root=os.path.join(os.path.dirname(__file__),"..")
def P(f): return os.path.join(root,f)
ev=pd.read_csv(P("events.csv")); ev["timestamp"]=pd.to_datetime(ev["timestamp"],errors="coerce",utc=True)
ipenr=pd.read_csv(P("ip_enrichment.csv"))
clusters=pd.read_csv(P("clusters.csv"))
alerts=pd.read_csv(P("alerts.csv")); alerts["timestamp"]=pd.to_datetime(alerts["timestamp"],errors="coerce",utc=True)
conns=ev[ev["eventid"]=="cowrie.session.connect"]; logins=ev[ev["eventid"].isin(["cowrie.login.success","cowrie.login.failed"])]

# per-IP aggregate
agg=[]
for ip,g in ev.groupby("src_ip"):
    agg.append({"src_ip":ip,
      "n_connections":int((g["eventid"]=="cowrie.session.connect").sum()),
      "n_logins":int(g["eventid"].isin(["cowrie.login.success","cowrie.login.failed"]).sum()),
      "n_commands":int((g["eventid"]=="cowrie.command.input").sum()),
      "n_sessions":int(g["session"].nunique())})
agg=pd.DataFrame(agg)
cl=clusters[["src_ip","cluster_name","anomaly_score","is_anomaly"]] if "cluster_name" in clusters else clusters
att=agg.merge(ipenr,on="src_ip",how="left").merge(cl,on="src_ip",how="left")
attackers=[]
for _,r in att.sort_values("n_connections",ascending=False).iterrows():
    attackers.append({k:(None if pd.isna(r.get(k)) else (float(r[k]) if k in("lat","lon","anomaly_score") else (int(r[k]) if k in("n_connections","n_logins","n_commands","n_sessions","abuse_score","total_reports") else (bool(r[k]) if k=="is_anomaly" else str(r[k]))))) for k in ["src_ip","country","country_code","city","lat","lon","isp","abuse_score","total_reports","n_connections","n_logins","n_commands","n_sessions","cluster_name","anomaly_score","is_anomaly"] if k in r.index})

# alerts: varied — newest 40
al=alerts.sort_values("timestamp",ascending=False).head(40)
alist=[{"sev":r["severity"],"rule":str(r["rule"]),"mitre":r["mitre_id"],"mitre_name":str(r.get("mitre_name","")),"ip":r["src_ip"],"detail":str(r["detail"])[:80],"time":(r["timestamp"].strftime("%m-%d %H:%M") if pd.notna(r["timestamp"]) else "")} for _,r in al.iterrows()]
# creds top 15
creds=(logins.groupby(["username","password"]).size().sort_values(ascending=False).head(15).reset_index(name="n"))
clist=[{"u":str(r["username"]),"p":str(r["password"]),"n":int(r["n"])} for _,r in creds.iterrows()]
# timeline
tl=conns.set_index("timestamp").resample("1h").size()
timeline=[{"t":str(i),"n":int(v)} for i,v in tl.items()]
# countries
byc=conns.merge(ipenr[["src_ip","country"]],on="src_ip",how="left").groupby("country").size().sort_values(ascending=False)
countries=[{"name":str(c),"n":int(n)} for c,n in byc.items()]

DATA={"generated":str(conns["timestamp"].max()),
 "totals":{"attacks":int(len(conns)),"ips":int(ev["src_ip"].nunique()),"logins":int(len(logins)),"alerts":int(len(alerts)),"countries":len(countries),"anomalies":int(att["is_anomaly"].sum()) if "is_anomaly" in att else 0},
 "attackers":attackers,"alerts":alist,"creds":clist,"timeline":timeline,"countries":countries,
 "severity":{k:int(v) for k,v in alerts["severity"].value_counts().items()},
 "mitre":[{"id":i,"name":str(n),"count":int(c)} for (i,n),c in alerts.groupby(["mitre_id","mitre_name"]).size().sort_values(ascending=False).items()]}
open(P("dashboard/fulldata.json"),"w").write(json.dumps(DATA,indent=1))
print("wrote dashboard/fulldata.json —", len(attackers),"attackers,",len(alist),"alerts")
