# Dashboard

`index.html` is a self-contained SOC dashboard — world attack map, KPI tiles,
live alert feed, attacks-over-time chart, top countries, and a credentials
table. No external libraries, so it runs anywhere (open the file in a browser,
or serve it from the VM).

## Wiring in real data
All data lives in one `DATA = { ... }` object near the top of the `<script>`.
To go live, replace it with pipeline output, e.g.:

```js
const DATA = await (await fetch('/api/stats')).json();
```

The shape of `DATA` (kpis, sources, countries, timeline, alerts, creds) is the
contract: whatever serves it just needs to match those keys. That makes this
file double as a spec for what the parser + detection output should produce.
