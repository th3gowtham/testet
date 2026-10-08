# Unauthenticated Prometheus `/metrics` endpoint exposes internal render-farm inventory — `temp-db.aura-acceleration.configura.com`

| | |
|---|---|
| **Program** | Configura Security Bug Bounty Program (Xposera) |
| **Scope asset** | `*.configura.com` (in scope) |
| **Affected host** | `https://temp-db.aura-acceleration.configura.com` |
| **Endpoint** | `GET /metrics` (no authentication) |
| **Vulnerability** | Security misconfiguration / sensitive information disclosure |
| **Weakness** | CWE-200 (Exposure of Sensitive Information), CWE-16 (Configuration) |
| **Severity** | **medium **  |
| **Date** | 2026-10-08 |

---

## Summary

The service at `temp-db.aura-acceleration.configura.com` (a Go application that fronts the Aura
Acceleration / offsite render farm) exposes its Prometheus metrics endpoint, `GET /metrics`,
**without any authentication**. Every other API route on the host is correctly protected
(`/api/stats`, `/api/active_servers`, `/api/servers` all return `401 'Authorization' header token
missing or is invalid`), but `/metrics` is served to anyone.

The exported metrics are not generic runtime counters only — they include a custom exporter
(`offsite_exporter_*`) that publishes the internal render-farm inventory and job pipeline state:
individual render-server hostnames, their health and status, per-server queue outcomes, and
cumulative job counts.

## Impact

An unauthenticated attacker learns internal operational details that are normally not public and
that aid reconnaissance / targeting of the render infrastructure:

- **Internal server inventory** — 15 render servers enumerated by hostname, e.g.
  `CIT-CWS-58557RenderServer` … `CIT-CWS-58977RenderServer`, each with `health_status` and
  `server_status` (all `HEALTHY` / `IDLE` at capture time). This reveals the internal naming
  convention (`CIT-CWS-<id>RenderServer`) and the fleet size.
- **Job pipeline volume and health** — cumulative job counters disclose throughput and error rates,
  e.g. `COMPLETED_RENDER = 130637`, `ABORTED_API = 212`, `ABORTED_RENDER = 34`,
  `RENDERING_RENDER = 1`, `UPLOADING_RENDER = 1`, plus per-server `queue_status` breakdowns.
- **Runtime fingerprint** — `go_info{version="go1.24.2"}` and the full Go runtime/GC metric set,
  useful for matching the host to known runtime-version issues.

No credentials, tokens, or customer data are exposed, so impact is limited to information disclosure
of internal infrastructure — hence **Low**. It is nonetheless a real misconfiguration: metrics
endpoints are a well-known thing to lock down precisely because they leak internal topology and can
expose far more (labels frequently carry hostnames, routes, user identifiers, or DB names).

## Steps to reproduce

```bash
curl -s https://temp-db.aura-acceleration.configura.com/metrics | head
```

Observed: `HTTP/2 200`, `Content-Type: text/plain; version=0.0.4`, e.g.

```
offsite_exporter_active_servers_total{health_status="HEALTHY",name="CIT-CWS-58557RenderServer",server_status="IDLE"} 1
offsite_exporter_active_servers_total{health_status="HEALTHY",name="CIT-CWS-58558RenderServer",server_status="IDLE"} 1
...
offsite_exporter_jobs_by_status_total{job_status="COMPLETED_RENDER"} 130637
offsite_exporter_jobs_by_status_total{job_status="ABORTED_API"} 212
offsite_exporter_queue_status_total{name="CIT-CWS-58782RenderServer",queue_status="UPLOADING_RENDER"} 1
go_info{version="go1.24.2"} 1
```

Control (the application API is correctly authenticated):

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://temp-db.aura-acceleration.configura.com/api/active_servers
# -> 401   ('Authorization' header token missing or is invalid)
```

## Evidence

- `evidence/20-tempdb-metrics-exposed.txt` — captured response excerpt (application metrics +
  runtime fingerprint).

## Remediation

- Do not expose `/metrics` on the public internet. Bind it to an internal interface / private
  network, or require authentication (the same bearer/JWT middleware already protecting `/api/*`),
  or scrape it over a private side-channel only.
- If a public metrics endpoint is unavoidable, strip high-cardinality / identifying labels
  (server hostnames) and keep only aggregate gauges.

## Severity justification (CVSS 3.1)

`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3 (Low–Medium boundary; treat as Low)** — unauthenticated
network read (`PR:N`), limited confidentiality impact (`C:L`: internal infrastructure inventory and
operational metrics, no credentials/PII), no integrity or availability impact.
