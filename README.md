# Gladia API key (`x-gladia-key`) disclosed to third-party storage host (OVH S3) on file-download redirect

## Summary

Both official Gladia SDKs (`@gladiaio/sdk` and `gladiaio-sdk`, v2.0.0) transmit the customer's
Gladia API key to an unrelated third-party host when downloading a job's audio file.

`GET /v2/pre-recorded/{id}/file` (and `/v2/live/{id}/file`) responds with an HTTP 302 redirect to a
presigned object-storage URL on `s3.gra.perf.cloud.ovh.net` (OVH). The SDKs automatically follow that
cross-origin redirect and re-send the `x-gladia-key` request header to the OVH host. The presigned URL
is self-authenticating and does **not** require the key, so the key is transmitted to OVH (and its access
logs) with no functional purpose. This is unnecessary exposure of a long-lived secret credential to a
host outside the intended trust boundary (`api.gladia.io`).

## Severity

Low (Medium if OVH-side access logs are retained/accessible, or if the API key is broadly privileged).

Estimated CVSS 3.1: `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N` ≈ 3.7 (Low). Severity note: the receiving host
is Gladia's storage subprocessor over TLS, not an arbitrary attacker, so this is a credential-hygiene /
information-exposure issue rather than direct key theft. Final rating is the program's to set.

## Affected Asset

- URL: `https://api.gladia.io/v2/pre-recorded/{id}/file` and `https://api.gladia.io/v2/live/{id}/file`
- Endpoint: pre-recorded / live job audio download (`get_file()` / `getFile()`)
- Parameter: `x-gladia-key` request header (auto-forwarded on redirect)
- HTTP Method: GET
- Affected functionality: SDK file-download helpers
  - Python `gladiaio_sdk`: `PreRecordedV2Client.get_file` / async, `LiveV2Client.get_file`
    (`network/http_client.py` — `httpx.Client(..., follow_redirects=True)` at the sync client, and
    the equivalent `httpx.AsyncClient(..., follow_redirects=True)`).
  - JS `@gladiaio/sdk`: `PreRecordedV2Client.getFile` / `LiveV2Client.getFile`
    (`network/httpClient.ts` — `fetch()` with default `redirect: 'follow'`).

## Vulnerability Details

The API key is sent as a **custom** header, `x-gladia-key`. On a cross-origin HTTP redirect, both
underlying HTTP clients strip only *standard* credential headers (`Authorization`, `Cookie`,
`Proxy-Authorization`) and preserve custom headers. Because neither SDK disables redirect-following nor
removes `x-gladia-key` when the redirect target host differs from the configured API host, the key is
forwarded verbatim to whatever host the `Location` header names.

In production, `Location` points to `s3.gra.perf.cloud.ovh.net` — a different registrable domain than
`api.gladia.io`. The presigned URL carries its own AWS SigV4 authentication in the query string
(`X-Amz-Signature`, `X-Amz-Expires=86400`) and is validated by object storage independently of the
Gladia key. Sending `x-gladia-key` to that host therefore provides no function and only exposes the
secret to a third party and its logging pipeline.

Observed facts vs. assumptions:
- Observed: the `/file` endpoint returns 302 to `s3.gra.perf.cloud.ovh.net`.
- Observed: the presigned URL returns the audio with no key, and with a junk key (both HTTP 200) — the
  key is superfluous at the storage host.
- Observed (local, controlled): both SDKs re-send `x-gladia-key` on a cross-origin redirect.
- Assumption (not independently verified against OVH's servers): OVH logs inbound request headers. This
  is standard for HTTP access logging but was not confirmed on Gladia/OVH infrastructure.

## Preconditions

- A valid Gladia API key.
- Any completed job with a retrievable audio file (normal usage).
- The consumer application calls the SDK's file-download helper (`get_file()` / `getFile()`), which is
  the documented way to retrieve job audio.

## Steps to Reproduce

1. Create/own a Gladia account and obtain an API key.
2. Submit any audio for transcription so a job with a downloadable file exists; note its job `id`.
3. Request the file endpoint and inspect the redirect without following it (see PoC request 1) — observe
   the 302 `Location` points to `s3.gra.perf.cloud.ovh.net`.
4. Fetch the presigned `Location` URL with no `x-gladia-key` header (PoC request 2) — observe HTTP 200
   and the audio bytes, proving the key is not needed at the storage host.
5. Confirm the SDK forwards the key: call `get_file()` / `getFile()` through an intercepting proxy (or
   the local mock in PoC request 3) and observe `x-gladia-key` present in the outbound request to the
   redirect target host.

## Proof of Concept

Keys and the AWS signature are redacted. Job/file identifiers below belong to the tester's own accounts.

PoC request 1 — capture the redirect (do not follow):

```http
GET /v2/pre-recorded/06fddbe9-df88-4339-b474-aeaffdd11967/file HTTP/2
Host: api.gladia.io
x-gladia-key: sk_gladia_REDACTED
```

Response 1 (redirect leaves api.gladia.io):

```http
HTTP/2 302
location: https://s3.gra.perf.cloud.ovh.net/gladia-eu-api-files/files/ced4a668-6e2c-4d17-9e4a-4e95f4242a15.wav?x-id=GetObject&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=REDACTED%2F20260916%2Fgra%2Fs3%2Faws4_request&X-Amz-Date=20260916T150339Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=REDACTED
```

PoC request 2 — the presigned URL needs no Gladia key (key is superfluous at OVH):

```http
GET /gladia-eu-api-files/files/ced4a668-...wav?...X-Amz-Signature=REDACTED HTTP/2
Host: s3.gra.perf.cloud.ovh.net
```

Response 2:

```http
HTTP/2 200
content-type: application/octet-stream
content-length: 32044

RIFF....WAVE   (audio bytes returned; no x-gladia-key was sent)
```

The same request repeated with `x-gladia-key: JUNK` also returns HTTP 200 — the storage host ignores the
header entirely, confirming it serves no purpose there.

PoC request 3 — SDK re-sends the key across origins (local, controlled proof of the forwarding behavior).
A mock API on `127.0.0.1:8001` answers 302 to a logging host on `127.0.0.2:8002`; driving the real SDKs
(`gladiaio_sdk` sync + async, `@gladiaio/sdk`) at the mock produced, at the different-origin logging host:

```text
ATTACKER HOST RECEIVED: GET /steal/... | x-gladia-key = FAKE-TEST-KEY-1234  | authorization = None   (py sync)
ATTACKER HOST RECEIVED: GET /steal/... | x-gladia-key = FAKE-TEST-KEY-ASYNC | authorization = None   (py async)
ATTACKER HOST RECEIVED: GET /steal/... | x-gladia-key = FAKE-TEST-KEY-JS    | authorization = None   (js)
```

`authorization` (a standard header, set for comparison) was correctly stripped, isolating the root cause:
only the custom `x-gladia-key` survives the cross-origin redirect. Scripts: `poc/mock.py`, `poc/poc.py`,
`poc/poc.mjs` in this workspace.

## Expected Behavior

The API key should be sent only to the configured Gladia API host. On a redirect to a different origin,
the SDK should drop `x-gladia-key` (as HTTP clients already do for `Authorization`).

## Actual Behavior

The SDK follows the cross-origin 302 and re-sends `x-gladia-key` to `s3.gra.perf.cloud.ovh.net`, where it
is unnecessary, on every file download.

## Security Impact

The customer's long-lived Gladia API key is disclosed to a third-party host (OVH object storage) and its
request-logging pipeline, outside the intended `api.gladia.io` trust boundary, on every audio download.
Anyone with access to OVH-side access logs (OVH personnel, a log-processing subprocessor, or an attacker
who compromises that logging path) could recover live Gladia API keys. Because Gladia keys are bearer
credentials, a recovered key grants full API access to that tenant's data and quota.

## Attack Scenario

An application backend uses `get_file()` to fetch transcription audio. On each call its Gladia API key is
transmitted to OVH's S3 endpoint. An adversary with visibility into OVH's HTTP access logs for that bucket
endpoint (or a misconfiguration/leak of those logs) harvests the recurring `x-gladia-key` header value and
reuses it directly against `api.gladia.io` to read the victim tenant's jobs, audio, and transcripts.

## Root Cause

The SDKs authenticate with a custom header (`x-gladia-key`) but rely on the HTTP client's default
redirect-following. `httpx` (`follow_redirects=True`) and `undici`/WHATWG `fetch` (`redirect: 'follow'`)
strip only standard credential headers on cross-origin redirects, not custom ones. No SDK-level logic
removes `x-gladia-key` when the redirect host changes. Behavior was introduced with the file-download
redirect handling (repo commit `bd3a394`, "Add follow_redirect to handle get_file redirection to s3").

## Remediation

- Do not auto-follow redirects with credentials attached. Set `follow_redirects=False` (httpx) /
  `redirect: 'manual'` (fetch) in the file-download path and re-issue the request to the redirect target
  **without** `x-gladia-key` (and only after validating the scheme/host).
- Alternatively, register a redirect hook that removes `x-gladia-key` whenever the next hop's origin
  differs from the configured API origin.
- Server-side defense-in-depth: the API need not depend on clients forwarding the key through the
  redirect; the presigned URL already authorizes the download.

## References

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-522: Insufficiently Protected Credentials
- OWASP API Security Top 10 (2023) — API2: Broken Authentication (credential handling)
- PortSwigger / general HTTP-client research on `Authorization`-header stripping across redirects

## Evidence

- Live: 302 `Location` to `s3.gra.perf.cloud.ovh.net` (Response 1 above), request IDs from testing on
  2026-09-16 (e.g. `G-…` values in session logs).
- Live: presigned URL returns HTTP 200 (32044 bytes, `WAVE audio`) with no key and with a junk key.
- Local controlled PoC output (Response 3 above); scripts `poc/mock.py`, `poc/poc.py`, `poc/poc.mjs`.
- Source: `packages/sdk-python/src/gladiaio_sdk/network/http_client.py` (`follow_redirects=True`);
  `packages/sdk-js/src/network/httpClient.ts` (default `redirect: 'follow'`); repo commit `bd3a394`.

## Verification Status

**Confirmed — Genuine Security Vulnerability**

## Notes

- Recipient is Gladia's storage subprocessor (OVH) over TLS; this is credential exposure to an unintended
  party, not direct interception by an arbitrary attacker. Severity is deliberately conservative.
- Not established from available evidence: OVH's actual header-logging/retention for this endpoint.
- The presigned URLs are valid for 24h (`X-Amz-Expires=86400`); anyone who obtains a presigned URL can
  fetch the audio without a key during that window. Tracked separately, not part of this finding
