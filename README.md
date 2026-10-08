# Unhandled exception in JWT auth middleware — malformed `Authorization` crashes every request — HTTP 500 & internal error disclosure on `data.content-platform.configura.com`

| | |
|---|---|
| **Program** | Configura Security Bug Bounty Program (Xposera) |
| **Scope** | `*.configura.com` (in scope) |
| **Affected host** | `https://data.content-platform.configura.com` |
| **Vulnerability** | Improper handling of exceptional conditions in authentication middleware; internal error-message disclosure |
| **Weakness** | CWE-755 (Improper Handling of Exceptional Conditions), CWE-209 (Information Exposure Through an Error Message), CWE-248 (Uncaught Exception) |
| **Severity** | **Medium — CVSS 3.1 5.3** (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`; 5.3 is the Medium band, 4.0–6.9) |
| **Date** | 2026-10-08 |

---

## Summary

The `data.content-platform.configura.com` API authenticates requests with a JWT bearer token. Its
auth middleware decodes the token **without null-checking the result**, so any `Authorization: Bearer`
value that is not a decodable JWT makes the handler throw and the server respond with **HTTP 500** and
an internal error message, instead of the correct **HTTP 401**:

```
{"success":false,"message":"Cannot destructure property 'header' of 'object null' as it is null."}
```

The message indicates the code does roughly `const { header } = jwt.decode(token, { complete: true })`
and destructures `header` before checking that `jwt.decode()` returned non-null (it returns `null` for
any string that is not a valid JWT). This is reachable by any unauthenticated attacker on every route.

## Impact

- **Improper input handling in the authentication layer.** Attacker-controlled input (the bearer
  value) reaches an uncaught exception on the server; the correct response to a bad token is `401`,
  not `500`. Exception-throwing auth code is fragile and a bad place to have unhandled paths.
- **Internal error-message disclosure (CWE-209).** The response leaks an implementation detail (the
  JWT-decode/destructure code path), which aids further attacks and fingerprints the stack.
- Not a denial of service: the framework catches the exception and the service remains available
  (verified — a subsequent no-token request still returns `401`).

Severity is **Medium (CVSS 5.3)**: a real defect in the authentication middleware where
attacker-controlled input reaches an uncaught exception and the server discloses an internal error
message (CWE-209). The `C:L` term is carried by that error-message disclosure; `I:N/A:N` because no
integrity or availability impact is demonstrated (the framework catches the exception and the service
stays up). The score sits at the lower end of the Medium band.

**Tested and NOT present (so it is not rated higher):** the signature verification itself is sound —
structurally-valid forged tokens are correctly rejected with `401 "Invalid token"`, including
`alg:none` (lower/upper/mixed case), empty-secret `HS256`, and common weak secrets. There is **no**
authentication bypass; the only defect is the unhandled-exception / error-disclosure path on
non-decodable input.

## Steps to reproduce

```bash
H=https://data.content-platform.configura.com

# Correct behaviour:
curl -s -w '\n%{http_code}\n' "$H/v1"                                  # 401 "No authorization token was found"
curl -s -w '\n%{http_code}\n' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x' "$H/v1"   # 401 "Invalid token"

# Bug — any non-JWT bearer crashes the handler:
curl -s -w '\n%{http_code}\n' -H 'Authorization: Bearer notajwt' "$H/v1"
#  -> 500 {"success":false,"message":"Cannot destructure property 'header' of 'object null' as it is null."}
```

Reproduced on `/`, `/v1`, `/v1/health`, `/v1/openapi.json`, `/metrics` with bearer values
`notajwt`, `abc`, `a.b.c`, `x`. Sibling services (`gabana`, `lodzilla`, `puppetshow`, `categories`,
`nxapi`, `thumbify`) correctly return `401` for the same input, so the defect is specific to this
host's middleware.

## Remediation

- Null-check the decode result before destructuring, e.g.
  `const decoded = jwt.decode(token, { complete: true }); if (!decoded) return res.status(401)...;`
  — and wrap token verification in try/catch so any parse/verify failure returns `401`, never `500`.
- Return a generic `401` body; do not echo internal exception text to clients.

## Evidence

- `evidence/22-data-cp-jwt-500.txt` — full request/response matrix (clean 401 vs 500 crash, sibling
  comparison, stability check).
