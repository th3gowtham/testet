# Stored HTML/CSS Injection in MyConfigura Briefcase → full-page phishing overlay on app.configura.com

**Program:** Configura Security Bug Bounty Program 
**Scope asset:** `*.configura.com` (in scope)
**Affected host:** `https://app.configura.com` (MyConfigura) — API `https://www2.configura.com/api/v3`
**Severity:** Medium — **CVSS 3.1 5.4** (`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`)
**Weakness:** CWE-79 (Improper Neutralization of HTML) / CWE-1021 (Improper Restriction of Rendered UI Layers) — stored HTML/CSS injection, content spoofing / UI redressing
**Date:** 2026-10-07

---

## Summary

A Briefcase member can store HTML in the Briefcase **description** (and **post body**). The
server-side sanitizer strips scripting vectors (`<script>`, `<img onerror>`, `<svg onload>`,
event handlers, etc.) but **keeps structural tags (`<div>`, `<span>`, `<p>`, `<a>`, …) together
with an arbitrary `style` attribute**. Because this content is rendered into the page with React
`dangerouslySetInnerHTML` in the `app.configura.com` origin, an attacker can inject a
`position:fixed`, full-viewport `<div>` that **covers the entire genuine MyConfigura page with
attacker-controlled content** for every member who opens the shared briefcase — enabling
convincing phishing (fake login/re-auth prompt on the real domain), UI redressing/clickjacking,
and external tracking beacons.

This is **not** JavaScript execution (modern browsers do not execute `javascript:`/`expression()`
in CSS); the impact is content spoofing / UI redress on a trusted, authenticated origin.

## Severity rationale

- **Stored & cross-user:** briefcases are shared; the payload is served to other members,
  **including Configura employees** (posts render a verified-employee badge, confirming staff use
  briefcases).
- **Trusted origin:** the fake content appears on the real `https://app.configura.com` with a
  valid certificate — ideal for credential-phishing.
- **Low privilege to exploit:** any member who can edit a briefcase description/post.
- Limited to spoofing/redress (no script execution, no direct data read) → **Medium**, not High.

## Steps to reproduce

1. Log in to MyConfigura (`https://app.configura.com`) as any user who owns/administers a
   briefcase (create one via **Briefcases → New briefcase**).
2. Set the briefcase description to the payload below. Via the UI: open the briefcase →
   **Settings** / edit description. Equivalent API request:

   ```http
   POST /api/v3/briefcases/edit HTTP/2
   Host: www2.configura.com
   Content-Type: application/json; charset=utf-8
   x-csrf-token: <value of the myconfigura-csrf-token cookie>
   Cookie: <your MyConfigura session cookies>

   {"briefcaseId": <BRIEFCASE_ID>,
    "briefcaseName": "santest",
    "briefcaseDescription": "<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;z-index:99999;background:#b30000;color:#fff;font-size:26px;padding:48px;font-family:sans-serif\">STORED HTML/CSS INJECTION &mdash; attacker-controlled full-page overlay rendered on app.configura.com. A real attacker could draw a fake login box here. <a href=\"https://example.com\">Continue</a></div>"}
   ```

3. The server responds `200` and stores the `style` attribute verbatim (confirmed: the stored
   `description` still contains `position:fixed`).
4. Open the briefcase in MyConfigura and click the **ℹ** (info) icon next to the briefcase name
   (or any view that renders the description/post).
5. **Result:** a full-viewport red overlay with attacker-controlled text and link is painted on
   top of the genuine `app.configura.com` UI. See attached `03-stored-html-css-overlay.jpg`.

A real attacker would instead render a pixel-perfect fake "Your session expired — please sign in
again" box and capture the credentials a victim enters, or use `background:url(//attacker/x.png)`
as a read-receipt/tracking beacon.

## Proof that script execution is NOT required / not possible here

For transparency: the sanitizer does block JavaScript. I tested extensively — event handlers,
`<script>/<img>/<svg>`, mXSS (`title`, `noscript`, `math`, `template`), and `data:`/`javascript:`
URI tricks were all neutralized or isolated. The impact of **this** report is purely the stored
HTML/CSS (overlay/phishing) described above.

## Impact

- Credential phishing on the genuine Configura domain against other briefcase members and staff.
- UI redressing / clickjacking of real MyConfigura controls.
- Visitor tracking via externally-loaded CSS resources (`background:url(...)`).

## Remediation

- **Remove the `style` attribute** from the allowed set (or restrict it to a vetted
  property/value allowlist). Replace the custom filter with a maintained sanitizer such as
  **DOMPurify** configured with a tag **and** attribute allowlist.
- Add a Content-Security-Policy to `app.configura.com` with `script-src 'self'`,
  `style-src 'self' 'unsafe-inline'`→tighten, and `img-src`/`default-src` restrictions to limit
  external resource loads and future injection impact (currently only `frame-ancestors` is set).
- Consider rendering user-supplied description/post content as plain text (or a safe Markdown
  subset) rather than raw HTML.

## Evidence (attached)

- `03-stored-html-css-overlay.jpg` — the stored payload rendering as a full-page overlay on
  `https://app.configura.com/my/briefcases/<id>`.
- `02-rendered-link-modal.jpg` — the description modal rendering injected HTML.

## Notes for the triager

- Testing used a throwaway account and a self-owned test briefcase; all test briefcases were
  deleted afterward. No other users' data was accessed.
- Related lower-severity observations submitted/under review separately: the sanitizer also
  permits an isolated `javascript:` link (executes only in an opaque `about:blank` tab), and the
  `myconfigura-session`/`-digest` cookies lack `HttpOnly`. These are defense-in-depth items and
  not required for the impact above.
