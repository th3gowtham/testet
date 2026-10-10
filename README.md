**To:** security@increase.com (reply in the existing thread "Responsible Security Disclosure – Valid Vulnerability Report")
**Subject:** [Low] Open redirect after SSO login on dashboard.increase.com via control character in `redirect` parameter

Hi Increase Security team,

As you suggested, here is a report with reproduction steps.

## Summary
An attacker can send an Increase user who signs in with SSO a genuine `dashboard.increase.com` login link. Once the user completes SSO, the dashboard sends them to an external site the attacker chose. The post-login path sanitizer strips leading `/` and `\`, but not tab or newline characters, and browsers remove those characters when they parse a URL.

**Affected:** `https://dashboard.increase.com`, current production bundle `/assets/index-ByLgVfuc.js` (verified 2026-10-10).

## Root cause (production bundle, minified names)
```js
s = o.get(`redirect`)                                    // login page reads ?redirect=
k1 = (e,t) => encodeURIComponent(btoa(JSON.stringify({nextUrl:t, email:e})))   // carried through SSO in `state`

// /authentication_callback, after the session is created:
window.location.replace(uG(r?.nextUrl || ``))
uG = e => `/${e.replace(/^[\\/]+/, ``)}`
```
With `nextUrl = "\t/evil.example"`, `uG` returns `"/\t/evil.example"`. WHATWG URL parsing removes ASCII tab and newline characters, so this becomes `//evil.example`, which resolves to `https://evil.example/`.

## Steps to reproduce
1. As a user whose email domain uses SSO, open:
   `https://dashboard.increase.com/login?redirect=%09/evil.example`
2. Enter the SSO email and complete sign-in with the identity provider.
3. After `/authentication_callback`, the browser lands on `https://evil.example/`.

`%0a/evil.example` and `%0d%0a//evil.example` behave the same way.

**Sanitizer check** (any browser console on `dashboard.increase.com`):
```js
const uG = e => `/${e.replace(/^[\\/]+/, ``)}`;
new URL(uG("\t/evil.example"), location.origin).href  // "https://evil.example/"
new URL(uG("//evil.example"), location.origin).href   // "https://dashboard.increase.com/evil.example" (blocked as intended)
```

**Verification note:** I confirmed the code path in the production bundle and the URL resolution in Chrome. I don't have an SSO-enabled organization, so I couldn't run the full SSO login end to end. An internal SSO test org should confirm it in a minute.

## Impact
- **Phishing from a trusted start:** the victim clicks a real `dashboard.increase.com` URL, authenticates with their real identity provider, and then lands on an attacker page that can imitate Increase (for example, "session expired, re-enter your credentials and 2FA code").
- **Limits:** this affects SSO users only. It can't produce XSS, because the output always starts with `/` so `javascript:` isn't reachable, and the CSP blocks inline script anyway. No token leaks: the auth code is exchanged before the redirect, and only the origin is sent as the Referer.

I'm reporting this as **Low**.

## Suggested fix
Resolve the value against the current origin and only redirect when it stays same-origin:
```js
const u = new URL(nextUrl, location.origin);
location.replace(u.origin === location.origin ? u.pathname + u.search + u.hash : "/");
```
Alternatively, reject values containing control characters (`\x00`–`\x1F`, `\x7F`) before applying the existing check.

**CVSS 3.1:** AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N, score 3.4 (Low)

Thanks,
Gowthambalaji S
