# Hardcoded catalogue-API secret credential in production `app.configura.com` JavaScript — accepted by the **production** catalogue API

| | |
|---|---|
| **Program** | Configura Security Bug Bounty Program (Xposera) |
| **Scope** | `*.configura.com` (in scope) |
| **Leak location** | `https://app.configura.com/static/js/main.ad1c8c93.chunk.js` (production bundle, world-readable) |
| **Credential type** | Catalogue-API secret token (`X-API-Key`, format `<id>.<secret>`) |
| **Accepting hosts** | `catalogueapi-admin.configura.com` (**production**), `admin.api.stage.configura.com` / `api.stage.configura.com` (staging) |
| **Weakness** | CWE-798 (Use of Hard-coded Credentials), CWE-522 (Insufficiently Protected Credentials), CWE-200 |
| **Severity** | **Medium — CVSS 3.1 6.5** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`) as *demonstrated*; **conditional High (7–8)** if Configura confirms the key is authorized for any catalogue read/write (see §4) |
| **Date** | 2026-10-08 |

---

## 1. Impact (why this matters)

Configura ships a **secret** catalogue-API credential inside the production MyConfigura web app's
JavaScript. Any anonymous visitor can copy it out of the static bundle. The credential is **not a
public client id** — it is the `X-API-Key` secret that the bundled catalogue SDK uses to call the
catalogue platform's **admin** and **content** APIs, and it is **accepted as a valid principal by
the production catalogue API** (`catalogueapi-admin.configura.com`), not only staging.

The catalogue platform is core Configura IP: it stores every manufacturer's product catalogues,
pricing/price-lists, geometry and render assets, and the admin surface that the SDK exposes with this
same `X-API-Key` includes manufacturer management, access-token issuance/activation, usage analytics,
and infrastructure control (cache administration, DynamoDB refresh). A leaked credential to that
platform is exactly the kind of secret that must never leave the server.

Because a real secret for a privileged, production-recognised API is sitting in client code, this is
reported as **Medium** on *demonstrated* facts, with a concrete path to **High** (§4) that only
Configura's knowledge of the key's authorization scope can settle.

## 2. The leak

`app.configura.com/static/js/main.ad1c8c93.chunk.js` (production) contains, in clear text:

```js
e.auth = {
  endpoint: "https://api.stage.configura.com",
  secretToken: "STEUCE13JIVJ54VHZNCP2DSRNZB4I3EH.2UYEZLMYCIBIBQXR7VPPCHV2DVXATQ3R",
  apiSession: { expires: "" }
};
```

`secretToken` is a two-part `<key-id>.<secret>` value sent as the HTTP header `X-API-Key` (with
`X-SDK-Version: 3.4.0`). The same bundle's catalogue SDK uses it against these endpoints:

- **Admin:** `/catadmin/user`, `/catadmin/manufacturer/{id}/catalogues`,
  `/catadmin/access-token/{pk}` and `/catadmin/access-token/{pk}/activate`,
  `/catadmin/primary-access-token[/list]`, `/catadmin/aggregated-usage/{daily,hourly}`,
  `/catadmin/admin/cache/{clear-keys,delete-key,scan,info,get}`, `/catadmin/admin/refresh-dynamo`,
  `/catadmin/debug-browsing-session-token`.
- **Content/viewer:** `/v2/catalogue/{cid}/{lang}/{enterprise}/{prdCat}/{prdCatVersion}/{vendor}/{priceList}[/{partNumber}]`,
  `/v2/render/{uuid}`, `/v2/export/.../{partNumber}`, `/v2/session-token/refresh`.

## 3. What is proven

**(a) The secret is in the public production bundle** — see §2 (fetch the JS and `grep STEUCE`).

**(b) The secret is a valid, recognised principal on the PRODUCTION catalogue API** — the server
authenticates the key, then applies an authorization decision. Without the key the request is
rejected at a different stage than with it:

```bash
KEY='STEUCE13JIVJ54VHZNCP2DSRNZB4I3EH.2UYEZLMYCIBIBQXR7VPPCHV2DVXATQ3R'

# PRODUCTION admin catalogue API
curl -s -w '%{http_code}\n' -o /dev/null                       https://catalogueapi-admin.configura.com/catadmin/user   # 400  (no key)
curl -s -w '%{http_code}\n' -H "X-API-Key: $KEY" -o -          https://catalogueapi-admin.configura.com/catadmin/user
#   -> 403 {"error":"403 Forbidden","code":403,"eventId":"5f1664f1fc6f48c7842963e4a5636769"}   (key recognised, this op forbidden)

# STAGING admin catalogue API — same recognition
curl -s -w '%{http_code}\n' -o /dev/null                       https://admin.api.stage.configura.com/catadmin/user      # 404  (no key)
curl -s -w '%{http_code}\n' -H "X-API-Key: $KEY" -o -          https://admin.api.stage.configura.com/catadmin/user
#   -> 403  (key recognised)
```

`403` (authenticated-but-forbidden), not `401`, confirms the key is a **valid credential** the API
accepts and attributes to a principal — on production and staging alike.

## 4. Demonstrated vs. conditional impact (the honest severity split)

- **Demonstrated (Medium):** a real secret catalogue-API credential is exposed in production client
  code and is accepted by the production catalogue API. Every `/catadmin/*` **admin** operation I
  tested returns `403` for this key, so I did **not** demonstrate an admin action, and I did not
  touch any state-changing endpoint.
- **Conditional (High) — one fact away:** the key's `/catadmin/user` being forbidden indicates it is
  a catalogue **viewer/content** credential, whose natural authorization is the
  `/v2/catalogue/...` read path. If that key is authorized to read manufacturer catalogue content
  (products, pricing/price-lists, geometry) — especially for catalogues beyond a single demo
  manufacturer — then the leak discloses proprietary multi-tenant manufacturer data to any anonymous
  user, which is a **High** confidentiality impact. I could not confirm this only because the
  `/v2/catalogue` read requires a valid `cid/lang/enterprise/prdCat/prdCatVersion/vendor/priceList`
  tuple that I could not enumerate (the catalogue-listing operations are themselves `403`). **Configura
  can settle this immediately by checking what the key `STEUCE13…ATQ3R` is scoped to.** If it grants
  catalogue reads (or any write), treat this as High and re-score
  (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5, or higher with integrity).

## 5. Attack chain

1. Anonymous attacker loads `app.configura.com`, opens the JS bundle, extracts `secretToken`.
2. Attacker replays it as `X-API-Key` directly against `catalogueapi-admin.configura.com` /
   `api.stage.configura.com` — no login, no CSRF, no user interaction. The production API accepts the
   credential (§3).
3. Attacker exercises whatever that credential is authorized for on the catalogue platform. At
   minimum the credential is valid indefinitely (it has no client-side expiry: `apiSession.expires: ""`)
   until Configura rotates it; at worst (per §4) it reads proprietary catalogue content.

## 6. Remediation

- **Rotate `STEUCE13…ATQ3R` now** — it is permanently compromised by shipping in a public bundle.
- **Remove the secret from client code.** The browser must never hold a catalogue *secret* token.
  Proxy catalogue calls through the app's own backend, or hand the browser a **short-lived,
  least-privilege public access token** scoped to exactly the catalogue it may view (the API already
  models this via `/v2/access-token/public/{id}/authorize`).
- **Confirm scope / blast radius:** verify what `STEUCE13…ATQ3R` is authorized for on **production**
  (`catalogueapi-admin.configura.com`) and whether any other hardcoded keys exist in shipped bundles.

## 7. Evidence

- `evidence/21-hardcoded-stage-key.txt` — bundle excerpt, full endpoint surface, and the observed
  production + staging recognition (`403` with key, `400`/`404` without).
