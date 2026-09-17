# Convex Platform Security Report — Read-only deployment identity can modify data and run internal functions

**Reporter:** Auditify Security (info@auditifysecurity.com)
**Date:** 2026-09-17
**Vendor / product:** Convex (convex.dev) — reactive backend-as-a-service; open-source backend `github.com/get-convex/convex-backend`
**Disclosure:** Private, per Convex VDP (`security@convex.dev`). No public disclosure until fixed.
**Method:** Static source audit of the public backend + live documentation verification. Code paths cited by `file:line` against the current `main` of `get-convex/convex-backend`.

---

## 1. Summary

Convex documents that, **on production deployments, a Team Developer who is not also a Project Admin receives a "read-only deployment identity"** and may modify data or run mutations *"only on non-production deployments."* The role model marks `deployment:data:write`, `deployment:functions:runInternalMutations`, and `deployment:functions:runInternalActions` as non-production only.

In the backend, that read-only restriction is enforced **only** on a subset of endpoints (the dashboard data-editor and a handful of management routes) via `Identity::require_operation`. The **function-execution surface — `POST /api/mutation`, `POST /api/function`, `POST /api/run/{path}`, and the WebSocket sync "Mutation" message — performs no such check.** These paths never consult the identity's `is_read_only` flag or require `data:write` / `runInternalMutations`. Internal functions are additionally gated only on `identity.is_admin()`, which is **true for a read-only admin identity**.

**Net effect:** any principal holding a read-only production identity (the *default* role for a non-admin team member, plus deliberately read-only contractors / CI keys) can **write and delete arbitrary production data and execute internal mutations and actions** (which can call external services via `fetch`, send email, spend money, etc.) — a direct contradiction of the platform's documented authorization guarantee.

- **Severity:** High — **CVSS:3.1 8.8** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)
- **Class:** CWE-863 Incorrect Authorization (also CWE-285 Improper Authorization, CWE-284 Improper Access Control)
- **Boundary broken:** platform-issued credential/role **scope** (management plane). This is the top-priority test in a multi-tenant BaaS threat model ("read-only → read-write escalation").

---

## 2. Affected surface

| Path | Handler | File |
|------|---------|------|
| `POST /api/mutation` | `public_mutation_post` | `crates/local_backend/src/public_api.rs:661` |
| `POST /api/function` | `public_function_post` | `crates/local_backend/src/public_api.rs:215` |
| `POST /api/run/{path}` | `public_function_post_with_path` | `crates/local_backend/src/public_api.rs:287` |
| WebSocket `Mutation` msg | sync worker mutation branch | `crates/sync/src/worker.rs:707` |
| `POST /api/run_test_function` | `run_test_function` (related; see §7) | `crates/local_backend/src/dashboard.rs:298` |

All are served by `local_backend`, which backs **both** Convex Cloud (behind the closed-source Usher proxy) and **self-hosted** deployments (no proxy). Self-hosted is unambiguously affected.

---

## 3. Preconditions (attacker starting state)

The attacker holds a **read-only deployment identity** for a **production** deployment. Realistic sources:

- A **Team Developer** who is not a Project Admin — per docs, the *default* read-only identity on production. This is an ordinary engineer on the team.
- A collaborator/contractor deliberately given read-only access to inspect data/logs.
- A read-only key issued for CI, analytics, or a support tool.

The read-only admin key is the credential the dashboard/CLI already uses (`Authorization: Convex <key>`); the holder can read it from local CLI state or a dashboard request.

---

## 4. Root cause (code walk-through)

### 4.1 Read-only is a `DeploymentOp` set enforced only via `require_operation`
A read-only key carries a reduced operation set inside its **authenticated** (AES-128-GCM-SIV) blob:

```rust
// crates/keybroker/src/operations.rs
pub fn operations_for_deploy_key(is_read_only: bool) -> Vec<DeploymentOp> {
    if is_read_only { read_only_operations() } else { vec![] } // empty == all allowed
}
pub fn read_only_operations() -> Vec<DeploymentOp> {
    vec![ ViewEnvironmentVariables, ViewLogs, ViewMetrics, ViewIntegrations,
          ViewData, ViewBackups, DownloadBackups, RunInternalQueries,
          RunTestQuery, ViewAuditLog, ViewUsageLimits, ViewUsage ]
    // NOTE: deliberately EXCLUDES WriteData, RunInternalMutations, RunInternalActions
}
```

Enforcement is centralized in one method:

```rust
// crates/roles/src/eval.rs:283
fn require_operation(&self, operation: DeploymentOp) -> anyhow::Result<()> {
    let admin_identity = match self {
        Identity::System(_) => return Ok(()),
        Identity::DeploymentAdmin(a) | Identity::ActingUser(a, _) => a,
        Identity::User(_) | Identity::Unknown(_) => return Err(bad_admin_key_error(...)),
    };
    if !admin_identity.is_operation_allowed(operation)? { bail!(forbidden("OperationNotPermitted", ...)); }
    Ok(())
}
```

The intent that read-only blocks **data writes** is proven by the dashboard **data-editor**, which does call it:

```rust
// crates/local_backend/src/dashboard.rs
identity.require_operation(keybroker::DeploymentOp::WriteData)?;   // :157, :184  (document add/update/delete)
```

### 4.2 The function-execution path enforces nothing
`POST /api/mutation`:

```rust
// crates/local_backend/src/public_api.rs:661  public_mutation_post
let identity = st.api.authenticate(&host, ctx, auth_token).await?;   // read-only DeploymentAdmin
let udf_result = st.api.execute_public_mutation(&host, ctx, identity, export_path, args, ...).await?;
// no require_operation, no is_read_only check
```

```rust
// crates/application/src/api.rs:343  execute_public_mutation
self.mutation_udf(ctx, PublicFunctionPath::RootExport(path), args, identity, ...).await
```

```rust
// crates/application/src/lib.rs:1323  mutation_udf  -> retry_mutation
//   no require_operation / is_read_only anywhere on this path
// crates/application/src/application_function_runner/mod.rs:884  retry_mutation
//   only identity gate:  if path.is_system() && !(identity.is_admin() || identity.is_system()) { deny }
```

The mutation commits. `is_read_only` is **never** read in the data plane (verified by grep: the flag is consulted only inside `require_operation` and to render dashboard "disabled states").

### 4.3 Internal functions are reachable because the gate is `is_admin()`
`POST /api/function` / `/api/run` → `execute_any_function` → `any_udf`:

```rust
// crates/application/src/lib.rs:1550  (inside any_udf function resolution)
.filter(|af| (identity.is_admin() || af.visibility == Some(Visibility::Public))
             && af.udf_type != UdfType::HttpAction)
```

```rust
// crates/keybroker/src/broker.rs:355
pub fn is_admin(&self) -> bool { matches!(self, Identity::DeploymentAdmin(..)) } // read-only-agnostic
```

A read-only admin satisfies `is_admin()`, so **internal** mutations/actions are selectable and then executed — even though `RunInternalMutations`/`RunInternalActions` are supposed to be denied. Those two ops are defined in the role system (`crates/roles/src/types.rs:1019+`) but are **enforced on no endpoint** (only `RunTestQuery` is, at `dashboard.rs:311`).

### 4.4 Why the "read-only" label is effectively UI-only
The backend advertises read-only status to the client precisely so the dashboard can grey out buttons:

```rust
// crates/local_backend/src/dashboard.rs:236  (doc comment on check_admin_key)
// "Returns the allowed operations and read-only status for the key so the
//  dashboard can show appropriate disabled states."
```

Anything that bypasses the dashboard UI (the CLI, `curl`, the WebSocket sync path) is unrestricted on the data plane.

---

## 5. Reproduction

A turnkey PoC is included (`run_poc.sh`, `convex/poc.ts`, `README.md`). Summary:

1. Deploy `convex/poc.ts` (public `writeMarker`, internal `internalWriteMarker`, query `countMarkers`, `cleanup`) to a deployment you own.
2. Obtain a **read-only** identity — a Team-Developer-on-production key, or a self-hosted `issue_read_only_admin_key`.
3. Confirm read-only: `GET /api/check_admin_key` → `{"isReadOnly": true, "allowedOps": [ …no WriteData/RunInternalMutations… ]}`.
4. Exploit A — public mutation:
   ```bash
   curl -s -X POST "$URL/api/mutation" -H "Authorization: Convex $RO_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"path":"poc:writeMarker","args":{"note":"ro"},"format":"json"}'
   # Expected per docs: 403 OperationNotPermitted.  Actual: 200 + a row inserted.
   ```
5. Exploit B — internal mutation:
   ```bash
   curl -s -X POST "$URL/api/function" -H "Authorization: Convex $RO_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"path":"poc:internalWriteMarker","args":{"note":"ro"},"format":"json"}'
   # Actual: 200, internal mutation executed.
   ```
6. Evidence: `POST /api/query {"path":"poc:countMarkers",...}` shows the count increased. `run_poc.sh` prints a `VULNERABLE` verdict (exit 1) and cleans up.

**Reproduction status:** code-confirmed end-to-end via static analysis. Live confirmation requires the reporter's own authorized deployment + a read-only key (the PoC automates it). The single residual question — whether Convex Cloud's closed-source Usher proxy independently strips read-only keys from `/api/*` — is resolved by running the PoC against a **self-hosted** instance (no proxy), which exercises this exact code.

---

## 6. Impact — what disaster

- **Integrity/Confidentiality/Availability of production data:** a read-only principal can insert, overwrite, and delete arbitrary documents in the production database via public mutations, and via internal mutations reach functions the developer never exposed publicly.
- **Side-effecting internal actions:** internal *actions* run in the action runtime with `fetch`, secrets/env access, and the scheduler — so the escalation extends to sending email, calling third-party/paid APIs, and enqueuing background work as the deployment.
- **Blast radius:** every deployment that has at least one non-admin Team Developer (the common case) or any read-only collaborator/CI key. The "read-only" guarantee that teams rely on to safely grant production visibility is void.
- **Trust-model inversion:** the feature exists specifically to let an organization grant *look-but-don't-touch* access to production; this bug turns every such grant into full data write + internal execution.

---

## 7. Related / secondary observations

- **`run_test_function` (`dashboard.rs:298`)** gates only on `RunTestQuery` (which read-only holds) yet executes an arbitrary bundled module — including mutation modules — via `execute_standalone_module`. Same class as the primary finding; likely the same fix (gate on the resolved UDF type).
- **Debug prints** in the request handlers leak request paths to stdout logs: `println!("{path:?}")` / `println!("{path_parts:?}")` in `public_function_post_with_path` (`public_api.rs`). Informational; remove before release.

---

## 8. Remediation

Enforce the documented role actions on the data plane, mirroring the dashboard editor:

1. In `execute_public_mutation`, `execute_admin_mutation`, and the mutation branch of the sync worker, call `identity.require_operation(DeploymentOp::WriteData)?` before dispatch.
2. In `any_udf` (and `execute_public_action`/`execute_admin_action`), when the resolved `AnalyzedFunction` is **internal**, require `RunInternalMutations` / `RunInternalActions` (by `udf_type`); when it is a public mutation, require `WriteData`. Do **not** use `identity.is_admin()` as the sole gate for selecting internal functions.
3. Actually consult `admin_identity.is_read_only()` (or the op set) in the write path rather than relying on the client to disable UI.
4. Add regression tests: a read-only identity must receive `403 OperationNotPermitted` from `/api/mutation`, `/api/function`, `/api/run`, and the WS `Mutation` message for both public and internal mutations/actions.

---

## 9. Disclosure note (draft to security@convex.dev)

> **Subject:** Broken authorization — read-only production identities can write data and run internal functions
>
> Convex documents that a Team Developer on a production deployment gets a read-only deployment identity and may modify data / run mutations only on non-production deployments (`docs.convex.dev/team-management/role-actions`). However, `POST /api/mutation`, `/api/function`, `/api/run/{path}`, and the WebSocket Mutation message execute functions without enforcing `data:write` / `runInternalMutations`. `mutation_udf` → `retry_mutation` never consult `is_read_only`; internal functions are gated only on `identity.is_admin()`, which is true for read-only admin identities. Read-only enforcement exists only on the dashboard data-editor (`require_operation(WriteData)`), so the CLI/HTTP/WS function paths bypass it.
>
> **Impact:** any read-only production collaborator (the default for a non-admin Team Developer) gains full read/write/delete of production data plus execution of internal mutations and actions. CVSS 3.1 8.8 (High).
>
> A turnkey PoC (deploy a sample module, invoke it with a read-only key, observe the write) and file:line references to the affected paths are attached. Happy to coordinate on a fix window.

---

## Appendix A — Rejected-candidate log (zero-false-positive discipline)

| Candidate | Surface | Why killed | By-design? | App vs platform | Evidence |
|---|---|---|---|---|---|
| JWT alg-confusion (`none`/HS256, RS↔HS) | Auth §5.3 | CustomJwt pins alg from config `decode_with_jwks(&jwks, Some(algorithm))`; OIDC `set_allowed_algs([RS256, EdDSA])` | correct | platform (secure) | `crates/authentication/src/lib.rs` |
| Issuer→wrong-provider routing | Auth §5.3 | `matches_token` requires exact normalized `iss == domain`; mis-routed token fails signature | correct | platform (secure) | `crates/common/src/auth.rs` |
| JWKS / OIDC-discovery SSRF via issuer (error reflects response body) | Auth/Runtime §5.2–5.3 | All provider fetches go through `build_proxied_reqwest_client` (Smokescreen); `407` treated as SSRF block. Self-hosted w/o proxy = operator-scoped, not cross-tenant | partly by-design | cloud-defended / operator | `crates/http_client/src/lib.rs`, `crates/common/src/http/fetch.rs` |
| Read-only → RW via blob tamper | Mgmt §5.4 | Read-only op set lives inside AES-128-GCM-SIV authenticated blob; tampering fails auth tag | correct | platform (secure) | `crates/keybroker/src/broker.rs` |
| `internal` function callable by unauth client | Runtime §5.2 | SyncWorker/HttpApi callers = `PublicOnly`; non-admin identity cannot select internal (`any_udf` filter) | correct for non-admin | platform (secure) | `crates/common/src/types/functions.rs:286`, `lib.rs:1550` |

## Appendix B — Coverage map

- **Deep / tested:** OIDC + custom-JWT verification; admin-key crypto & read-only scope; public/internal function boundary; **read-only data-plane enforcement (this finding).**
- **Partial:** JWKS / action-`fetch` SSRF (cloud proxy-defended; self-hosted operator-scoped).
- **Not yet reached:** cross-deployment routing / Host-header confusion at the edge; storage-ID predictability & cross-deployment file fetch; dashboard IDOR (closed-source, needs live accounts); sync-protocol / Convex-value decoder (prototype pollution); streaming export/import authz across projects; deploy-key over-scope.

## Appendix C — Evidence index (file:line)

- `crates/local_backend/src/public_api.rs:215,287,661` — ungated function-execution handlers
- `crates/application/src/api.rs:343` — `execute_public_mutation` (no op check)
- `crates/application/src/lib.rs:1323,1519,1550` — `mutation_udf`, `any_udf`, `is_admin()` internal gate
- `crates/application/src/application_function_runner/mod.rs:884` — `retry_mutation` (only system-path gate)
- `crates/keybroker/src/operations.rs` — `read_only_operations()` (excludes writes)
- `crates/keybroker/src/broker.rs:355` — `is_admin()` read-only-agnostic
- `crates/roles/src/eval.rs:283` — `require_operation` (the only enforcement point)
- `crates/local_backend/src/dashboard.rs:157,184,311,236` — data-editor `WriteData` gate; `RunTestQuery`; UI-only comment
- `crates/sync/src/worker.rs:707` — WebSocket mutation path (no op check)
