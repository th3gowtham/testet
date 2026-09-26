# FINDING #3 — Unclaimed npm namespace (dependency-confusion / package-takeover exposure) for the Bright SDK toolchain

**Asset:** Bright Data partner SDK — Node/JS toolchain & plugins (`github.com/BrightSDK/*`, distributed via `brightsdk.github.io/packages/*` and git).
**Class:** Supply-chain — npm namespace hijack / dependency confusion.
**Status:** Exposure CONFIRMED (registry 404s + code references). Not demonstrated as RCE-via-official-docs today (see honest scope). No malicious package was or will be published.
**Tentative tier:** Security misconfiguration / supply-chain (T1) with realistic escalation to RCE-in-partner-build (T2) under the resolution-by-name conditions below.

## Confirmed facts
Every package name Bright's own repos declare/publish is **unregistered on the public npm registry** (HTTP 404 = freely registrable by anyone), and the **`@bright-sdk` scope is entirely unclaimed**:

| npm name | registry status |
|---|---|
| `react-native-bright-sdk` (published name of `BrightSDK/react-native-plugin`, v2.0.3) | **404 — unclaimed** |
| `bright-sdk-integration` | **404 — unclaimed** |
| `bright-sdk-keycode-parser` | **404 — unclaimed** |
| `bright-sdk-external-consent`, `bright-sdk-settings-dialog`, `bright-sdk-webpack` | **404 — unclaimed** |
| `bright-sdk-i18n`, `bright-sdk-tool-release-manager`, `bright-sdk-react-native` | **404 — unclaimed** |
| `brd-ono-util-exec`, `brd-ono-util-logger`, `brd-ono-app-image-processor`, `brd-ono-util-progress-tracker-{core,cli}`, `brd-ono-util-tizen-resign`, `brd-sdk-integ-tools`, `brd-sdk` | **404 — unclaimed** |
| scope `@bright-sdk/*` (e.g. `@bright-sdk/i18n`, `@bright-sdk/tool-release-manager`) | **404 — scope unclaimed** |

Third-party-held natural names (NOT Bright Data — maintainer `efoxbr`): `node-bright-sdk`, `capacitor-brightsdk`. The official `@brightdata` scope IS owned by Bright Data.

Code references (bare names + scope) that make these live targets for resolution-by-name:
- `bright-sdk-external-consent/package.json` → `devDependencies: { "@bright-sdk/i18n": "https://brightsdk.github.io/.../latest.tgz", "@bright-sdk/tool-release-manager": "https://..." }` and `dependencies: { "bright-sdk-keycode-parser": "https://..." }`
- `bright-sdk-settings-dialog/package.json` → `bright-sdk-keycode-parser` (URL)
- `@bright-sdk/i18n/package.json` → `brd-ono-util-exec`, `brd-ono-util-logger` (URL)
- `bright-sdk-webpack/package.json` → `bright-sdk-integration` (URL)
- Source `import`/`require` of `bright-sdk-keycode-parser`, `bright-sdk-external-consent`, `bright-sdk-integration`, `brd-ono-util-exec`, `brd-ono-util-logger`, `react-native-bright-sdk`.

## Honest exploitability scope (what is and isn't proven)
- **Not proven today via official docs:** the current install instructions use tgz/git/`https://` URL sources (`npm install ./react-native-bright-sdk-2.0.3.tgz`, `npm install git+https://github.com/BrightSDK/react-native-plugin.git`, `npm install -g github:BrightSDK/bright-sdk-integration`), and the shipped packages pin each other by URL — npm does not consult the registry for URL/git specs, so a partner following the docs verbatim is not compromised. This is stated plainly so the report is not a false positive.
- **Realistic exploitation paths (why this is still a vulnerability):**
  1. **Natural `npm i <name>`.** Developers routinely install plugins by their published name. `npm i react-native-bright-sdk` / `npm i bright-sdk-integration` is the obvious first attempt; an attacker squatting those names ships an `install`/`postinstall` script → **RCE on the partner developer/CI machine**.
  2. **Name-instead-of-URL drift.** Any partner or internal repo that lists these as normal semver deps (e.g. converting `"@bright-sdk/i18n":"https://…"` to `"@bright-sdk/i18n":"^1"`, or adding `bright-sdk-keycode-parser` by name) resolves the attacker package from the registry → RCE at install.
  3. **Private-registry public fallback.** If Bright's own CI installs these by name against a registry configured to fall back to public npm (classic dependency confusion), the attacker's higher/any version is pulled.
  4. **Future publish hijack / trust.** The names/scope being open lets an attacker permanently occupy Bright's identifiers, block official publication, and typosquat with a trusted-looking package.

## Impact
Arbitrary code execution (via npm lifecycle scripts) in the build/CI environments of Bright Data and its SDK partners, and long-term hijack of Bright's npm identity/namespace. Partner-build compromise is a supply-chain path into shipped apps that embed the SDK.

## Proof (evidence-based; no malicious publish performed)
- `curl https://registry.npmjs.org/<name>` → `404` for every name above; `https://registry.npmjs.org/-/v1/search?text=scope:bright-sdk` returns none owned by Bright.
- `node-bright-sdk` / `capacitor-brightsdk` maintainer = `efoxbr` (third party), confirming the natural names are already occupied by non-Bright parties.
- Code references above are from Bright's own repos.
- **No package was registered or published** — doing so would squat/endanger the ecosystem. Verification is read-only registry lookups.

## Suggested fix
1. Defensively register all names above **and** the `@bright-sdk` scope on public npm (publish empty placeholder packages with a security README, or publish the official packages).
2. Recover/attain control of the natural names currently held by third parties (`node-bright-sdk`, `capacitor-brightsdk`) or clearly document that they are unofficial.
3. In docs and tooling, pin dependencies to immutable sources (git commit SHAs or integrity-checked tarballs) and never by bare registry name for internal packages; add `.npmrc`/scope config that forces internal names to the intended source.

## Notes
- Novelty: distinct from the SSRF (Finding #1) and loopback-IPC (Finding #2); unrelated to the fixed iOS VPN bypass.
- Rules compliance: read-only registry lookups only; no DoS; no package published; no customer data touched.
