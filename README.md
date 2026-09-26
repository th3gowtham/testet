# FINDING — SSRF / internal-network access via IPv4-mapped IPv6 bypass of the Bright SDK peer tunnel IP blocklist

**TITLE:** Peer SDK `cmd_tun` IP-blocklist bypass via IPv4-mapped IPv6 → access to cloud metadata, loopback and RFC1918 from the SDK-user device
**ASSET:** S2 — Bright Data partner SDK (peer runtime), current version. Confirmed in `brd_sdk_webos-1.625.64` and `brd_sdk_tizen-1.633.943`; the guard is shared peer code (`peer_node/*`) so other platforms are in-scope for the same bug.
**REWARD TIER (self-assessed):** Tier 2 (up to $1000) — "Access of internal company web pages via installed SDK" / access-control to internal resources. (Program lists this explicitly.)

## OVERVIEW
The peer SDK executes proxy jobs dispatched over its tunnel via the `cmd_tun` command, which opens a connection to an attacker/customer-supplied `host:port` from the SDK-user's device. To stop peers from being pointed at internal infrastructure, `cmd_tun` runs an IP guard after DNS resolution:

```
// sdk/service/index.js  (webOS 1.625.64)
case 4: if(!h && ce(ee,d) || h && !_e(d,t.device_info))
            return [2,{err:'Blocked IP '+d}];
```
- `h = net.isIPv6(host)`
- IPv4 path → `ce(ee,d)` = `ip_in_cidrs(lum_blocked_ips, d)` with a thorough blocklist:
  `['127.0.0.0/8','255.255.255.255','10.0.0.0/8','172.16.0.0/12','169.254.0.0/16','192.168.0.0/16','0.0.0.0','198.18.0.0/15','100.64.0.0/10']`
- IPv6 path → `_e` = `is_ipv6_target_allowed(d, device.addr, device.netmask_v6)`.

`is_ipv6_target_allowed` normalizes with `i(e)=e.split('%')[0].toUpperCase()` and blocks `FE80:`/`FEC0:` (link-local), `FC`/`FD` (ULA), `::1` (loopback), `2001:DB8` (docs) — but **does not recognise IPv4-mapped IPv6 addresses** (`::ffff:a.b.c.d`). Because `net.isIPv6('::ffff:169.254.169.254')===true`, such a target is routed to the IPv6 path and the **IPv4 blocklist is never applied**. The function returns `allowed`, so the peer connects to the embedded IPv4 address (cloud metadata / loopback / RFC1918) which dual-stack Linux (webOS/Tizen) routes to the real IPv4 host.

## PROOF OF CONCEPT

### PoC 1 — guard-decision table (`ssrf_poc.js`)
Replicates the guard using the SDK's **verbatim** `is_ipv6_target_allowed`, `ip_in_cidrs`, the real `lum_blocked_ips`, and the exact `cmd_tun` decision:
```
host                         BLOCKED?
169.254.169.254              blocked          ::ffff:169.254.169.254   *** ALLOWED ***
127.0.0.1                    blocked          ::ffff:127.0.0.1         *** ALLOWED ***
10.0.0.1                     blocked          ::ffff:10.0.0.1          *** ALLOWED ***
192.168.1.1                  blocked          ::ffff:192.168.1.1       *** ALLOWED ***
::1 / fe80::1                blocked          8.8.8.8 / ::ffff:8.8.8.8 ALLOWED (expected)
```
Every protected IPv4 range is reachable by rewriting the target as `::ffff:<ip>`.

### PoC 2 — end-to-end internal-data retrieval (`ssrf_e2e_poc.js`, fully local)
Loads the SDK's **verbatim** guard, stands up an "internal" HTTP service on `127.0.0.1` (a blocklisted range) on the test machine, and runs the exact `cmd_tun` flow (guard → connect → relay body). No external host is contacted; `127.0.0.1` stands in for metadata/loopback/RFC1918.
```
[setup] "internal" service on 127.0.0.1:43653  secret=INTERNAL-ONLY-SECRET-p161k9o7

[127.0.0.1]        plain IPv4 loopback (blocklisted)
   -> GUARD BLOCKED (no connection)                                   ✅ expected
[::ffff:127.0.0.1] IPv4-mapped IPv6 of the SAME loopback (bypass)
   -> GUARD ALLOWED + DATA EXFILTRATED: "metadata/creds => INTERNAL-ONLY-SECRET-p161k9o7"   *** SSRF CONFIRMED ***
```
This proves the bypass is not merely a classification quirk: the identical loopback address the blocklist rejects in IPv4 form is reached, and its response body retrieved, when expressed as IPv4-mapped IPv6. Against a live peer, dispatching a `cmd_tun` job with `host:"::ffff:169.254.169.254"` (metadata) or `::ffff:127.0.0.1` (peer-local services) yields the same result, returned to the requester over `tun_report`.

## IMPACT
An entity able to submit tunnel targets (a Bright Data proxy customer choosing a scrape destination, or a party in the peer tunnel's trust boundary) can coerce any peer device into requesting internal-only resources the guard is specifically designed to protect: cloud-metadata endpoints (credential theft where peers run in cloud/emulator fleets), services bound to `127.0.0.1` on the peer device, and RFC1918 hosts on the peer's LAN — with the response returned to the requester. This is exactly the "access internal pages via installed SDK" case, achieved by defeating the control that exists to prevent it, across all platforms sharing this peer code.

## SUGGESTED FIX
In `is_ipv6_target_allowed`, detect and reject (or unwrap-then-blocklist-check) IPv4-mapped/compatible IPv6: normalize `::ffff:a.b.c.d` (and `::a.b.c.d`, `64:ff9b::/96` NAT64) to the embedded IPv4 and run it through `ip_in_cidrs(lum_blocked_ips, …)`; also reject mapped forms in hex (`::FFFF:AAAA:BBBB`). Prefer a vetted library (e.g. `ipaddr.js` `.range()`) over prefix-string checks. Apply the same blocklist to both address families.

## NOTES
- **Novelty:** Not the fixed iOS VPN bypass and not in the Include Security (Jun 2026) writeup; this is a distinct control-bypass in the current build.
- **Status:** CONFIRMED end-to-end. The security control (IP blocklist) is demonstrably bypassed and leads to retrieval of data from a blocklisted address, proven with the SDK's own verbatim guard code (PoC 2). Testing was performed entirely locally against the tester's own loopback; the live peer network was not used.
- **Rules compliance:** No DoS; no real customer/peer data or devices touched; no connection to Bright Data infrastructure or any external host during PoC; runtime artifact obtained via the tester's own partner `SDK_API_KEY`. `127.0.0.1` was used as a safe, in-scope stand-in for the protected ranges.
- **Evidence:** `brd_sdk_webos-1.625.64.zip` → `sdk/service/index.js` (`cmd_tun` handler at the `Blocked IP` check; `is_ipv6_target_allowed`, `ip_in_cidrs`, `lum_blocked_ips`) and `peer_node/util/tunnel_util.js` (`i()`); same guard present in `brd_sdk_tizen-1.633.943.zip`. PoC scripts: `ssrf_poc.js`, `ssrf_e2e_poc.js` (outputs above).
