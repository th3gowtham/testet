# Dangling CloudFront CNAME — `public-dev.configura.com`

**Program:** Configura Security Bug Bounty Program (Xposera)
**Scope:** `*.configura.com` (in scope)
**Affected asset:** `public-dev.configura.com`
**Severity:** Medium (DNS hygiene / subdomain-takeover risk)
**Weakness:** CWE-1327 — Binding to an Unrestricted/Dangling Resource (dangling DNS record)
**Date:** 2026-10-07

---

## Summary

`public-dev.configura.com` is a **dangling CNAME**: it points to an Amazon CloudFront distribution
(`d2zp2dgwurq7f4.cloudfront.net`) that no longer exists. The DNS record was left in place after the
underlying CloudFront distribution was deleted.

## Steps to reproduce / Evidence (verified)

```
# 1) The subdomain still has a live CNAME:
$ dig +noall +answer public-dev.configura.com
public-dev.configura.com. 3600 IN CNAME d2zp2dgwurq7f4.cloudfront.net.

# 2) The CloudFront target no longer resolves (distribution deleted) — on 1.1.1.1, 8.8.8.8, 9.9.9.9:
$ dig @1.1.1.1 d2zp2dgwurq7f4.cloudfront.net
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, ... ANSWER: 0      # no A record

# 3) Control — a live Configura CloudFront DOES resolve, confirming the method:
$ dig +short d39qp5n00czdvs.cloudfront.net
18.161.229.23

# 4) The subdomain currently serves nothing:
$ curl -m8 -o /dev/null -w '%{http_code}\n' https://public-dev.configura.com/
000
```

Of 13 CloudFront/SaaS CNAME targets reviewed across the estate, `public-dev.configura.com` is the
**only** one whose target fails to resolve.

## Exploitability — honest assessment

This matches the classic CloudFront subdomain-takeover *pattern* (dangling CNAME to a deleted
distribution). However, a **working HTTPS takeover is not confirmed and is likely blocked**:

- To claim the hostname, an attacker must add `public-dev.configura.com` as an **Alternate Domain
  Name** on a CloudFront distribution they control, **and attach a TLS certificate covering that
  hostname**.
- Obtaining a publicly-trusted certificate for `public-dev.configura.com` requires domain-control
  validation (DNS or HTTP) that the attacker cannot pass without already controlling
  `configura.com` DNS or the not-yet-claimed host.
- Without a valid certificate, HTTPS requests to the hostname fail.

I did **not** attempt to register a distribution or otherwise claim the subdomain against live
infrastructure. This report documents the **dangling record** (verified) and the takeover risk —
not a demonstrated takeover.

## Impact

- **Now:** DNS hygiene / standing takeover-risk. A dangling record is a latent liability.
- **If it ever becomes claimable** (e.g. future AWS behaviour change, or the attacker otherwise
  obtains a certificate): it would allow serving attacker content from a genuine `*.configura.com`
  origin — phishing/malware on a trusted Configura domain, cookie setting/fixation on
  `.configura.com`, and the exact `*.configura.com` origin needed to exploit the separate
  credentialed-CORS issue on the MyConfigura API.

## Remediation

- Remove the `public-dev.configura.com` CNAME, or re-point it to a CloudFront distribution you
  currently own.
- Audit all DNS records for CNAMEs targeting deleted CloudFront/S3/other cloud resources.
- Adopt a process that de-provisions DNS records at the same time as the cloud resource they point
  to is deleted.

## Notes
Read-only DNS verification; no takeover performed. In-scope `*.configura.com` testing.
