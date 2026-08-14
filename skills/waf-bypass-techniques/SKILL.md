---
name: waf-bypass-techniques
description: >-
  WAF bypass methodology and generic evasion techniques. Use when a web application
  firewall blocks injection payloads (SQLi, XSS, RCE) and you need to craft
  bypasses using encoding, protocol-level tricks, or WAF-specific weaknesses.
---

# SKILL: WAF Bypass Techniques — Evasion Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Covers WAF identification, generic bypass categories (encoding, protocol abuse, HTTP/2, parameter pollution), and a decision tree. For product-specific bypasses (Cloudflare, AWS WAF, ModSecurity, Akamai, etc.), inspect [WAF_PRODUCT_MATRIX.md](./WAF_PRODUCT_MATRIX.md). baseline analyses often suggest basic encoding but miss protocol-level bypasses and WAF behavioral quirks.

## 0. RELATED ROUTING

- `sqli-sql-injection` for payloads to deliver after bypassing WAF
- `xss-cross-site-scripting` for XSS payloads that need WAF evasion
- `request-smuggling` when smuggling can route requests around WAF entirely
- `http-parameter-pollution` HPP is itself a WAF bypass primitive
- `csp-bypass-advanced` when WAF blocks inline scripts but CSP bypass is available

### Product-Specific Reference

Inspect [WAF_PRODUCT_MATRIX.md](./WAF_PRODUCT_MATRIX.md) when you need per-product bypass techniques for Cloudflare, AWS WAF, ModSecurity CRS, Akamai, Imperva, F5 BIG-IP, or Sucuri.

---

## 1. PHASE 0 — IDENTIFY THE WAF

Before bypassing, know what you're fighting.

### 1.1 Tools

| Tool | Usage |
|---|---|
| `wafw00f target.com` | Fingerprint WAF vendor from response headers/behavior |
| `nmap --script=http-waf-detect` | NSE script for WAF detection |
| Manual header inspection | `Server`, `X-CDN`, `X-Cache`, `cf-ray` (Cloudflare), `x-sucuri-id`, `x-akamai-*` |

### 1.2 Behavioral Fingerprinting

```
1. Send benign request → record baseline response (status, headers, body size)
2. Send obvious attack: /?q=<script>alert(1)</script>
3. Compare: 403? Custom block page? Redirect? Connection reset?
4. Block page content reveals WAF: "Cloudflare", "Access Denied (Imperva)", "ModSecurity"
5. If transparent proxy: check response time difference (WAF adds latency)
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 2. GENERIC BYPASS CATEGORIES
- 3. PROTOCOL-LEVEL BYPASS TECHNIQUES
- 4. WAF BYPASS DECISION TREE
- 5. COMMON MISTAKES & TRICK NOTES
- 6. DEFENSE PERSPECTIVE
