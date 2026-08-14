---
name: csp-bypass-advanced
description: >-
  Advanced Content Security Policy bypass techniques. Use when XSS or data
  exfiltration is blocked by CSP and you need to find policy weaknesses, trusted
  endpoint abuse, nonce leakage, or exfiltration channels that CSP cannot block.
---

# SKILL: CSP Bypass — Advanced Techniques

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Covers per-directive bypass techniques, nonce/hash abuse, trusted CDN exploitation, data exfiltration despite CSP, and framework-specific bypasses. baseline analyses often suggest `unsafe-inline` bypass without checking if the CSP actually uses it, or miss the critical `base-uri` and `object-src` gaps.

## 0. RELATED ROUTING

- `xss-cross-site-scripting` for XSS vectors to deliver after CSP bypass
- `dangling-markup-injection` when CSP blocks scripts but HTML injection exists — exfiltrate without JS
- `crlf-injection` when CRLF can inject CSP header or steal nonce via response splitting
- `waf-bypass-techniques` when both WAF and CSP must be bypassed
- `clickjacking` when CSP lacks `frame-ancestors` — clickjacking still possible

---

## 1. CSP DIRECTIVE REFERENCE MATRIX

| Directive | Controls | Default Fallback |
|---|---|---|
| `default-src` | Fallback for all `-src` directives not explicitly set | None (browser default: allow all) |
| `script-src` | JavaScript execution | `default-src` |
| `style-src` | CSS loading | `default-src` |
| `img-src` | Image loading | `default-src` |
| `connect-src` | XHR, fetch, WebSocket, EventSource | `default-src` |
| `frame-src` | iframe/frame sources | `default-src` |
| `font-src` | Font loading | `default-src` |
| `object-src` | `<object>`, `<embed>`, `<applet>` | `default-src` |
| `media-src` | `<audio>`, `<video>` | `default-src` |
| `base-uri` | `<base>` element | **No fallback** — unrestricted if absent |
| `form-action` | Form submission targets | **No fallback** — unrestricted if absent |
| `frame-ancestors` | Who can embed this page (replaces X-Frame-Options) | **No fallback** — unrestricted if absent |
| `report-uri` / `report-to` | Where violation reports are sent | N/A |
| `navigate-to` | Navigation targets (limited browser support) | **No fallback** |

**Critical insight**: `base-uri`, `form-action`, and `frame-ancestors` do NOT fall back to `default-src`. Their absence is always a potential bypass vector.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 2. BYPASS TECHNIQUES BY DIRECTIVE
- 3. CSP IN META TAG vs. HEADER
- 4. DATA EXFILTRATION DESPITE CSP
- 5. CSP BYPASS DECISION TREE
- 6. TRICK NOTES — WHAT AI MODELS MISS
